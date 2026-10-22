"""Offline DNS decoding bounds name compression and keeps TXT content private."""
import base64
import ipaddress
import struct
import unittest
from unittest.mock import patch
from cyber_platform import dns_message as dns
from cyber_platform.store import encode


class DNSMessageTests(unittest.TestCase):
    def raw(self):return base64.b64decode(dns.sample()['dns_base64'])
    def label(self,name):return b''.join(bytes((len(v),))+v.encode() for v in name.split('.'))+b'\0'
    def packet(self,kind=1,data=bytes((192,0,2,1)),name=None,ttl=300):
        question=self.label('example.test')+struct.pack('!HH',kind,1)
        rr=(b'\xc0\x0c' if name is None else name)+struct.pack('!HHIH',kind,1,ttl,len(data))+data
        return struct.pack('!6H',10,0x8180,1,1,0,0)+question+rr

    def test_sample_compressed_a_response(self):
        report=dns.analyze(self.raw())
        self.assertEqual(report['question_count'],1);self.assertEqual(report['record_count'],1)
        self.assertEqual(report['questions'][0]['name'],'example.test')
        self.assertEqual(report['records'][0]['data'],{'address':'192.0.2.1'})
        self.assertEqual(report['records'][0]['ttl'],300)
        self.assertFalse(report['network']);self.assertFalse(report['dnssec_verified'])

    def test_raw_and_envelope_match_message_hash_not_source_hash(self):
        raw=dns.analyze(self.raw());wrapped=dns.analyze(encode(dns.sample()).encode())
        self.assertEqual(raw['message_sha256'],wrapped['message_sha256'])
        self.assertNotEqual(raw['source_sha256'],wrapped['source_sha256'])
        self.assertEqual(wrapped['input_encoding'],'base64-json')

    def test_exact_envelope_and_base64_validation(self):
        for raw in (b'{}',b'{"dns_base64":1}',b'{"dns_base64":"%%%"}',b'{"dns_base64":"AA==","extra":1}',b'{"dns_base64":"AA==","dns_base64":"AA=="}'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):dns.analyze(raw)

    def test_query_without_answers_and_root_name(self):
        raw=struct.pack('!6H',11,0x0100,1,0,0,0)+b'\0'+struct.pack('!HH',2,1)
        result=dns.analyze(raw);self.assertEqual(result['questions'][0]['name'],'.');self.assertEqual(result['record_count'],0)

    def test_empty_header_message_is_not_a_security_verdict(self):
        result=dns.analyze(struct.pack('!6H',1,0,0,0,0,0));self.assertEqual(result['question_count'],0)
        self.assertNotIn('passed',result)

    def test_aaaa_address(self):
        address=ipaddress.IPv6Address('2001:db8::1')
        self.assertEqual(dns.analyze(self.packet(28,address.packed))['records'][0]['data']['address'],str(address))

    def test_cname_ns_ptr_names_decode_with_exact_record_bounds(self):
        for kind in (2,5,12):
            with self.subTest(kind=kind):
                result=dns.analyze(self.packet(kind,b'\xc0\x0c'))
                self.assertEqual(result['records'][0]['data'],{'name':'example.test'})

    def test_mx_and_srv_records(self):
        mx=dns.analyze(self.packet(15,struct.pack('!H',10)+b'\xc0\x0c'))['records'][0]['data']
        self.assertEqual(mx,{'preference':10,'exchange':'example.test'})
        srv=dns.analyze(self.packet(33,struct.pack('!HHH',1,2,443)+b'\xc0\x0c'))['records'][0]['data']
        self.assertEqual(srv,{'priority':1,'weight':2,'port':443,'target':'example.test'})

    def test_soa_records(self):
        result=dns.analyze(self.packet(6,b'\xc0\x0c'+self.label('hostmaster.example.test')+struct.pack('!5I',1,2,3,4,5)))
        record=result['records'][0]['data'];self.assertEqual(record['primary'],'example.test')
        self.assertEqual(record['responsible'],'hostmaster.example.test');self.assertEqual(record['minimum'],5)

    def test_txt_values_are_not_exported(self):
        secret=b'PRIVATE_TXT_CANARY';raw=self.packet(16,bytes((len(secret),))+secret+b'\x00')
        result=dns.analyze(raw);self.assertNotIn(secret.decode(),encode(result))
        self.assertEqual(result['records'][0]['data'],{'string_count':2,'lengths':[len(secret),0]})

    def test_unknown_and_opt_rdata_export_only_length(self):
        for kind in (41,65000):
            result=dns.analyze(self.packet(kind,b'PRIVATE_RDATA_CANARY'))
            self.assertEqual(result['records'][0]['data'],{'bytes':20})
            self.assertNotIn('PRIVATE_RDATA_CANARY',encode(result))

    def test_header_flags_are_claims_not_dnssec_verification(self):
        raw=bytearray(self.raw());raw[2:4]=struct.pack('!H',0x85b3)
        result=dns.analyze(bytes(raw));self.assertTrue(result['flags']['authoritative_claim'])
        self.assertTrue(result['flags']['authenticated_data_claim']);self.assertEqual(result['flags']['rcode'],3)
        self.assertFalse(result['dnssec_verified'])

    def test_reserved_header_bit_is_refused(self):
        raw=bytearray(self.raw());raw[2:4]=struct.pack('!H',0x81c0)
        with self.assertRaises(ValueError):dns.analyze(bytes(raw))

    def test_all_truncated_prefixes_refused(self):
        raw=self.raw()
        for size in range(len(raw)):
            with self.subTest(size=size),self.assertRaises(ValueError):dns.analyze(raw[:size])

    def test_trailing_data_and_declared_count_mismatch_refused(self):
        with self.assertRaises(ValueError):dns.analyze(self.raw()+b'\0')
        raw=bytearray(self.raw());raw[6:8]=struct.pack('!H',2)
        with self.assertRaises(ValueError):dns.analyze(bytes(raw))

    def test_invalid_a_aaaa_and_service_lengths_refused(self):
        for kind,data in ((1,b'abc'),(28,b'1234'),(15,b'\0\0'),(33,b'\0'*6),(6,b'\xc0\x0c'),(16,b''),(16,b'\x03a')):
            with self.subTest(kind=kind),self.assertRaises(ValueError):dns.analyze(self.packet(kind,data))

    def test_name_rdata_with_trailing_bytes_refused(self):
        for kind,prefix in ((2,b''),(15,b'\0\0'),(33,b'\0'*6)):
            with self.subTest(kind=kind),self.assertRaises(ValueError):dns.analyze(self.packet(kind,prefix+b'\xc0\x0c\0'))

    def test_self_forward_header_and_middle_label_pointers_refused(self):
        for pointer in (b'\xc0\x00',b'\xc0\x0d',b'\xc0\x1e',b'\xc0\xff'):
            with self.subTest(pointer=pointer),self.assertRaises(ValueError):dns.analyze(self.packet(name=pointer))

    def test_valid_pointer_to_prior_pointer_is_supported(self):
        raw=self.raw();pointer_offset=12+len(self.label('example.test'))+4
        first=raw[12+len(self.label('example.test'))+4:]
        second=struct.pack('!H',0xc000|pointer_offset)+struct.pack('!HHIH',1,1,20,4)+bytes((192,0,2,2))
        head=struct.pack('!6H',1234,0x8180,1,2,0,0)
        result=dns.analyze(head+raw[12:12+len(self.label('example.test'))+4]+first+second)
        self.assertEqual(result['record_count'],2);self.assertEqual(result['records'][1]['name'],'example.test')

    def test_reserved_label_encodings_and_nonprintable_labels_refused(self):
        for name in (b'\x40'+b'a'*64,b'\x80',b'\x01\xff\0',b'\x01\x01\0',b'\x03a.b\0',b'\x01\\\0'):
            raw=struct.pack('!6H',1,0,1,0,0,0)+name+struct.pack('!HH',1,1)
            with self.subTest(name=name),self.assertRaises(ValueError):dns.analyze(raw)

    def test_max_expanded_name_limit_is_enforced(self):
        name=b''.join(b'\x3f'+b'a'*63 for _ in range(4))+b'\0'
        with self.assertRaises(ValueError):dns.analyze(struct.pack('!6H',1,0,1,0,0,0)+name+struct.pack('!HH',1,1))

    def test_count_byte_and_name_step_limits_are_enforced(self):
        with self.assertRaises(ValueError):dns.analyze(struct.pack('!6H',1,0,1001,0,0,0))
        with patch.dict(dns.LIMITS,input_bytes=1),self.assertRaises(ValueError):dns.analyze(self.raw())
        with patch.dict(dns.LIMITS,message_bytes=12),self.assertRaises(ValueError):dns.analyze(self.raw())
        with patch.dict(dns.LIMITS,name_steps=1),self.assertRaises(ValueError):dns.analyze(self.raw())

    def test_uppercase_names_are_normalized_without_changing_message_hash(self):
        raw=self.raw().replace(b'example',b'EXAMPLE');result=dns.analyze(raw)
        self.assertEqual(result['questions'][0]['name'],'example.test')
        self.assertNotEqual(result['message_sha256'],dns.analyze(self.raw())['message_sha256'])

    def test_authority_and_additional_sections_are_preserved(self):
        base=self.raw();tail=base[-16:];head=struct.pack('!6H',1,0x8180,1,0,1,1)
        result=dns.analyze(head+base[12:-16]+tail+tail)
        self.assertEqual([r['section'] for r in result['records']],['authority','additional'])

    def test_later_malformed_record_never_returns_partial_success(self):
        raw=self.raw();head=struct.pack('!6H',1,0x8180,1,2,0,0)
        with self.assertRaises(ValueError):dns.analyze(head+raw[12:]+b'\xc0\x0c\0')

    def test_offline_parser_never_reads_files_or_uses_sockets(self):
        with patch('builtins.open',side_effect=AssertionError('file')),patch('socket.create_connection',side_effect=AssertionError('network')):
            self.assertEqual(dns.analyze(self.raw())['record_count'],1)

    def test_actual_spawned_worker_decodes_and_refuses_malformed_input(self):
        from cyber_platform import worker
        result=worker.analyze('dns',encode(dns.sample()).encode())
        self.assertEqual(result['record_count'],1)
        with self.assertRaises(ValueError):worker.analyze('dns',b'bad')
