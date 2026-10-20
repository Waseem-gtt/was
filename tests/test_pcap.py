"""Classic PCAP is untrusted data; bounded metadata parsing never exports payload."""
import base64
import hashlib
import ipaddress
import json
import struct
import unittest
from unittest.mock import patch

from cyber_platform import pcap, worker


class PcapTests(unittest.TestCase):
    def capture(self, packets=None, endian='<', nanos=False, link=1, times=None, snaplen=65535):
        packets = [pcap.sample()[40:]] if packets is None else packets
        magic = 0xa1b23c4d if nanos else 0xa1b2c3d4
        out = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, snaplen, link)
        for index, packet in enumerate(packets):
            seconds, fraction = times[index] if times else (1700000000 + index, 10)
            out += struct.pack(endian + 'IIII', seconds, fraction, len(packet), len(packet)) + packet
        return out

    def ip4(self, payload=None, protocol=17, flags=0, destination='198.51.100.2'):
        payload = struct.pack('!HHHH', 53000, 53, 8, 0) if payload is None else payload
        return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, flags, 64, protocol, 0,
                           ipaddress.IPv4Address('192.0.2.1').packed,
                           ipaddress.IPv4Address(destination).packed) + payload

    def ip6(self, payload=None, protocol=17):
        payload = struct.pack('!HHHH', 53000, 53, 8, 0) if payload is None else payload
        return struct.pack('!IHBB16s16s', 6 << 28, len(payload), protocol, 64,
                           ipaddress.IPv6Address('2001:db8::1').packed,
                           ipaddress.IPv6Address('2001:db8::2').packed) + payload

    def ether(self, payload=None, kind=0x0800):
        return bytes.fromhex('020000000002020000000001') + struct.pack('!H', kind) + (self.ip4() if payload is None else payload)

    def test_sample_has_fixed_addresses_ports_and_no_payload_export(self):
        raw = pcap.sample()
        result = pcap.analyze(raw)
        self.assertEqual(result['schema'], 'was.pcap-analysis/1')
        self.assertEqual(result['packet_count'], 1)
        self.assertEqual(result['captured_bytes'], 42)
        self.assertEqual(result['protocols'], {'UDP': 1})
        flow = result['flows'][0]
        self.assertEqual((flow['source'], flow['destination'], flow['source_port'], flow['destination_port']),
                         ('192.0.2.1', '198.51.100.2', 53000, 53))
        self.assertFalse(result['payload_exported'])
        self.assertFalse(result['live_capture'])
        self.assertFalse(result['checksums_verified'])
        self.assertEqual(result['capture_sha256'], hashlib.sha256(raw).hexdigest())

    def test_all_four_magic_byte_orders_and_resolutions(self):
        for endian in ('<', '>'):
            for nanos in (False, True):
                with self.subTest(endian=endian, nanos=nanos):
                    result = pcap.analyze(self.capture(endian=endian, nanos=nanos))
                    self.assertEqual(result['packet_count'], 1)
                    self.assertEqual(result['byte_order'], 'little' if endian == '<' else 'big')
                    self.assertEqual(result['timestamp_resolution'], 'nanoseconds' if nanos else 'microseconds')

    def test_strict_base64_envelope_has_separate_original_and_capture_hash(self):
        raw = pcap.sample()
        envelope = json.dumps({'pcap_base64': base64.b64encode(raw).decode()}).encode()
        result = pcap.analyze(envelope)
        self.assertEqual(result['input_encoding'], 'base64-json')
        self.assertEqual(result['input_sha256'], hashlib.sha256(envelope).hexdigest())
        self.assertEqual(result['capture_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['flows'], pcap.analyze(raw)['flows'])

    def test_envelope_rejects_extra_duplicate_malformed_or_nonstring_values(self):
        for value in (b'{"pcap_base64":"AA==","shell":"x"}', b'{"pcap_base64":"AA==","pcap_base64":"AA=="}',
                      b'{"pcap_base64":1}', b'{"pcap_base64":"!invalid"}', b'{"pcap_base64":"\xff"}', b'{'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pcap.analyze(value)

    def test_every_physical_truncation_refuses_without_partial_results(self):
        capture = self.capture([self.ether(), self.ether()])
        # A global header alone and complete first packet are valid captures;
        # all other proper prefixes cut a documented field or packet.
        valid_ends = {24, 24 + 16 + len(self.ether())}
        for cut in range(len(capture)):
            if cut not in valid_ends:
                with self.subTest(cut=cut), self.assertRaises(ValueError):
                    pcap.analyze(capture[:cut])

    def test_empty_capture_is_zero_without_invented_timestamp(self):
        result = pcap.analyze(self.capture([]))
        self.assertEqual(result['packet_count'], 0)
        self.assertEqual(result['flows'], [])
        self.assertEqual(result['time_range'], {'first': None, 'last': None})

    def test_pcapng_invalid_version_link_and_snaplen_rejected(self):
        bad = [b'\x0a\x0d\x0d\x0a' + b'\0' * 32]
        for offset, fmt, value in ((4, 'H', 3), (6, 'H', 3), (16, 'I', 0), (20, 'I', 113)):
            capture = bytearray(pcap.sample())
            struct.pack_into('<' + fmt, capture, offset, value)
            bad.append(bytes(capture))
        for capture in bad:
            with self.subTest(capture=capture[:24]), self.assertRaises(ValueError):
                pcap.analyze(capture)

    def test_snap_truncation_length_and_timestamp_errors_rejected(self):
        for offset, value in ((28, 1000000), (32, 0), (32, 65536), (36, 41), (36, 43)):
            capture = bytearray(pcap.sample())
            struct.pack_into('<I', capture, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                pcap.analyze(bytes(capture))
        with self.assertRaises(ValueError):
            pcap.analyze(self.capture(nanos=True, times=[(1, 1000000000)]))

    def test_aggregation_is_directional_and_time_range_handles_reordered_clock(self):
        packet = self.ether()
        result = pcap.analyze(self.capture([packet, packet], times=[(30, 2), (20, 1)]))
        self.assertEqual(len(result['flows']), 1)
        self.assertEqual(result['flows'][0]['packets'], 2)
        self.assertEqual(result['time_range'], {'first': [20, 1], 'last': [30, 2]})

    def test_packet_and_flow_caps_refuse_instead_of_silently_truncating(self):
        with patch.object(pcap, 'MAX_PACKETS', 1), self.assertRaises(ValueError):
            pcap.analyze(self.capture([self.ether(), self.ether()]))
        with patch.object(pcap, 'MAX_FLOWS', 1), self.assertRaises(ValueError):
            pcap.analyze(self.capture([self.ether(), self.ether(self.ip4(destination='198.51.100.3'))]))

    def test_input_limit_refuses_before_parser(self):
        with self.assertRaises(ValueError):
            pcap.analyze(b'x' * (pcap.MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            pcap.analyze('not bytes')

    def test_vlan_two_layers_parse_and_third_layer_or_short_tag_refused(self):
        mac = bytes.fromhex('020000000002020000000001')
        tagged = mac + struct.pack('!HHHHH', 0x88a8, 10, 0x8100, 20, 0x0800) + self.ip4()
        self.assertEqual(pcap.analyze(self.capture([tagged]))['protocols'], {'UDP': 1})
        for data in (mac + b'\x81\x00\0', mac + struct.pack('!HHHHHHH', 0x88a8, 10, 0x8100, 20, 0x8100, 30, 0x0800) + self.ip4()):
            with self.assertRaises(ValueError):
                pcap.analyze(self.capture([data]))

    def test_raw_ip_link_supports_ipv4_ipv6_and_rejects_trailing_junk(self):
        result = pcap.analyze(self.capture([self.ip4(), self.ip6()], link=101))
        self.assertEqual(result['protocols'], {'UDP': 2})
        self.assertEqual(result['link_name'], 'raw IP')
        for packet in (b'', b'\x10' * 20, self.ip4() + b'junk'):
            with self.assertRaises(ValueError):
                pcap.analyze(self.capture([packet], link=101))

    def test_ipv4_fragments_never_invent_ports(self):
        for flags in (0x2000, 1):
            result = pcap.analyze(self.capture([self.ether(self.ip4(payload=b'\xff' * 8, flags=flags))]))
            flow = result['flows'][0]
            self.assertEqual(flow['fragmented_packets'], 1)
            self.assertIsNone(flow['source_port'])
            self.assertIsNone(flow['destination_port'])
        for flags in (0x8000, 0x6000):
            with self.assertRaises(ValueError):
                pcap.analyze(self.capture([self.ether(self.ip4(flags=flags))]))

    def test_ipv4_header_options_lengths_and_truncated_ip_refused(self):
        for offset, value in ((0, 0x44), (0, 0x4f), (2, 1), (3, 0), (3, 100)):
            packet = bytearray(self.ip4())
            packet[offset] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                pcap.analyze(self.capture([self.ether(bytes(packet))]))
        with self.assertRaises(ValueError):
            pcap.analyze(self.capture([self.ether(self.ip4()[:19])]))

    def test_tcp_header_length_and_udp_length_are_checked(self):
        tcp = bytearray(20)
        struct.pack_into('!HH', tcp, 0, 443, 50000)
        tcp[12] = 0x50
        result = pcap.analyze(self.capture([self.ether(self.ip4(bytes(tcp), 6))]))
        self.assertEqual(result['flows'][0]['source_port'], 443)
        for payload, protocol in ((bytes(tcp[:19]), 6), (bytes(20), 6), (b'\0' * 7, 17), (b'\0' * 8, 17)):
            with self.subTest(protocol=protocol, size=len(payload)), self.assertRaises(ValueError):
                pcap.analyze(self.capture([self.ether(self.ip4(payload, protocol))]))

    def test_icmp_and_icmpv6_metadata_require_minimum_headers(self):
        packets = [self.ether(self.ip4(b'\x08\0\0\0', 1)), self.ether(self.ip6(b'\x80\0\0\0', 58), 0x86dd)]
        self.assertEqual(pcap.analyze(self.capture(packets))['protocols'], {'ICMP': 1, 'ICMPv6': 1})
        with self.assertRaises(ValueError):
            pcap.analyze(self.capture([self.ether(self.ip4(b'\x08\0\0', 1))]))

    def test_ipv6_extensions_and_fragment_metadata(self):
        udp = struct.pack('!HHHH', 53000, 53, 8, 0)
        hop = bytes([17, 0]) + b'\0' * 6
        result = pcap.analyze(self.capture([self.ether(self.ip6(hop + udp, 0), 0x86dd)]))
        self.assertEqual(result['flows'][0]['destination_port'], 53)
        for flags in (1, 8):
            frag = struct.pack('!BBHI', 17, 0, flags, 123) + b'\xff' * 8
            result = pcap.analyze(self.capture([self.ether(self.ip6(frag, 44), 0x86dd)]))
            self.assertEqual(result['flows'][0]['fragmented_packets'], 1)
            self.assertIsNone(result['flows'][0]['source_port'])

    def test_ipv6_atomic_fragment_can_parse_ports_but_duplicate_fragment_refused(self):
        udp = struct.pack('!HHHH', 53000, 53, 8, 0)
        fragment = struct.pack('!BBHI', 17, 0, 0, 123)
        result = pcap.analyze(self.capture([self.ether(self.ip6(fragment + udp, 44), 0x86dd)]))
        self.assertEqual(result['flows'][0]['destination_port'], 53)
        double = struct.pack('!BBHI', 44, 0, 0, 123) + fragment + udp
        with self.assertRaises(ValueError):
            pcap.analyze(self.capture([self.ether(self.ip6(double, 44), 0x86dd)]))

    def test_ipv6_extension_limit_reserved_fields_and_short_lengths(self):
        udp = struct.pack('!HHHH', 53000, 53, 8, 0)
        chains = [bytes([0, 0]) + b'\0' * 6 for _ in range(8)]
        excessive = b''.join(chains) + bytes([17, 0]) + b'\0' * 6 + udp
        invalid = [self.ip6(excessive, 0), self.ip6(b'\x11\x01\0\0', 0),
                   self.ip6(struct.pack('!BBHI', 17, 1, 0, 123) + udp, 44),
                   self.ip6(struct.pack('!BBHI', 17, 0, 2, 123) + udp, 44),
                   self.ip6(bytes([17, 0]) + b'\0' * 6 + udp, 51)]
        for packet in invalid:
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                pcap.analyze(self.capture([self.ether(packet, 0x86dd)]))

    def test_unknown_ethertype_and_protocol_remain_explicit_without_payload(self):
        marker = b'PRIVATE_SYNTHETIC_PAYLOAD_NOT_FOR_EXPORT'
        packets = [self.ether(marker, 0x0806), self.ether(self.ip4(marker, 250))]
        result = pcap.analyze(self.capture(packets))
        self.assertEqual(result['protocols'], {'ETHERTYPE_0806': 1, 'IP_250': 1})
        self.assertNotIn(marker.decode(), json.dumps(result))

    def test_empty_ipv6_no_next_header_allows_ethernet_padding(self):
        packet = self.ether(self.ip6(b'', 59) + b'\0' * 6, 0x86dd)
        result = pcap.analyze(self.capture([packet]))
        self.assertEqual(result['protocols'], {'NO_NEXT_HEADER': 1})

    def test_analysis_never_opens_socket_or_executes_input(self):
        with patch('socket.socket', side_effect=AssertionError('network prohibited')):
            self.assertEqual(pcap.analyze(pcap.sample())['packet_count'], 1)

    def test_registered_worker_analyzes_raw_capture_with_resource_boundary(self):
        result = worker.analyze('pcap', pcap.sample(), timeout=3)
        self.assertEqual(result['protocols'], {'UDP': 1})
        self.assertEqual(result['packet_count'], 1)
