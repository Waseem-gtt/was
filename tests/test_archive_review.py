"""Adversarial offline ZIP/TAR metadata review acceptance."""
import base64
import io
import json
import struct
import tarfile
import unittest
from unittest.mock import patch
from cyber_platform import archive_review as ar


def zipped(name='a.txt', body=b'abc', mode=0o100644, flags=0, method=0, expanded=None, extra=b''):
    n = name.encode('utf-8'); flags |= 0x800
    size = len(body) if expanded is None else expanded
    local = struct.pack('<4s5H3I2H', b'PK\x03\x04',20,flags,method,0,0,0,len(body),size,len(n),len(extra)) + n + extra + body
    directory = struct.pack('<4s6H3I5H2I',b'PK\x01\x02',788,20,flags,method,0,0,0,len(body),size,len(n),len(extra),0,0,0,mode<<16,0) + n + extra
    end = struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,1,1,len(directory),len(local),0)
    return local + directory + end


def zip_many(names):
    locals_, directories, offset = [], [], 0
    for name in names:
        raw = zipped(name)
        directory_pos = raw.index(b'PK\x01\x02')
        local, directory = raw[:directory_pos], bytearray(raw[directory_pos:-22])
        struct.pack_into('<I', directory,42,offset)
        locals_.append(local);directories.append(bytes(directory));offset += len(local)
    central=b''.join(directories)
    return b''.join(locals_) + central + struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,len(names),len(names),len(central),offset,0)


def tarred(name='a.txt', body=b'abc', kind=tarfile.REGTYPE, link='', mode=0o644):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        item=tarfile.TarInfo(name);item.type=kind;item.mode=mode;item.linkname=link
        item.size=len(body) if kind==tarfile.REGTYPE else 0
        archive.addfile(item,io.BytesIO(body) if item.size else None)
    return out.getvalue()


class ArchiveReviewTests(unittest.TestCase):
    def codes(self,data):return {f['code'] for f in ar.analyze(data)['findings']}

    def test_fixed_sample_metadata_33_bytes(self):
        result=ar.analyze(json.dumps(ar.sample()).encode())
        self.assertEqual((result['format'],result['member_count']),('ZIP',1))
        self.assertEqual(result['summary']['declared_expanded_bytes'],33)
        self.assertFalse(result['extracted']);self.assertFalse(result['crc_verified']);self.assertFalse(result['content_exported'])

    def test_raw_zip_and_envelope_bind_distinct_source_hashes(self):
        envelope=json.dumps(ar.sample()).encode();raw=base64.b64decode(ar.sample()['archive_base64'])
        a,b=ar.analyze(envelope),ar.analyze(raw)
        self.assertEqual(a['archive_sha256'],b['archive_sha256']);self.assertNotEqual(a['source_sha256'],b['source_sha256'])

    def test_zip_trailer_refused(self):
        with self.assertRaises(ValueError):ar.analyze(zipped()+b'overlay')

    def test_zip_prefix_refused(self):
        raw=zipped();central=raw.index(b'PK\x01\x02')
        altered=bytearray(b'PKxx'+raw)
        struct.pack_into('<I',altered,central+4+42,4);struct.pack_into('<I',altered,len(altered)-6,central+4)
        with self.assertRaises(ValueError):ar.analyze(bytes(altered))

    def test_zip_truncated_last_member_is_not_partial_success(self):
        for count in (1,7,25):
            with self.subTest(count=count),self.assertRaises(ValueError):ar.analyze(zipped()[:-count])

    def test_zip_local_directory_name_mismatch_refused(self):
        raw=bytearray(zipped());raw[30]=ord('x')
        with self.assertRaises(ValueError):ar.analyze(bytes(raw))

    def test_zip_local_size_mismatch_refused(self):
        raw=bytearray(zipped());struct.pack_into('<I',raw,22,99)
        with self.assertRaises(ValueError):ar.analyze(bytes(raw))

    def test_zip_declared_compression_bomb_never_decompressed(self):
        raw=zipped(body=b'x',method=8,expanded=100_000_000)
        with patch('zlib.decompress',side_effect=AssertionError('must not decompress')):
            self.assertIn('declared_expansion',self.codes(raw))

    def test_zip_encryption_reported_without_password(self):
        self.assertIn('encrypted_member',self.codes(zipped(flags=1)))

    def test_zip_crc_metadata_is_never_reported_verified(self):
        self.assertFalse(ar.analyze(zipped())['crc_verified'])

    def test_zip64_and_multidisk_refused(self):
        for offset,value in ((4,1),(8,65535)):
            raw=bytearray(zipped());struct.pack_into('<H',raw,len(raw)-22+offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):ar.analyze(bytes(raw))

    def test_zip_directory_record_count_limit_preflight(self):
        raw=bytearray(zipped());struct.pack_into('<HH',raw,len(raw)-14,2001,2001)
        with self.assertRaises(ValueError):ar.analyze(bytes(raw))

    def test_zip_name_override_extras_refused(self):
        for kind in (0x1,0x7075,0x000d,0x756e):
            with self.subTest(kind=kind),self.assertRaises(ValueError):ar.analyze(zipped(extra=struct.pack('<HH',kind,0)))

    def test_zip_malformed_extra_length_refused(self):
        with self.assertRaises(ValueError):ar.analyze(zipped(extra=b'\x02\x00\xff\xff'))

    def test_zip_path_traversal_absolute_drive_and_backslash_flagged(self):
        for name in ('../x','/etc/x','C:/x','a\\b','\\\\host\\file'):
            with self.subTest(name=name):self.assertIn('unsafe_path',self.codes(zipped(name)))

    def test_zip_alias_names_detected(self):
        self.assertIn('duplicate_path',self.codes(zip_many(['a/b','a/./b','a//b'])))

    def test_zip_file_ancestor_conflict_both_orders(self):
        for names in (['a','a/b'],['a/b','a']):
            with self.subTest(names=names):self.assertIn('path_type_conflict',self.codes(zip_many(names)))

    def test_zip_deep_names_do_not_require_unbounded_prefix_set(self):
        names=[('x/'*300)+str(i) for i in range(100)]
        self.assertEqual(ar.analyze(zip_many(names))['member_count'],100)

    def test_unicode_control_or_bidi_names_refused(self):
        for name in ('x\x01','x\u202efoo','x\u200bfoo'):
            with self.subTest(name=name),self.assertRaises(ValueError):ar.analyze(zipped(name))

    def test_zip_symlink_is_metadata_only(self):
        r=ar.analyze(zipped(mode=0o120777,body=b'../../secret'))
        self.assertEqual(r['members'][0]['type'],'symlink');self.assertIsNone(r['members'][0]['link_target'])
        self.assertIn('link_member',{f['code'] for f in r['findings']})

    def test_permission_modes_flagged(self):
        codes=self.codes(zipped(mode=0o106666));self.assertIn('privileged_mode',codes);self.assertIn('world_writable',codes)

    def test_zip_special_files_flagged(self):
        self.assertIn('special_member',self.codes(zipped(mode=0o010644)))

    def test_tar_basic_header_checksum_and_metadata(self):
        r=ar.analyze(tarred());self.assertEqual(r['format'],'TAR');self.assertEqual(r['members'][0]['size'],3)

    def test_tar_bad_checksum_rejected(self):
        raw=bytearray(tarred());raw[10]=65
        with self.assertRaises(ValueError):ar.analyze(bytes(raw))

    def test_tar_links_and_unsafe_targets_flagged(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                codes=self.codes(tarred(kind=kind,link='../../outside'));self.assertIn('link_member',codes);self.assertIn('unsafe_link_target',codes)

    def test_tar_special_device_flagged(self):
        self.assertIn('special_member',self.codes(tarred(kind=tarfile.CHRTYPE)))

    def test_tar_final_zero_blocks_required(self):
        raw=tarred()[:1024]
        with self.assertRaises(ValueError):ar.analyze(raw)

    def test_tar_trailing_payload_refused(self):
        with self.assertRaises(ValueError):ar.analyze(tarred()+b'x'*512)

    def test_tar_unaligned_or_truncated_refused(self):
        with self.assertRaises(ValueError):ar.analyze(tarred()[:-1])

    def test_pax_gnu_compressed_tar_refused(self):
        for data in (b'\x1f\x8bxxx',b'BZhxxx',b'\xfd7zXZxxx',tarred(kind=tarfile.XHDTYPE)):
            with self.subTest(data=data[:5]),self.assertRaises(ValueError):ar.analyze(data)

    def test_json_duplicate_or_extra_fields_invalid_base64_refused(self):
        for data in (b'{"archive_base64":"!"}',b'{"archive_base64":"","archive_base64":""}',b'{"archive_base64":"","x":1}'):
            with self.subTest(data=data),self.assertRaises(ValueError):ar.analyze(data)

    def test_input_or_name_bounds_refused(self):
        with self.assertRaises(ValueError):ar.analyze(b'x'*(4*1024*1024+1))
        with self.assertRaises(ValueError):ar.analyze(zipped('a'*1001))

    def test_analyze_never_reads_files_opens_sockets_or_extracts(self):
        raw=zipped()
        with patch('builtins.open',side_effect=AssertionError('file read')),patch('socket.socket',side_effect=AssertionError('network')):
            self.assertEqual(ar.analyze(raw)['member_count'],1)

    def test_zero_member_classic_zip(self):
        raw=struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,0,0,0,0,0)
        self.assertEqual(ar.analyze(raw)['member_count'],0)

    def test_real_resource_bounded_worker(self):
        from cyber_platform import worker
        result=worker.analyze('archive',json.dumps(ar.sample()).encode())
        self.assertEqual(result['member_count'],1)
        with self.assertRaises(ValueError):worker.analyze('archive',b'invalid')
