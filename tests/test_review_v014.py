"""Independent adversarial checks for the eleven offline analysis functions."""
import base64
import copy
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import tarfile
import unittest
from unittest.mock import patch
import zipfile

from cyber_platform import (archive_review, case_reports, coverage_scans, curriculum,
                            detection, dns_message, email_review, engine, event_ingest,
                            har, kubernetes_review, plans, quality, sarif, ssh_keys,
                            systemd_review, tools)
from cyber_platform.store import encode


class IndependentBatchReviewTests(unittest.TestCase):
    def data(self, value):
        return encode(value).encode()

    def zip(self, names):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name in names:
                archive.writestr(name, b'fixed synthetic data')
        return stream.getvalue()

    def test_all_eight_implementation_files_bind_every_reuse_fingerprint(self):
        names = ('har.py', 'email_review.py', 'kubernetes_review.py', 'systemd_review.py',
                 'sarif.py', 'dns_message.py', 'archive_review.py', 'ssh_keys.py')
        self.assertTrue(set(names) <= set(tools.ANALYZER_FILES))
        functions = (engine.fingerprint, plans.fingerprint, quality._engine,
                     detection._engine, curriculum._engine, case_reports._fingerprint,
                     coverage_scans._engine, event_ingest.fingerprint)
        read = Path.read_bytes
        for name in names:
            for fingerprint in functions:
                before = fingerprint()
                def changed(path, name=name):
                    raw = read(path)
                    return raw + b'\n# independent provenance mutation\n' if path.name == name else raw
                with self.subTest(file=name, fingerprint=fingerprint.__module__), patch.object(Path, 'read_bytes', changed):
                    self.assertNotEqual(fingerprint(), before)

    def test_har_credentials_and_url_components_do_not_escape_to_report(self):
        value = har.sample()
        entry = value['log']['entries'][0]
        secret = 'PRIVATE_BATCH_SECRET_249'
        entry['request']['url'] = 'https://user:' + secret + '@example.test/private/' + secret + '?secret=' + secret + '#' + secret
        entry['request']['headers'].append({'name':'Authorization', 'value':'Bearer ' + secret})
        entry['request']['cookies'] = [{'name':secret, 'value':secret}]
        entry['request']['postData'] = {'mimeType':'text/plain', 'text':secret}
        entry['response'].setdefault('content', {})['text'] = secret
        entry['response']['cookies'] = [{'name':secret, 'value':secret, 'secure':True, 'httpOnly':True}]
        report = har.analyze(self.data(value))
        self.assertNotIn(secret, encode(report))
        self.assertEqual(report['entries'][0]['origin'], 'https://example.test')
        self.assertFalse(report['content_exported'])

    def test_har_diff_does_not_claim_hidden_body_or_credentials_equality(self):
        left, right = har.sample(), har.sample()
        right['log']['entries'][0]['response'].setdefault('content', {})['text'] = 'PRIVATE_BODY_ONLY_CHANGE'
        report = har.analyze_diff(self.data({'left':left, 'right':right}))
        self.assertTrue(report['normalized_metadata_equal'])
        self.assertTrue(report['complete'])
        self.assertNotIn('PRIVATE_BODY_ONLY_CHANGE', encode(report))
        self.assertEqual(report['embedded_document_encoding'], 'canonical_json')
        self.assertNotEqual(report['left_sha256'], report['right_sha256'])

    def test_har_status_zero_never_invents_a_missing_response_header(self):
        value = har.sample()
        entry = value['log']['entries'][0]
        entry['response'].update(status=0, headers=[])
        report = har.analyze(self.data(value))
        self.assertFalse(report['entries'][0]['response_recorded'])
        self.assertFalse(any(row['code'].startswith('missing_') for row in report['findings']))

    def test_email_body_and_filename_are_hashed_or_omitted_not_exported(self):
        secret = 'PRIVATE_MAIL_CONTENT_249'
        value = email_review.sample().replace('Synthetic private body.', secret).replace('example.txt', secret + '.txt')
        value = value.replace('sender@example.test', secret + '@example.test')
        report = email_review.analyze(value.encode())
        self.assertNotIn(secret, encode(report))
        self.assertEqual(report['attachment_count'], 1)
        self.assertEqual(report['attachments'][0]['extension'], 'txt')
        self.assertEqual(report['domains']['from'], ['example.test'])
        self.assertTrue(all(row['verification']=='source_claim_only' for row in report['auth_claims']))
        self.assertFalse(report['content_exported'])

    def test_ssh_execution_option_values_and_comments_never_run_or_export(self):
        public = ssh_keys.sample().strip().split(' ', 1)[1].split(' synthetic', 1)[0]
        secret = 'PRIVATE_SSH_COMMAND_249'
        raw = ('command="' + secret + ' --argument",environment="TOKEN=' + secret + '" ' + public + ' ' + secret).encode()
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('execution')), patch.object(socket, 'create_connection', side_effect=AssertionError('network')):
            report = ssh_keys.analyze(raw)
        self.assertNotIn(secret, encode(report))
        self.assertEqual(report['keys'][0]['option_names'], ['command', 'environment'])
        self.assertFalse(report['authenticated'])

    def test_kubernetes_known_uid_change_is_detected_without_finding_count_change(self):
        left = kubernetes_review.sample()
        context = left['items'][0]['spec']['template']['spec']['containers'][0]['securityContext']
        context['runAsUser'] = 1001
        right = copy.deepcopy(left)
        right['items'][0]['spec']['template']['spec']['containers'][0]['securityContext']['runAsUser'] = 1002
        a, b = [kubernetes_review.analyze(self.data(v)) for v in (left, right)]
        self.assertEqual(a['summary'], b['summary'])
        report = kubernetes_review.analyze_diff(self.data({'left':left, 'right':right}))
        self.assertFalse(report['normalized_review_equal'])
        self.assertTrue(report['changed_resources'])

    def test_kubernetes_serviceaccount_subject_namespace_changes_binding_identity(self):
        left = {'apiVersion':'rbac.authorization.k8s.io/v1', 'kind':'RoleBinding',
                'metadata':{'name':'synthetic-binding', 'namespace':'demo'},
                'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'reader'},
                'subjects':[{'kind':'ServiceAccount','name':'reader','namespace':'first'}]}
        right = copy.deepcopy(left)
        right['subjects'][0]['namespace'] = 'second'
        report = kubernetes_review.analyze_diff(self.data({'left':left, 'right':right}))
        self.assertFalse(report['normalized_review_equal'])
        self.assertEqual(len(report['changed_resources']), 1)

    def test_kubernetes_unknown_secret_is_not_reviewed_and_value_not_exported(self):
        value = {'apiVersion':'v1','kind':'Secret','metadata':{'name':'synthetic-secret'},
                 'stringData':{'password':'PRIVATE_KUBERNETES_VALUE_249'}}
        report = kubernetes_review.analyze(self.data(value))
        self.assertEqual(report['resources'][0]['review_status'], 'not_reviewed')
        self.assertEqual(report['summary']['not_reviewed_resources'], 1)
        self.assertNotIn('PRIVATE_KUBERNETES_VALUE_249', encode(report))

    def test_sarif_duplicate_claims_preserve_multiplicity_with_severity_change(self):
        left = sarif.sample()
        left['runs'][0]['results'] *= 3
        right = copy.deepcopy(left)
        right['runs'][0]['results'][0] = copy.deepcopy(right['runs'][0]['results'][0])
        right['runs'][0]['results'][0]['level'] = 'error'
        del right['runs'][0]['results'][-1]
        report = sarif.analyze_diff(self.data({'left':left, 'right':right}))
        self.assertEqual(report['counts'], {'added':0, 'resolved':1, 'unchanged':1, 'severity_changed':1})
        self.assertFalse(report['normalized_findings_equal'])

    def test_sarif_claimed_fingerprints_do_not_control_identity_or_scanner_version(self):
        left = sarif.sample()
        result = left['runs'][0]['results'][0]
        result['partialFingerprints'] = {'attacker':'same'}
        right = copy.deepcopy(left)
        right['runs'][0]['tool']['driver']['semanticVersion'] = '99.0.0'
        report = sarif.analyze_diff(self.data({'left':left, 'right':right}))
        self.assertEqual(report['counts']['added'], 1)
        self.assertEqual(report['counts']['resolved'], 1)
        self.assertFalse(report['normalized_findings_equal'])

    def test_sarif_file_uri_never_reads_a_local_source_or_exports_snippet(self):
        value = sarif.sample()
        result = value['runs'][0]['results'][0]
        physical = result['locations'][0]['physicalLocation']
        physical['artifactLocation']['uri'] = 'file:///private/not-readable.py'
        physical['region']['snippet'] = {'text':'PRIVATE_SOURCE_SNIPPET_249'}
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('file access')), patch.object(socket, 'create_connection', side_effect=AssertionError('network')):
            report = sarif.analyze(self.data(value))
        self.assertNotIn('PRIVATE_SOURCE_SNIPPET_249', encode(report))
        self.assertFalse(report['snippets_exported'])

    def test_archive_lexical_aliases_and_non_directory_ancestors_are_flagged(self):
        value = self.zip(['directory/./file', 'directory//file', 'parent', 'parent/child'])
        report = archive_review.analyze(value)
        codes = {row['code'] for row in report['findings']}
        self.assertIn('duplicate_path', codes)
        self.assertIn('path_type_conflict', codes)
        self.assertFalse(report['extracted'])
        self.assertFalse(report['crc_verified'])

    def test_archive_extra_filename_override_cannot_mask_unsafe_extraction_name(self):
        stream = io.BytesIO()
        info = zipfile.ZipInfo('safe-name.txt')
        payload = b'\x01' + b'\0'*4 + b'../../other'
        info.extra = struct.pack('<HH', 0x7075, len(payload)) + payload
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr(info, b'synthetic')
        with self.assertRaises(ValueError):
            archive_review.analyze(stream.getvalue())

    def test_archive_declared_expansion_is_not_decompressed(self):
        value = bytearray(self.zip(['synthetic.txt']))
        # Declare a deflated huge output in both headers while retaining inert bytes.
        central = value.index(b'PK\x01\x02')
        struct.pack_into('<H', value, 8, 8)
        struct.pack_into('<I', value, 22, 100*1024*1024)
        struct.pack_into('<H', value, central+10, 8)
        struct.pack_into('<I', value, central+24, 100*1024*1024)
        with patch('zlib.decompress', side_effect=AssertionError('decompression')), patch.object(Path, 'write_bytes', side_effect=AssertionError('extraction')):
            report = archive_review.analyze(bytes(value))
        self.assertIn('declared_expansion', {row['code'] for row in report['findings']})
        self.assertFalse(report['content_exported'])

    def test_dns_compression_loop_and_trailing_bytes_never_return_partial_message(self):
        loop = struct.pack('!6H', 1, 0, 1, 0, 0, 0) + b'\xc0\x0c\x00\x01\x00\x01'
        with self.assertRaises(ValueError):
            dns_message.analyze(loop)
        sample = base64.b64decode(dns_message.sample()['dns_base64'])
        with self.assertRaises(ValueError):
            dns_message.analyze(sample+b'garbage')

    def test_dns_txt_secret_is_represented_by_lengths_only(self):
        label = b'\x07example\x04test\x00'
        secret = b'PRIVATE_DNS_TXT_249'
        raw = struct.pack('!6H', 1, 0x8000, 0, 1, 0, 0) + label + struct.pack('!HHIH', 16, 1, 60, len(secret)+1) + bytes([len(secret)]) + secret
        report = dns_message.analyze(raw)
        self.assertNotIn(secret.decode(), encode(report))
        self.assertEqual(report['records'][0]['data'], {'string_count':1,'lengths':[len(secret)]})
        self.assertFalse(report['dnssec_verified'])

    def test_systemd_command_and_environment_are_presence_metadata_only(self):
        secret = 'PRIVATE_UNIT_EXECUTION_249'
        value = ('[Service]\nExecStart=/bin/sh -c "'+secret+'"\nEnvironment=TOKEN='+secret+'\nUser=0\n').encode()
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('execution')), patch.object(socket, 'create_connection', side_effect=AssertionError('network')):
            report = systemd_review.analyze(value)
        self.assertNotIn(secret, encode(report))
        self.assertTrue(report['exec_start_present'])
        self.assertTrue(report['environment_present'])
        self.assertFalse(report['applied'])
