"""MIME metadata is bounded, private and never treated as trusted authentication."""
import base64
import hashlib
import unittest
from unittest.mock import patch
from cyber_platform import email_review as eml
from cyber_platform.store import encode


class EmailReviewTests(unittest.TestCase):
    def raw(self):return eml.sample().encode()
    def basic(self,extra='',body='private body'):
        return ('From: Local <private@example.test>\r\nTo: destination@example.net\r\n'+extra+'\r\n'+body).encode()

    def test_sample_metadata_and_hashes(self):
        raw=self.raw();result=eml.analyze(raw)
        self.assertEqual((result['part_count'],result['attachment_count']),(3,1))
        self.assertEqual(result['attachments'][0]['decoded_bytes'],20)
        self.assertEqual(result['attachments'][0]['sha256'],hashlib.sha256(b'Synthetic attachment').hexdigest())
        self.assertEqual(result['source_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertFalse(result['network']);self.assertFalse(result['content_exported']);self.assertFalse(result['extracted'])

    def test_domains_without_mailbox_localparts(self):
        result=eml.analyze(self.raw())
        self.assertEqual(result['domains'],{'from':['example.test'],'to':['example.net'],'reply_to':['example.test']})
        self.assertNotIn('sender@',encode(result));self.assertNotIn('recipient@',encode(result))

    def test_all_sensitive_owner_content_is_excluded(self):
        secret='PRIVATE_CANARY_728194'
        # Keep header syntax valid while carrying a secret in independent fields.
        raw=self.raw().replace(b'From: Synthetic <sender@',('Subject: '+secret+'\r\nX-Secret: '+secret+'\r\nFrom: '+secret+' <'+secret+'@').encode()).replace(b'Synthetic private body.',secret.encode()).replace(b'example.txt',(secret+'.'+secret).encode())
        result=eml.analyze(raw);serialized=encode(result)
        self.assertNotIn(secret,serialized);self.assertEqual(result['attachments'][0]['extension'],'unknown')

    def test_content_type_unknown_values_cannot_export_arbitrary_secrets(self):
        raw=self.raw().replace(b'Content-Type: text/plain\r\nContent-Disposition',b'Content-Type: application/PRIVATE_CANARY\r\nContent-Disposition')
        result=eml.analyze(raw)
        self.assertEqual(result['attachments'][0]['content_type'],'other');self.assertNotIn('private_canary',encode(result))

    def test_auth_results_are_claims_only_and_whitelisted(self):
        result=eml.analyze(self.raw())
        self.assertEqual(len(result['auth_claims']),3)
        self.assertTrue(all(a['verification']=='source_claim_only' and a['result']=='pass' for a in result['auth_claims']))
        self.assertEqual(result['auth_verification'],'source_claims_only')
        raw=self.basic('Authentication-Results: owner.example; spf=PRIVATE_TOKEN; dkim=fail\r\n')
        result=eml.analyze(raw);self.assertNotIn('PRIVATE_TOKEN',encode(result));self.assertEqual(len(result['auth_claims']),1)
        self.assertIn('reported_auth_failure',[f['code'] for f in result['findings']])

    def test_reply_domain_difference_is_observation_not_phishing_verdict(self):
        result=eml.analyze(self.basic('Reply-To: other@different.test\r\n'))
        self.assertEqual(result['findings'][0]['code'],'reply_domain_differs')
        self.assertNotIn('phishing',encode(result))

    def test_empty_malformed_and_non_header_input_rejected(self):
        for raw in (b'',b'just body',b'\x00',b'Bad header\r\n\r\nbody'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):eml.analyze(raw)

    def test_duplicate_structural_headers_rejected(self):
        for extra in ('From: other@example.test\r\n','Content-Type: text/plain\r\nContent-Type: text/html\r\n','Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit\r\n'):
            with self.assertRaises(ValueError):eml.analyze(self.basic(extra))

    def test_bad_domains_and_addresses_rejected_without_echo(self):
        for address in ('private@bad_domain.test','private@','private@[127.0.0.1]'):
            raw=('From: '+address+'\r\n\r\nbody').encode()
            with self.assertRaises(ValueError) as caught:eml.analyze(raw)
            self.assertNotIn('private',str(caught.exception))

    def test_later_malformed_mime_part_never_returns_earlier_success(self):
        raw=self.raw().replace(b'U3ludGhldGljIGF0dGFjaG1lbnQ=',b'%%%%INVALID_BASE64%%%%')
        with self.assertRaisesRegex(ValueError,'Invalid EML base64'):eml.analyze(raw)

    def test_malformed_multipart_boundary_rejected(self):
        with self.assertRaises(ValueError):eml.analyze(self.raw().replace(b'--synthetic-boundary--',b'--wrong-boundary--'))

    def test_unsupported_encapsulated_message_rejected(self):
        raw=self.basic('Content-Type: message/rfc822\r\n',body='From: nested@example.test\r\n\r\ninner')
        with self.assertRaisesRegex(ValueError,'Encapsulated'):eml.analyze(raw)

    def test_multipart_attachment_container_rejected(self):
        raw=self.raw().replace(b'MIME-Version: 1.0',b'Content-Disposition: attachment; filename="private.eml"\r\nMIME-Version: 1.0')
        with self.assertRaises(ValueError):eml.analyze(raw)

    def test_transfer_encodings_strict(self):
        for encoding,body in [('rot13','abc'),('base64','bad!!'),('quoted-printable','bad=XX'),('7bit','\u00e9')]:
            with self.subTest(encoding=encoding),self.assertRaises(ValueError):eml.analyze(self.basic('Content-Transfer-Encoding: '+encoding+'\r\n',body))

    def test_quoted_printable_attachment_bytes_are_hashed(self):
        raw=self.basic('Content-Type: text/plain\r\nContent-Disposition: attachment; filename="safe.txt"\r\nContent-Transfer-Encoding: quoted-printable\r\n','a=20b')
        result=eml.analyze(raw)
        self.assertEqual(result['attachments'][0]['sha256'],hashlib.sha256(b'a b').hexdigest())
        self.assertEqual(result['attachments'][0]['decoded_bytes'],3)

    def test_base64_attachment_name_is_only_hash_and_extension(self):
        raw=self.basic('Content-Type: application/pdf\r\nContent-Disposition: attachment; filename="PRIVATE-NAME.pdf"\r\nContent-Transfer-Encoding: base64\r\n',base64.b64encode(b'PRIVATE_BODY_CANARY').decode())
        result=eml.analyze(raw);self.assertEqual(result['attachments'][0]['extension'],'pdf')
        self.assertNotIn('PRIVATE-NAME',encode(result));self.assertNotIn('PRIVATE_BODY_CANARY',encode(result))

    def test_8bit_body_is_not_exported(self):
        result=eml.analyze(self.basic('Content-Transfer-Encoding: 8bit\r\n','موضوع خاص'))
        self.assertEqual(result['part_count'],1);self.assertNotIn('موضوع',encode(result))

    def test_input_line_and_output_limits(self):
        for limits in ({'input_bytes':1},{'line_bytes':3},{'lines':1},{'output_bytes':1}):
            with patch.dict(eml.LIMITS,limits),self.assertRaises(ValueError):eml.analyze(self.raw())

    def test_header_count_size_and_address_caps(self):
        for limits in ({'headers_per_part':1},{'header_bytes':1},{'addresses':0}):
            with patch.dict(eml.LIMITS,limits),self.assertRaises(ValueError):eml.analyze(self.raw())

    def test_part_depth_and_attachment_filename_caps(self):
        for limits in ({'parts':1},{'depth':0},{'filename_characters':2}):
            with patch.dict(eml.LIMITS,limits),self.assertRaises(ValueError):eml.analyze(self.raw())

    def test_nul_and_header_invalid_encoding_rejected(self):
        for raw in (self.raw()+b'\x00',b'From: \xff@example.test\r\n\r\nbody'):
            with self.assertRaises(ValueError):eml.analyze(raw)

    def test_no_network_file_creation_or_process_execution(self):
        with patch('socket.create_connection',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('exec')),patch('builtins.open',side_effect=AssertionError('file')):
            self.assertEqual(eml.analyze(self.raw())['attachment_count'],1)

    def test_registered_bounded_worker_preserves_private_metadata(self):
        from cyber_platform import worker
        result=worker.analyze('email',self.raw())
        self.assertEqual(result['attachment_count'],1)
        self.assertFalse(result['content_exported'])
