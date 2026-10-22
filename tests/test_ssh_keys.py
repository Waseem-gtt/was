"""OpenSSH public metadata and option redaction regression tests."""
import base64
import json
import struct
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cyber_platform import ssh_keys as ssh


class SSHKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa1024=rsa.generate_private_key(public_exponent=65537,key_size=1024).public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
        cls.rsa2048=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()

    def test_fixed_public_sample_restricted_ed25519(self):
        r=ssh.analyze(ssh.sample().encode());self.assertEqual(r['key_count'],1)
        self.assertEqual(r['keys'][0]['type'],'Ed25519');self.assertEqual(r['keys'][0]['bits'],256)
        self.assertEqual(r['keys'][0]['option_names'],['restrict']);self.assertEqual(r['findings'],[])
        self.assertFalse(r['authenticated']);self.assertFalse(r['network'])

    def test_public_fingerprint_binds_key_blob(self):
        a=ssh.analyze(ssh.sample().encode())['keys'][0]
        self.assertEqual(len(a['sha256']),64);self.assertTrue(a['fingerprint'].startswith('SHA256:'))
        plain=ssh.sample().split(' ',1)[1]
        b=ssh.analyze(plain.encode())['keys'][0]
        self.assertEqual(a['sha256'],b['sha256'])

    def test_private_key_formats_are_refused(self):
        private=ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption())
        with self.assertRaises(ValueError):ssh.analyze(private)

    def test_rsa_weak_size_warning(self):
        r=ssh.analyze(self.rsa1024.encode());self.assertEqual(r['keys'][0]['bits'],1024)
        self.assertIn('weak_rsa_size',{f['code'] for f in r['findings']})

    def test_rsa_2048_public_key(self):
        r=ssh.analyze(self.rsa2048.encode());self.assertEqual(r['keys'][0]['type'],'RSA')
        self.assertNotIn('weak_rsa_size',{f['code'] for f in r['findings']})

    def test_all_documented_ecdsa_curves(self):
        for curve in (ec.SECP256R1(),ec.SECP384R1(),ec.SECP521R1()):
            public=ec.generate_private_key(curve).public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH)
            with self.subTest(curve=curve.name):
                r=ssh.analyze(public);self.assertEqual(r['keys'][0]['bits'],curve.key_size)

    def test_declared_algorithm_mismatch_refused(self):
        sample=ssh.sample().replace('restrict ssh-ed25519','ssh-rsa')
        with self.assertRaises(ValueError):ssh.analyze(sample.encode())

    def test_malformed_base64_refused(self):
        with self.assertRaises(ValueError):ssh.analyze(b'ssh-ed25519 !!')

    def test_truncated_length_blob_refused(self):
        value=base64.b64encode(b'\xff\xff\xff\xffx').decode()
        with self.assertRaises(ValueError):ssh.analyze(('ssh-ed25519 '+value).encode())

    def test_trailing_blob_fields_refused(self):
        algorithm,blob=ssh.sample().split()[1:3]
        value=base64.b64encode(base64.b64decode(blob)+b'trailing').decode()
        with self.assertRaises(ValueError):ssh.analyze((algorithm+' '+value).encode())

    def test_duplicate_public_keys_preserve_both_and_finding(self):
        r=ssh.analyze((ssh.sample()*2).encode());self.assertEqual(r['key_count'],2)
        self.assertEqual(r['summary']['duplicate_keys'],1);self.assertEqual(r['findings'][0]['code'],'duplicate_key')

    def test_comment_and_option_secrets_are_not_exported(self):
        public=' '.join(ssh.sample().split()[1:3])
        secret='SECRET_CANARY_NO_EXPORT_12345'
        value='command="echo '+secret+'",environment="API_TOKEN='+secret+'",from="'+secret+'" '+public+' '+secret
        r=ssh.analyze(value.encode());encoded=json.dumps(r)
        self.assertNotIn(secret,encoded);self.assertNotIn('API_TOKEN',encoded);self.assertNotIn('echo ',encoded)
        self.assertEqual(r['keys'][0]['option_names'],['command','environment','from'])
        self.assertIn('option_command',{f['code'] for f in r['findings']})

    def test_quoted_spaces_commas_and_escapes_are_data(self):
        public=' '.join(ssh.sample().split()[1:3])
        data=('command="echo \\\"a,b\\\"",no-pty '+public).encode()
        r=ssh.analyze(data);self.assertEqual(r['keys'][0]['option_names'],['command','no-pty'])

    def test_unknown_option_and_known_hosts_refused(self):
        public=' '.join(ssh.sample().split()[1:3])
        for option in ('localhost','example.test','unknown-flag','@cert-authority'):
            with self.subTest(option=option),self.assertRaises(ValueError):ssh.analyze((option+' '+public).encode())

    def test_duplicate_options_refused(self):
        with self.assertRaises(ValueError):ssh.analyze(ssh.sample().replace('restrict','restrict,restrict').encode())

    def test_flag_cannot_have_value_and_value_requires_argument(self):
        for option in ('restrict=yes','command','command=','command=""'):
            with self.subTest(option=option),self.assertRaises(ValueError):ssh.analyze(ssh.sample().replace('restrict',option).encode())

    def test_unterminated_or_interior_quoted_options_refused(self):
        for option in ('command="unterminated','command="x"y"','command=x\\'):
            with self.subTest(option=option),self.assertRaises(ValueError):ssh.analyze(ssh.sample().replace('restrict',option).encode())

    def test_comments_and_blank_lines_are_ignored(self):
        data='# header\n\n'+ssh.sample()+'\n# footer\n'
        self.assertEqual(ssh.analyze(data.encode())['key_count'],1)

    def test_no_public_key_refused(self):
        for data in (b'',b'# comment\n',b'   \n'):
            with self.subTest(data=data),self.assertRaises(ValueError):ssh.analyze(data)

    def test_unicode_controls_bidi_and_invalid_utf8_refused(self):
        for data in (ssh.sample().encode()+b'\x01',ssh.sample().encode()+b'\xff',(ssh.sample()+'\u202e').encode()):
            with self.subTest(data=data[-3:]),self.assertRaises(ValueError):ssh.analyze(data)

    def test_max_input_and_line_and_line_count_refused(self):
        for data in (b'x'*(4*1024*1024+1),b'#'+b'x'*8192,b'\n'*2001):
            with self.subTest(size=len(data)),self.assertRaises(ValueError):ssh.analyze(data)

    def test_key_count_and_option_count_enforced(self):
        with patch.dict(ssh.LIMITS,keys=1),self.assertRaises(ValueError):ssh.analyze((ssh.sample()*2).encode())
        with patch.dict(ssh.LIMITS,options_per_key=1),self.assertRaises(ValueError):ssh.analyze(ssh.sample().replace('restrict','restrict,no-pty').encode())

    def test_rsa_size_policy_applies_before_result(self):
        with patch.dict(ssh.LIMITS,rsa_bits=1024),self.assertRaises(ValueError):ssh.analyze(self.rsa2048.encode())

    def test_ssh_cert_and_dsa_types_are_not_silently_accepted(self):
        for name in ('ssh-ed25519-cert-v01@openssh.com','ssh-dss'):
            with self.subTest(name=name),self.assertRaises(ValueError):ssh.analyze(ssh.sample().replace('ssh-ed25519',name).encode())

    def test_error_does_not_echo_secret_option_value(self):
        secret='SECRET_ERROR_CANARY'
        data=ssh.sample().replace('restrict','unknown="'+secret+'"').encode()
        with self.assertRaises(ValueError) as error:ssh.analyze(data)
        self.assertNotIn(secret,str(error.exception))

    def test_no_files_network_or_shell_execution(self):
        with patch('builtins.open',side_effect=AssertionError('filesystem')),patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('shell')):
            self.assertEqual(ssh.analyze(ssh.sample().encode())['key_count'],1)

    def test_actual_bounded_worker_and_refusal(self):
        from cyber_platform import worker
        self.assertEqual(worker.analyze('ssh-keys',ssh.sample().encode())['key_count'],1)
        with self.assertRaises(ValueError):worker.analyze('ssh-keys',b'not a key')
