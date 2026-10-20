"""Public certificate analysis stays offline and never promotes supplied trust."""
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from cyber_platform import certificates


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def cert(self, name='root.fixture.test', key=None, signer=None, issuer=None, serial=1, extensions=(), rsa_padding=None):
        key = key or self.key
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
                   .public_key(key.public_key()).serial_number(serial)
                   .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
                   .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc)))
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical)
        signer = signer or key
        algorithm = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
        return builder.sign(signer, algorithm, rsa_padding=rsa_padding)

    def pem(self, *certs):
        return b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs)

    def envelope(self, pem=None, **changes):
        value = {'certificates_pem': (pem or self.pem(self.cert())).decode(), **changes}
        return json.dumps(value).encode()

    def test_fixed_public_sample_signature_and_explicit_time_are_deterministic(self):
        result = certificates.analyze(json.dumps(certificates.sample()).encode())
        self.assertEqual(result['schema'], 'was.certificate-analysis/1')
        self.assertEqual(result['certificate_count'], 1)
        cert = result['certificates'][0]
        self.assertEqual(cert['self_signature'], 'valid')
        self.assertTrue(cert['self_issued'])
        self.assertEqual(cert['time_status'], 'within_validity_period')
        self.assertEqual(cert['key']['type'], 'EC')
        self.assertEqual(cert['subject_alt_names'][0]['value'], 'synthetic.example.test')
        self.assertEqual(result['trust'], 'not_evaluated')
        self.assertFalse(result['network'])
        self.assertEqual(result, certificates.analyze(json.dumps(certificates.sample()).encode()))

    def test_raw_pem_and_der_have_identical_results_without_implicit_clock(self):
        cert = self.cert()
        pem = certificates.analyze(self.pem(cert))
        der = certificates.analyze(cert.public_bytes(serialization.Encoding.DER))
        self.assertEqual(pem, der)
        self.assertIsNone(pem['validation_time'])
        self.assertEqual(pem['certificates'][0]['time_status'], 'not_evaluated')
        self.assertEqual(len(pem['certificates'][0]['spki_sha256']), 64)

    def test_explicit_expired_future_and_offset_normalization(self):
        for date, status in [('2031-01-01T00:00:00Z', 'expired'),
                             ('2024-01-01T00:00:00Z', 'not_yet_valid'),
                             ('2026-10-20T03:00:00+03:00', 'within_validity_period')]:
            result = certificates.analyze(self.envelope(validation_time=date))
            self.assertEqual(result['certificates'][0]['time_status'], status)
        self.assertEqual(result['validation_time'], '2026-10-20T00:00:00+00:00')

    def test_validation_time_requires_valid_explicit_offset(self):
        for date in ['2026-10-20', '2026-10-20T00:00:00', '2026-02-30T00:00:00Z',
                     '2026-10-20T00:00:00+24:00', '2026-10-20T00:00:00+00:99', None, True]:
            with self.subTest(date=date), self.assertRaises(ValueError):
                certificates.analyze(self.envelope(validation_time=date))

    def test_extra_envelope_fields_duplicates_and_nonfinite_rejected(self):
        sample = certificates.sample()
        for value in [{**sample, 'url': 'https://example.test'}, {'certificates_pem': []},
                      {'validation_time': '2026-10-20T00:00:00Z'}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                certificates.analyze(json.dumps(value).encode())
        for raw in [b'{"certificates_pem":"a","certificates_pem":"b"}',
                    b'{"certificates_pem":"a","validation_time":NaN}']:
            with self.assertRaises(ValueError): certificates.analyze(raw)

    def test_empty_malformed_and_wrong_input_types_rejected(self):
        for raw in [b'', b'not a certificate', b'{}', b'-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----', '', None]:
            with self.subTest(raw=raw), self.assertRaises(ValueError): certificates.analyze(raw)

    def test_trailing_and_prefixed_pem_data_or_private_key_blocks_rejected(self):
        pem = self.pem(self.cert())
        for raw in [pem + b'junk', b'junk' + pem,
                    pem + b'-----BEGIN PRIVATE KEY-----\nsynthetic-only\n-----END PRIVATE KEY-----',
                    b'-----BEGIN TRUSTED CERTIFICATE-----\nAA\n-----END TRUSTED CERTIFICATE-----']:
            with self.subTest(raw=raw[:35]), self.assertRaises(ValueError): certificates.analyze(raw)
        self.assertEqual(certificates.analyze(b' \n' + pem + b'\n ')['certificate_count'], 1)

    def test_der_cannot_hide_trailing_bytes_or_second_certificate(self):
        cert = self.cert().public_bytes(serialization.Encoding.DER)
        for raw in [cert + b'junk', cert + cert]:
            with self.assertRaises(ValueError): certificates.analyze(raw)

    def test_duplicate_and_over_count_bundles_rejected(self):
        cert = self.cert()
        with self.assertRaises(ValueError): certificates.analyze(self.pem(cert, cert))
        many = [self.cert(serial=i + 1) for i in range(11)]
        with self.assertRaises(ValueError): certificates.analyze(self.pem(*many))
        self.assertEqual(certificates.analyze(self.pem(*many[:10]))['certificate_count'], 10)

    def test_input_limit_enforced_before_parsing(self):
        with self.assertRaises(ValueError): certificates.analyze(b'A' * (certificates.MAX_BYTES + 1))

    def test_provided_issuer_signature_and_constraints_do_not_establish_trust(self):
        root = self.cert(extensions=[(x509.BasicConstraints(ca=True, path_length=1), True)])
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = self.cert(name='leaf.fixture.test', key=leaf_key, signer=self.key, issuer=root.subject, serial=2)
        result = certificates.analyze(self.pem(leaf, root))
        self.assertEqual(result['chain_links'], [{'certificate': 0, 'issuer': 1, 'signature': 'valid',
            'issuer_is_ca': True, 'issuer_key_cert_sign': None, 'trusted': False}])
        self.assertEqual(result['trust'], 'not_evaluated')
        self.assertFalse(result['certificates'][0]['self_issued'])
        self.assertEqual(result['certificates'][0]['self_signature'], 'not_evaluated')

    def test_same_issuer_name_wrong_key_is_invalid_not_trusted(self):
        root = self.cert()
        other_signer = ec.generate_private_key(ec.SECP256R1())
        leaf = self.cert(name='leaf.fixture.test', signer=other_signer, issuer=root.subject, serial=2)
        result = certificates.analyze(self.pem(leaf, root))
        self.assertEqual(result['chain_links'][0]['signature'], 'invalid')
        self.assertFalse(result['chain_links'][0]['trusted'])

    def test_self_issued_is_not_assumed_self_signed(self):
        other_signer = ec.generate_private_key(ec.SECP256R1())
        result = certificates.analyze(self.pem(self.cert(signer=other_signer)))['certificates'][0]
        self.assertTrue(result['self_issued'])
        self.assertEqual(result['self_signature'], 'invalid')

    def test_rsa_pkcs1_and_pss_signatures_verified_with_actual_parameters(self):
        for signature_padding in [None, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)]:
            cert = self.cert(key=self.rsa_key, rsa_padding=signature_padding)
            result = certificates.analyze(self.pem(cert))['certificates'][0]
            self.assertEqual(result['self_signature'], 'valid')
            self.assertEqual(result['key'], {'type': 'RSA', 'bits': 2048})

    def test_ed25519_has_no_hash_and_real_signature_verification(self):
        key = ed25519.Ed25519PrivateKey.generate()
        result = certificates.analyze(self.pem(self.cert(key=key)))['certificates'][0]
        self.assertIsNone(result['signature']['hash'])
        self.assertEqual(result['key']['type'], 'Ed25519')
        self.assertEqual(result['self_signature'], 'valid')

    def test_key_usage_sans_eku_and_unknown_critical_are_descriptive(self):
        usage = x509.KeyUsage(True, False, False, False, False, True, True, False, False)
        extensions = [(usage, True), (x509.SubjectAlternativeName([x509.DNSName('leaf.fixture.test')]), False),
                      (x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), False),
                      (x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4.5'), b'\x05\x00'), True)]
        result = certificates.analyze(self.pem(self.cert(extensions=extensions)))['certificates'][0]
        self.assertTrue(result['key_usage']['key_cert_sign'])
        self.assertIsNone(result['key_usage']['encipher_only'])
        self.assertEqual(result['extended_key_usage'], ['1.3.6.1.5.5.7.3.1'])
        self.assertIn('unrecognized_critical_extensions', result['warnings'])

    def test_weak_key_size_is_a_warning_not_safety_judgment(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        result = certificates.analyze(self.pem(self.cert(key=key)))
        self.assertIn('weak_public_key_size', result['certificates'][0]['warnings'])
        self.assertEqual(result['trust'], 'not_evaluated')

    def test_san_and_extension_output_limits_refuse_truncation(self):
        extension = x509.SubjectAlternativeName([x509.DNSName(f'fixture-{i}.test') for i in range(101)])
        with self.assertRaises(ValueError): certificates.analyze(self.pem(self.cert(extensions=[(extension, False)])))
        extensions = [(x509.UnrecognizedExtension(x509.ObjectIdentifier(f'1.2.3.4.{i}'), b'\x05\x00'), False) for i in range(51)]
        with self.assertRaises(ValueError): certificates.analyze(self.pem(self.cert(extensions=extensions)))

    def test_certificate_analysis_never_connects_or_resolves_external_sources(self):
        with patch('socket.socket', side_effect=AssertionError('network is forbidden')):
            result = certificates.analyze(json.dumps(certificates.sample()).encode())
        self.assertFalse(result['network'])
        self.assertEqual(result['chain_links'], [])

    def test_tampered_signature_is_reported_invalid(self):
        cert = self.cert().public_bytes(serialization.Encoding.DER)
        # DER signature is the final bit string. Changing the last signature byte
        # retains the certificate structure but invalidates its proof.
        tampered = cert[:-1] + bytes([cert[-1] ^ 1])
        result = certificates.analyze(tampered)['certificates'][0]
        self.assertEqual(result['self_signature'], 'invalid')

    def test_registered_bounded_worker_executes_and_rejects_invalid_certificates(self):
        from cyber_platform import worker
        raw = json.dumps(certificates.sample()).encode()
        result = worker.analyze('certificate', raw, timeout=3)
        self.assertEqual(result, certificates.analyze(raw))
        with self.assertRaises(ValueError):
            worker.analyze('certificate', b'not an X.509 certificate', timeout=3)
