"""Independent regression checks for offline technical analysis boundaries."""
import copy
import ipaddress
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cyber_platform import (case_reports, certificates, coverage_scans, curriculum,
                            detection, engine, event_adapters, pcap, plans, quality,
                            supply_chain)


class TechnicalReviewTests(unittest.TestCase):
    def test_every_technical_source_change_invalidates_all_execution_fingerprints(self):
        functions = (engine.fingerprint, quality._engine, plans.fingerprint,
                     detection._engine, curriculum._engine,
                     case_reports._fingerprint, coverage_scans._engine)
        original_read = Path.read_bytes
        for source in ('pcap.py', 'certificates.py', 'supply_chain.py', 'event_adapters.py'):
            for fingerprint in functions:
                before = fingerprint()

                def changed(path, source=source):
                    value = original_read(path)
                    return value + b'\n# independent provenance regression\n' if path.name == source else value

                with self.subTest(source=source, function=fingerprint.__module__), patch.object(Path, 'read_bytes', changed):
                    self.assertNotEqual(fingerprint(), before)

    def test_later_malformed_packet_never_returns_earlier_capture_as_complete(self):
        source = pcap.sample()
        broken = source + struct.pack('<IIII', 1700000001, 0, 20, 20) + b'bad'
        with self.assertRaises(ValueError):
            pcap.analyze(broken)
        self.assertEqual(pcap.analyze(source)['packet_count'], 1)

    def test_noninitial_fragment_payload_is_never_interpreted_as_tcp_ports(self):
        # These bytes resemble ports but belong to a later IP fragment.
        payload = struct.pack('!HHI', 22, 443, 0)
        packet = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 1, 1, 64, 6, 0,
                             ipaddress.IPv4Address('192.0.2.1').packed,
                             ipaddress.IPv4Address('198.51.100.2').packed) + payload
        capture = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        capture += struct.pack('<IIII', 1700000000, 0, len(packet), len(packet)) + packet
        flow = pcap.analyze(capture)['flows'][0]
        self.assertIsNone(flow['source_port'])
        self.assertIsNone(flow['destination_port'])
        self.assertEqual(flow['fragmented_packets'], 1)

    def test_supplied_self_signed_certificate_does_not_create_trust_or_implicit_clock(self):
        public_pem = certificates.sample()['certificates_pem'].encode()
        result = certificates.analyze(public_pem)
        self.assertEqual(result['trust'], 'not_evaluated')
        self.assertIsNone(result['validation_time'])
        self.assertEqual(result['certificates'][0]['self_signature'], 'valid')
        self.assertEqual(result['certificates'][0]['time_status'], 'not_evaluated')
        self.assertFalse(result['network'])

    def test_tampered_signature_is_not_promoted_by_self_issued_name(self):
        cert = x509.load_pem_x509_certificate(certificates.sample()['certificates_pem'].encode())
        changed = bytearray(cert.public_bytes(serialization.Encoding.DER))
        changed[-1] ^= 1
        result = certificates.analyze(bytes(changed))
        self.assertTrue(result['certificates'][0]['self_issued'])
        self.assertEqual(result['certificates'][0]['self_signature'], 'invalid')
        self.assertEqual(result['trust'], 'not_evaluated')

    def test_vulnerability_rating_score_change_is_visible_in_complete_sbom_comparison(self):
        before = supply_chain.sample()
        identifier = before['components'][0]['bom-ref']
        before['vulnerabilities'] = [{'id': 'CVE-2026-0001', 'affects': [{'ref': identifier}],
                                      'ratings': [{'severity': 'high', 'score': 7.5, 'method': 'CVSSv3'}]}]
        after = copy.deepcopy(before)
        after['vulnerabilities'][0]['ratings'][0]['score'] = 9.8
        difference = supply_chain.diff(json.dumps(before).encode(), json.dumps(after).encode())
        self.assertTrue(difference['complete'])
        self.assertTrue(difference['vulnerability_claims_changed'])
        self.assertFalse(difference['normalized_inventory_equal'])

    def test_absent_vulnerability_declarations_are_not_a_safety_verdict(self):
        result = supply_chain.analyze(json.dumps(supply_chain.sample()).encode())
        self.assertEqual(result['vulnerabilities'], [])
        self.assertEqual(result['vulnerability_assessment'], 'source_claims_only_not_live_audit')
        self.assertNotIn('safe', result)
        self.assertNotIn('passed', result)

    def test_windows_xml_entity_processing_and_foreign_elements_fail_without_io(self):
        sample = next(item['example_content'] for item in event_adapters.catalog()
                      if item['id'] == 'windows-xml')
        malicious = [
            '<!DOCTYPE Event [<!ENTITY secret SYSTEM "file:///nonexistent-review-fixture">]>' + sample,
            '<?review forbidden?>' + sample,
            sample.replace('<System>', '<System><xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///nonexistent-review-fixture"/>'),
        ]
        with patch('socket.socket', side_effect=AssertionError('unexpected network')), \
                patch('builtins.open', side_effect=AssertionError('unexpected filesystem read')):
            for content in malicious:
                with self.subTest(content=content[:70]), self.assertRaises(ValueError):
                    event_adapters.normalize('windows-xml', content)
            normalized = event_adapters.normalize('windows-xml', sample)
        self.assertEqual(normalized['count'], 1)
        self.assertEqual(normalized['events'][0]['outcome'], 'unknown')
