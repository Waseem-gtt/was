"""Offline Windows XML subset: strict structure, no entity or I/O authority."""
import hashlib
import json
from unittest import TestCase
from unittest.mock import patch

from cyber_platform import event_adapters as ea, event_ingest, worker
from cyber_platform.store import Problem
from tests.test_platform import StoreCase


class WindowsXMLTests(TestCase):
    def sample(self):
        return next(row['example_content'] for row in ea.catalog() if row['id'] == 'windows-xml')

    def normalize(self, content):
        return ea.normalize('windows-xml', content)

    def test_single_event_100ns_timestamp_original_and_no_guessed_outcome(self):
        content = self.sample().replace('>demo</Data>', '>علي &amp; test</Data>')
        result = self.normalize(content)
        self.assertEqual(result['input_sha256'], hashlib.sha256(content.encode()).hexdigest())
        event = result['events'][0]
        self.assertEqual(event['actor'], 'علي & test')
        self.assertEqual(event['time'], '2026-01-01T00:00:00.1234567Z')
        self.assertEqual(event['event_id'], 4625)
        self.assertEqual(event['host'], 'demo-host')
        self.assertEqual((event['action'], event['outcome']), ('unknown', 'unknown'))
        self.assertEqual(event['original']['System']['Security'], {'UserID': 'S-1-0-0'})
        self.assertEqual(result['failed'], 0)

    def test_multiple_events_and_namespaced_or_plain_wrapper(self):
        for wrapper in ('<Events>', f'<Events xmlns="{ea.XML_NAMESPACE}">'):
            result = self.normalize(wrapper + self.sample() * 2 + '</Events>')
            self.assertEqual(result['count'], 2)
            self.assertEqual(result['events'][0], result['events'][1])

    def test_xml_namespace_prefix_is_supported(self):
        content = self.sample().replace('xmlns=', 'xmlns:w=')
        for name in ('Event', 'System', 'Provider', 'EventID', 'TimeCreated', 'Computer', 'Security', 'EventData', 'Data'):
            content = content.replace('<' + name, '<w:' + name).replace('</' + name, '</w:' + name)
        self.assertEqual(self.normalize(content)['count'], 1)

    def test_standard_optional_system_metadata_and_security_actor_fallback(self):
        content = self.sample().replace('<EventData>', '<EventData>').replace('<Data Name="TargetUserName">demo</Data>', '')
        content = content.replace('<Provider Name="Synthetic"/>', '<Provider Name="Synthetic" Guid="{00000000-0000-0000-0000-000000000000}"/>')
        content = content.replace('</System>', '<Version>1</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><EventRecordID>123</EventRecordID><Execution ProcessID="4" ThreadID="8"/><Correlation ActivityID="synthetic"/><Channel>Security</Channel></System>')
        event = self.normalize(content)['events'][0]
        self.assertEqual(event['actor'], 'S-1-0-0')
        self.assertEqual(event['original']['System']['Execution'], {'ProcessID': 4, 'ThreadID': 8})
        self.assertEqual(event['original']['System']['EventRecordID'], 123)
        self.assertEqual(event['original']['System']['Channel'], 'Security')

    def test_empty_target_actor_is_unknown_but_original_is_preserved(self):
        event = self.normalize(self.sample().replace('>demo</Data>', '></Data>'))['events'][0]
        self.assertEqual(event['actor'], 'unknown')
        self.assertEqual(event['original']['EventData']['TargetUserName'], '')

    def test_missing_required_or_duplicate_event_containers_rejected(self):
        sample = self.sample()
        cases = [sample.replace('<System>', '<Other>').replace('</System>', '</Other>'),
                 sample.replace('<EventID>4625</EventID>', ''),
                 sample.replace('<TimeCreated SystemTime="2026-01-01T00:00:00.1234567Z"/>', ''),
                 sample.replace('</Event>', '<System/></Event>'),
                 sample.replace('</Event>', '<EventData/></Event>')]
        for content in cases:
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.normalize(content)

    def test_duplicate_system_fields_or_data_names_rejected(self):
        for insertion in ('<EventID>2</EventID>', '<Computer>other</Computer>'):
            with self.subTest(insertion=insertion), self.assertRaises(ValueError):
                self.normalize(self.sample().replace('</System>', insertion + '</System>'))
        with self.assertRaises(ValueError):
            self.normalize(self.sample().replace('</EventData>', '<Data Name="TargetUserName">second</Data></EventData>'))

    def test_unsupported_shapes_attributes_and_mixed_text_rejected(self):
        cases = [self.sample().replace('<EventData>', '<EventData Name="x">'),
                 self.sample().replace('<Data Name="TargetUserName">', '<Data>'),
                 self.sample().replace('<Data Name="TargetUserName">', '<Data Name="TargetUserName" Extra="x">'),
                 self.sample().replace('<System>', '<System>unexpected'),
                 self.sample().replace('</System>', '<Events/></System>'),
                 self.sample().replace('</System>', '<EventID><Data Name="x">x</Data></EventID></System>'),
                 self.sample().replace('</Event>', '<UserData/></Event>'),
                 '<Events>unexpected' + self.sample() + '</Events>',
                 '<Events Unknown="x">' + self.sample() + '</Events>']
        for content in cases:
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.normalize(content)

    def test_foreign_or_missing_namespaces_and_xinclude_rejected(self):
        cases = [self.sample().replace(ea.XML_NAMESPACE, 'https://example.test/foreign'),
                 self.sample().replace(' xmlns="' + ea.XML_NAMESPACE + '"', ''),
                 self.sample().replace('<Computer>', '<Computer xmlns="">'),
                 self.sample().replace('</Event>', '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/></Event>')]
        for content in cases:
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.normalize(content)

    def test_doctype_entities_and_processing_instructions_rejected_without_io(self):
        cases = ['<!DOCTYPE Event>' + self.sample(),
                 '<!DOCTYPE Event SYSTEM "file:///etc/passwd">' + self.sample(),
                 '<!DOCTYPE Event [<!ENTITY x SYSTEM "https://example.test/xxe">]>' + self.sample().replace('>demo</Data>', '>&x;</Data>'),
                 '<!DOCTYPE Event [<!ENTITY a "aaaaaaaa"><!ENTITY b "&a;&a;&a;">]>' + self.sample(),
                 '<?xml-stylesheet href="https://example.test/style"?>' + self.sample(),
                 self.sample().replace('</Event>', '<?custom payload?></Event>')]
        with patch('builtins.open', side_effect=AssertionError('No file reads')):
            for content in cases:
                with self.subTest(content=content), self.assertRaises(ValueError):
                    self.normalize(content)

    def test_xml_declaration_utf8_only_and_unicode_content_validation(self):
        self.assertEqual(self.normalize('<?xml version="1.0" encoding="UTF-8"?>' + self.sample())['count'], 1)
        for declaration in ('<?xml version="1.0" encoding="UTF-16"?>', '<?xml version="1.1"?>'):
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                self.normalize(declaration + self.sample())
        with self.assertRaises(ValueError):
            self.normalize(self.sample() + '\ud800')

    def test_invalid_second_event_or_truncated_xml_fails_whole_batch(self):
        for content in ('<Events>' + self.sample() + self.sample().replace('4625', '70000') + '</Events>',
                        '<Events>' + self.sample() + self.sample()[:-5], self.sample() + '<extra/>', '<Events/>'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.normalize(content)

    def test_numeric_metadata_and_timestamp_constraints(self):
        for value in ('-1', '65536', '001', 'true', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.normalize(self.sample().replace('>4625</EventID>', '>' + value + '</EventID>'))
        for value in ('unknown', '2026-02-30T00:00:00Z', '2026-01-01T00:00:00', '2026-01-01T00:00:00.12345678Z'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.normalize(self.sample().replace('2026-01-01T00:00:00.1234567Z', value))
        event = self.normalize(self.sample().replace('<EventID>', '<EventID Qualifiers="1">'))['events'][0]
        self.assertEqual(event['original']['System']['EventIDQualifiers'], 1)

    def test_file_record_attribute_count_and_structure_limits(self):
        for content in (self.sample().replace('>demo</Data>', '>' + 'x' * 8192 + '</Data>'),
                        self.sample().replace('Name="Synthetic"', 'Name="' + 'x' * 8193 + '"'),
                        self.sample() + ' ' * ea.MAX_BYTES,
                        '<Events>' + self.sample() * 1001 + '</Events>',
                        self.sample().replace('</EventData>', ''.join('<Data Name="k' + str(i) + '">x</Data>' for i in range(130)) + '</EventData>')):
            with self.subTest(length=len(content)), self.assertRaises(ValueError):
                self.normalize(content)
        self.assertEqual(self.normalize('<Events>' + self.sample() * 1000 + '</Events>')['count'], 1000)
        with patch.object(ea, 'MAX_XML_ELEMENTS', 2), self.assertRaises(ValueError):
            self.normalize(self.sample())
        with patch.object(ea, 'MAX_XML_DEPTH', 2), self.assertRaises(ValueError):
            self.normalize(self.sample())

    def test_spawned_worker_accepts_xml_and_rejects_entity_inputs(self):
        payload = {'adapter': 'windows-xml', 'content': self.sample()}
        self.assertEqual(worker.analyze('events', json.dumps(payload).encode())['count'], 1)
        payload['content'] = '<!DOCTYPE Event>' + self.sample()
        with self.assertRaises(ValueError):
            worker.analyze('events', json.dumps(payload).encode())


class WindowsXMLPersistenceTests(StoreCase):
    def test_original_bytes_parent_hash_and_bounded_replay_are_preserved(self):
        raw = next(row['example_content'] for row in ea.catalog() if row['id'] == 'windows-xml').encode()
        source = self.evidence(raw, 'synthetic-events.xml')
        normalized = event_ingest.normalize(self.store, self.pid, source['id'], 'windows-xml')
        self.assertEqual(normalized['evidence']['parent_id'], source['id'])
        self.assertEqual(normalized['report']['input_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(event_ingest.verify(self.store, self.pid, normalized['evidence']['id']), normalized['report'])
        self.assertEqual(self.store.read_evidence(self.pid, source['id']), raw)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_invalid_entity_input_does_not_publish_partial_evidence(self):
        raw = b'<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///etc/passwd">]><Event>&x;</Event>'
        source = self.evidence(raw, 'invalid.xml')
        before = self.store.project_data(self.pid)
        with self.assertRaises(Problem):
            event_ingest.normalize(self.store, self.pid, source['id'], 'windows-xml')
        self.assertEqual(self.store.project_data(self.pid), before)
