"""A verified child must never imply a completed owner-selected section batch."""
import unittest
from cyber_platform import requirements
from scripts.build_requirements import apply_completion_policy


class CompletionPolicyTests(unittest.TestCase):
    def test_verified_services_are_partial_while_their_sections_are_unfinished(self):
        records = {item['id']: item for item in requirements.DATA['requirements'] + requirements.DATA['owner_added_sections']}
        for identifier in ('BASE.13', 'E02', 'F03', 'F04', 'F06'):
            with self.subTest(identifier=identifier):
                record = records[identifier]
                self.assertEqual(record['status'], 'partial')
                self.assertEqual(record['functional_status'], 'verified')
                self.assertTrue(record['open_completion_dependencies'])
                for parent in record['open_completion_dependencies']:
                    self.assertIn(parent, records)
                    self.assertNotEqual(records[parent]['status'], 'available')

    def test_missing_parent_fails_closed_without_losing_function_acceptance(self):
        record = {'id': 'F03', 'status': 'available', 'scope': 'مكتمل: قاموس ومحول مختبر'}
        apply_completion_policy([record])
        self.assertEqual(record['status'], 'partial')
        self.assertEqual(record['functional_status'], 'verified')
        self.assertEqual(record['open_completion_dependencies'], ['SECTION.03'])

    def test_parent_completion_does_not_complete_an_unfinished_child(self):
        parent = {'id': 'SECTION.03', 'status': 'available', 'scope': 'قسم متحقق'}
        child = {'id': 'F03', 'status': 'partial', 'scope': 'قاموس ناقص'}
        apply_completion_policy([parent, child])
        self.assertEqual(child['status'], 'partial')
        self.assertEqual(child['functional_status'], 'partial')
        self.assertEqual(child['open_completion_dependencies'], [])

    def test_verified_function_and_completed_parent_satisfy_both_gates(self):
        parent = {'id': 'SECTION.03', 'status': 'available', 'scope': 'قسم متحقق'}
        child = {'id': 'F03', 'status': 'available', 'scope': 'قاموس ومحول متحققان'}
        apply_completion_policy([parent, child])
        self.assertEqual(child['status'], 'available')
        self.assertEqual(child['functional_status'], 'verified')
        self.assertEqual(child['open_completion_dependencies'], [])
