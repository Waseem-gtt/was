"""Static coverage must distinguish references, stale evidence and tested support."""
import hashlib
from unittest.mock import patch
from cyber_platform import coverage
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase


class CoverageTests(StoreCase):
    def add_asset(self):
        return coverage.asset(self.store, self.pid, 'خادم خاص', 'host')

    def assessment(self, asset, evidence):
        return coverage.assess(self.store, self.pid, asset['id'], 'تسجيل دخول', 'كشف محاولات', evidence['id'])

    def test_empty_asset_is_explicit_gap_and_regular_evidence_is_unverified(self):
        item = self.add_asset()
        result = coverage.view(self.store, self.pid)
        self.assertEqual(result['assets'][0]['status'], 'untested')
        self.assertEqual(result['gaps'][0]['reason'], 'no_assessment')
        evidence = self.evidence(b'{"passed":true,"status":"protected"}')
        assessment = self.assessment(item, evidence)
        self.assertEqual(assessment['status'], 'unverified')
        result = coverage.view(self.store, self.pid)
        self.assertEqual(result['summary']['supported'], 0)
        self.assertEqual(result['summary']['unverified'], 1)
        self.assertEqual(len(result['edges']), 1)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_persistence_and_remove_preserve_evidence(self):
        item, evidence = self.add_asset(), self.evidence()
        assessment = self.assessment(item, evidence)
        root = self.store.root
        self.store.close()
        self.store = Store(root)
        self.assertEqual(coverage.view(self.store, self.pid)['summary']['assessments'], 1)
        self.assertTrue(coverage.remove(self.store, self.pid, assessment['id'])['evidence_preserved'])
        self.assertEqual(self.store.read_evidence(self.pid, evidence['id']), b'test')
        result = coverage.view(self.store, self.pid)
        self.assertEqual(result['assets'][0]['status'], 'untested')
        with self.assertRaises(Problem):
            coverage.remove(self.store, self.pid, assessment['id'])

    def test_cross_project_reference_and_asset_are_rejected(self):
        item = self.add_asset()
        other = self.store.create_project('other')['id']
        evidence = self.store.add_evidence(other, 'foreign', b'x')
        with self.assertRaises(Problem):
            self.assessment(item, evidence)
        with self.assertRaises(Problem):
            coverage.assess(self.store, other, item['id'], 'threat', 'control', evidence['id'])

    def test_missing_tampered_reference_becomes_stale_without_writes(self):
        item, evidence = self.add_asset(), self.evidence()
        self.assessment(item, evidence)
        before = self.store.setting(coverage.PREFIX + self.pid)
        path = self.store.blobs / evidence['id']
        path.chmod(0o600)
        path.write_bytes(b'evil')
        self.assertEqual(coverage.view(self.store, self.pid)['assessments'][0]['status'], 'stale')
        self.assertEqual(self.store.setting(coverage.PREFIX + self.pid), before)
        path.unlink()
        self.assertEqual(coverage.view(self.store, self.pid)['summary']['stale'], 1)

    def test_validation_caps_and_strict_saved_digest(self):
        for name, kind in [('', 'host'), ('x', 'bad'), ('x\n', 'host'), ('x', []), ('x' * 121, 'host')]:
            with self.assertRaises(Problem):
                coverage.asset(self.store, self.pid, name, kind)
        item = self.add_asset()
        state = self.store.setting(coverage.PREFIX + self.pid)
        state['assets'][0]['name'] = 'changed'
        with self.store.db:
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?', (encode(state), coverage.PREFIX + self.pid))
        with self.assertRaises(Problem):
            coverage.view(self.store, self.pid)
        state.pop('digest')
        state['assets'][0]['created'] = True
        state['digest'] = coverage._digest(state)
        with self.store.db:
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?', (encode(state), coverage.PREFIX + self.pid))
        with self.assertRaises(Problem):
            coverage.view(self.store, self.pid)
        self.assertEqual(item['kind'], 'host')

    def test_asset_and_assessment_caps_are_transactional(self):
        for _ in range(100):
            self.add_asset()
        with self.assertRaises(Problem):
            self.add_asset()
        item = coverage.view(self.store, self.pid)['assets'][0]
        evidence = self.evidence()
        for _ in range(200):
            self.assessment(item, evidence)
        with self.assertRaises(Problem):
            self.assessment(item, evidence)
        self.assertEqual(coverage.view(self.store, self.pid)['summary']['assessments'], 200)

    def test_conflicting_current_tests_and_snapshot_change_are_derived(self):
        item = self.add_asset()
        passing, failing = self.evidence(b'pass'), self.evidence(b'fail')
        original = coverage._reference
        def reference(store, pid, eid):
            result = original(store, pid, eid)
            result['status'] = 'supported' if eid == passing['id'] else 'gap'
            return result
        with patch.object(coverage, '_reference', side_effect=reference):
            a = self.assessment(item, passing)
            self.assessment(item, failing)
            result = coverage.view(self.store, self.pid)
            self.assertEqual(result['assets'][0]['status'], 'conflict')
            self.assertEqual(result['summary']['conflict'], 2)
            coverage.remove(self.store, self.pid, a['id'])
            self.assertEqual(coverage.view(self.store, self.pid)['assets'][0]['status'], 'gap')
        # A saved snapshot must match a fresh independently derived snapshot.
        def changed(store, pid, eid):
            result = original(store, pid, eid)
            result['snapshot']['engine_sha256'] = hashlib.sha256(b'new').hexdigest()
            return result
        with patch.object(coverage, '_reference', side_effect=changed):
            self.assertEqual(coverage.view(self.store, self.pid)['summary']['stale'], 1)

    def test_storage_replacement_and_corrupt_audit_block_operations(self):
        item = self.add_asset()
        evidence = self.evidence()
        with self.store.db:
            self.store.db.execute("UPDATE audit SET hash='bad' WHERE seq=1")
        for operation in [lambda: self.add_asset(), lambda: self.assessment(item, evidence), lambda: coverage.view(self.store, self.pid)]:
            with self.assertRaises(Problem):
                operation()
        self.assertEqual(len(self.store.setting(coverage.PREFIX + self.pid)['assets']), 1)

    def test_verification_budget_never_reports_support(self):
        item, evidence = self.add_asset(), self.evidence()
        self.assessment(item, evidence)
        with patch.object(coverage, 'MAX_VERIFICATION_BYTES', 1):
            result = coverage.view(self.store, self.pid)
        self.assertEqual(result['assessments'][0]['status'], 'unverified')
        self.assertEqual(result['assessments'][0]['reason'], 'verification_budget')

    def test_regular_evidence_kind_change_is_stale(self):
        item, evidence = self.add_asset(), self.evidence()
        self.assessment(item, evidence)
        with self.store.db:
            self.store.db.execute("UPDATE evidence SET kind='another' WHERE id=?", (evidence['id'],))
        self.assertEqual(coverage.view(self.store, self.pid)['summary']['stale'], 1)

    def test_real_detection_replay_conflict_and_source_provenance(self):
        from cyber_platform import detection
        item = self.add_asset()
        reports = []
        for outcome in ('failure', 'success'):
            raw = encode({'schema': 'was.event/1', 'events': [{'action': 'login', 'outcome': outcome}], 'expected_matches': {'was-login-failure': [0]}}).encode()
            original = self.evidence(raw)
            result = detection.test(self.store, self.pid, original['id'], ['was-login-failure'])
            reports.append(result['evidence'])
            self.assessment(item, result['evidence'])
        view = coverage.view(self.store, self.pid)
        self.assertEqual(view['summary']['conflict'], 2)
        with patch('cyber_platform.detection._engine', return_value='0' * 64):
            self.assertEqual(coverage.view(self.store, self.pid)['summary']['stale'], 2)
        source_id = view['assessments'][0]['snapshot']['input_evidence']
        path = self.store.blobs / source_id
        path.chmod(0o600)
        path.write_bytes(b'changed')
        self.assertEqual(coverage.view(self.store, self.pid)['summary']['stale'], 1)
        fake = self.store.add_evidence(self.pid, 'fake.json', b'{"schema":"was.detection-test/1","passed":true}', kind='detection-test')
        with self.assertRaises(Problem):
            self.assessment(item, fake)

    def test_replay_count_is_bounded_and_overflow_is_unverified(self):
        item = self.add_asset()
        for _ in range(4):
            self.assessment(item, self.evidence())
        with self.store.db:
            self.store.db.execute("UPDATE evidence SET kind='detection-test' WHERE project_id=?", (self.pid,))
        # Make snapshots reflect detection records without inventing executable reports.
        state = coverage._load(self.store, self.pid)
        for assessment in state['assessments']:
            assessment['snapshot']['evidence_kind'] = 'detection-test'
        with self.store.db:
            coverage._save(self.store, state, 'test.fixture', {})
        def replay(store, pid, eid):
            assessment = next(a for a in state['assessments'] if a['evidence_id'] == eid)
            return {'status': 'supported', 'snapshot': assessment['snapshot']}
        with patch.object(coverage, '_reference', side_effect=replay) as verified:
            result = coverage.view(self.store, self.pid)
        self.assertEqual(verified.call_count, 3)
        self.assertEqual(result['summary']['supported'], 3)
        self.assertEqual(result['summary']['unverified'], 1)
        self.assertEqual(result['assessments'][-1]['reason'], 'verification_budget')
