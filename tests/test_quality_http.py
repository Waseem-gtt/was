"""Owner-only fixed quality suite API; no supplied code, paths or fixtures."""
import json
import threading
from unittest.mock import patch
import tests.test_platform as core
from cyber_platform.server import App


class QualityHTTPTests(core.StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(('127.0.0.1', 0), self.store)
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        self.cookie, self.csrf = '', ''

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join()
        super().tearDown()

    def test_all_quality_routes_require_owner_and_mutations_require_csrf(self):
        for path in ('/api/quality/catalog', '/api/quality/history', '/api/quality?run=' + 'a' * 32):
            self.assertEqual(self.request(path)[0], 401)
        for path, body in (('start', {}), ('advance', {'run_id': 'a' * 32}),
                           ('compare', {'left_id': 'a' * 32, 'right_id': 'b' * 32})):
            self.assertEqual(self.request('/api/quality/' + path, body)[0], 401)
        self.login()
        for path, body in (('start', {}), ('advance', {'run_id': 'a' * 32}),
                           ('compare', {'left_id': 'a' * 32, 'right_id': 'b' * 32})):
            self.assertEqual(self.request('/api/quality/' + path, body, {'X-CSRF-Token': 'bad'})[0], 403)

    def test_supplied_cases_paths_and_execution_options_rejected(self):
        self.login()
        for path, body in (('start', {'cases': []}), ('start', {'path': '/tmp/input'}),
                           ('advance', {'run_id': 'a' * 32, 'max_cases': 100}),
                           ('advance', {}), ('compare', {'left_id': 'a' * 32, 'right_id': 'b' * 32, 'tool': 'ioc'})):
            self.assertEqual(self.request('/api/quality/' + path, body)[0], 400)
        self.assertEqual(json.loads(self.request('/api/quality/history')[2])['runs'], [])

    def test_quality_competes_for_existing_heavy_operation_slot(self):
        self.login()
        with self.app.execution_lock:
            for path, body in (('start', {}), ('advance', {'run_id': 'a' * 32}),
                               ('compare', {'left_id': 'a' * 32, 'right_id': 'b' * 32})):
                self.assertEqual(self.request('/api/quality/' + path, body)[0], 409)
            self.assertEqual(self.request('/api/quality/catalog')[0], 200)

    def test_fixed_suite_progress_history_and_no_owner_evidence_reads(self):
        self.login()
        cases = json.loads(self.request('/api/quality/catalog')[2])['cases']
        self.assertEqual(len({case['tool'] for case in cases}), 36)
        with patch.object(self.store, 'read_evidence', side_effect=AssertionError('owner evidence accessed')):
            code, _, raw = self.request('/api/quality/start', {})
            self.assertEqual(code, 200)
            run = json.loads(raw)
            self.assertFalse(run['passed'])
            code, _, raw = self.request('/api/quality/advance', {'run_id': run['id']})
            self.assertEqual(code, 200)
            advanced = json.loads(raw)
        self.assertGreater(advanced['counts']['completed'], 0)
        self.assertLessEqual(advanced['counts']['completed'], 3)
        self.assertEqual(json.loads(self.request('/api/quality?run=' + run['id'])[2]), advanced)
        history = json.loads(self.request('/api/quality/history')[2])['runs']
        self.assertEqual(history[0]['id'], run['id'])
        self.assertEqual(self.request('/api/quality/compare', {'left_id': run['id'], 'right_id': run['id']})[0], 409)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_bad_identifiers_and_missing_runs(self):
        self.login()
        for bad in ([], {}, True, '../secret', ''):
            self.assertEqual(self.request('/api/quality/advance', {'run_id': bad})[0], 400)
        self.assertEqual(self.request('/api/quality?run=' + 'a' * 32)[0], 404)
