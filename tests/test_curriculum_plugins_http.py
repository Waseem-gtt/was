"""Owner boundaries and end-to-end persisted curriculum/plugin governance."""
import json
import threading
from pathlib import Path
import tests.test_platform as core
from cyber_platform import backup, curriculum, plugin_registry
from cyber_platform.server import App
from cyber_platform.store import Store, encode


class CurriculumPluginsHTTPTests(core.StoreCase):
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

    def post(self, path, value):
        code, _, raw = self.request('/api/' + path, value)
        self.assertEqual(code, 200, (path, raw))
        return json.loads(raw)

    def bodies(self):
        return [('/api/curriculum/attempt', {'project_id': self.pid, 'path_id': 'foundations', 'lesson_id': 'lesson.04', 'answer_index': 0}),
                ('/api/plugins/register', {'project_id': self.pid, 'evidence_id': 'a' * 32}),
                ('/api/plugins/transition', {'project_id': self.pid, 'plugin_id': 'fixture', 'action': 'approve', 'reason': 'Reviewed synthetic fixture'})]

    def test_reads_and_writes_require_owner(self):
        for path in ('curriculum', 'curriculum/progress', 'curriculum/history', 'plugins'):
            self.assertEqual(self.request('/api/' + path + '?project=' + self.pid)[0], 401)
        for path, body in self.bodies():
            self.assertEqual(self.request(path, body)[0], 401)

    def test_csrf_exact_fields_shared_slot_and_static_assets(self):
        self.login()
        for path, body in self.bodies():
            self.assertEqual(self.request(path, body, {'X-CSRF-Token': 'bad'})[0], 403)
            self.assertEqual(self.request(path, {**body, 'command': 'forbidden'})[0], 400)
        with self.app.execution_lock:
            for path, body in self.bodies():
                self.assertEqual(self.request(path, body)[0], 409)
            for path in ('curriculum/progress', 'curriculum/history', 'plugins'):
                self.assertEqual(self.request('/api/' + path + '?project=' + self.pid)[0], 409)
            self.assertEqual(self.request('/api/curriculum')[0], 200)
        for path in ('/curriculum.js', '/plugins.js'):
            code, headers, raw = self.request(path)
            self.assertEqual(code, 200)
            self.assertIn('javascript', headers['Content-Type'])
            self.assertTrue(raw)

    def first_pass(self):
        catalog = json.loads(self.request('/api/curriculum')[2])
        path = catalog['paths'][0]
        lesson = next(l for l in catalog['lessons'] if l['id'] == path['lesson_ids'][0])
        result = self.post('curriculum/attempt', {'project_id': self.pid, 'path_id': path['id'], 'lesson_id': lesson['id'], 'answer_index': lesson['choices'].index(lesson['defense'])})
        self.assertTrue(result['result']['correct'])
        return result

    def manifest(self):
        return {'id': 'owner.fixture', 'version': '1.0.0', 'license': 'MIT', 'source': 'https://example.test/fixture', 'permissions': ['selected_evidence.read']}

    def registered(self):
        source = self.evidence(encode(self.manifest()).encode(), 'synthetic-plugin.json')
        return self.post('plugins/register', {'project_id': self.pid, 'evidence_id': source['id']})

    def test_learning_progress_and_plugin_decisions_via_real_http(self):
        self.login()
        self.first_pass()
        progress = json.loads(self.request('/api/curriculum/progress?project=' + self.pid)[2])
        self.assertEqual(progress['paths'][0]['lessons'][0]['status'], 'passed')
        self.assertEqual(progress['paths'][0]['lessons'][1]['status'], 'available')
        self.assertEqual(len(json.loads(self.request('/api/curriculum/history?project=' + self.pid)[2])['attempts']), 1)
        value = self.registered()
        self.assertEqual(value['item']['state'], 'pending')
        approved = self.post('plugins/transition', {'project_id': self.pid, 'plugin_id': 'owner.fixture', 'action': 'approve', 'reason': 'Synthetic metadata checked'})
        self.assertEqual(approved['item']['state'], 'approved')
        disabled = self.post('plugins/transition', {'project_id': self.pid, 'plugin_id': 'owner.fixture', 'action': 'disable', 'reason': 'Synthetic review paused'})
        self.assertEqual(disabled['item']['state'], 'disabled')
        self.assertEqual(len(disabled['item']['history']), 3)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_cross_project_and_invalid_targets_fail_without_execution(self):
        self.login()
        source = self.evidence(encode(self.manifest()).encode())
        other = self.store.create_project('Other')['id']
        self.assertEqual(self.request('/api/plugins/register', {'project_id': other, 'evidence_id': source['id']})[0], 404)
        invalid = {'project_id': self.pid, 'path_id': 'foundations', 'lesson_id': 'lesson.04', 'answer_index': True}
        self.assertEqual(self.request('/api/curriculum/attempt', invalid)[0], 400)
        self.assertEqual(json.loads(self.request('/api/plugins?project=' + other)[2])['items'], [])
        invalid['lesson_id'] = 'https://example.test'
        self.assertEqual(self.request('/api/curriculum/attempt', invalid)[0], 400)

    def test_response_slot_is_released_before_next_request(self):
        self.login()
        for _ in range(3):
            self.first_pass()
            self.assertEqual(self.request('/api/plugins?project=' + self.pid)[0], 200)

    def test_encrypted_restore_preserves_progress_and_plugin_review_chain(self):
        self.login()
        self.first_pass()
        self.registered()
        self.post('plugins/transition', {'project_id': self.pid, 'plugin_id': 'owner.fixture', 'action': 'approve', 'reason': 'Restore fixture approval'})
        before_progress = curriculum.progress(self.store, self.pid)
        before_plugins = plugin_registry.view(self.store, self.pid)
        password = 'Temporary-curriculum-backup-123'
        payload = backup.export(self.store, password)
        destination = Path(self.temp.name) / 'restored-curriculum-plugins'
        backup.restore(payload, password, destination)
        restored = Store(destination)
        try:
            self.assertEqual(curriculum.progress(restored, self.pid), before_progress)
            self.assertEqual(plugin_registry.view(restored, self.pid), before_plugins)
            self.assertTrue(restored.verify_audit()['valid'])
        finally:
            restored.close()
