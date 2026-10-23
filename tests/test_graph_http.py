"""Independent F06 HTTP acceptance: owner boundary, sources and publication."""
import json
import threading
from pathlib import Path
from unittest.mock import patch

from cyber_platform import backup, knowledge_graph
from cyber_platform.server import App, Handler
from cyber_platform.store import Problem, Store
from tests.test_platform import StoreCase
import tests.test_platform as core


class GraphHTTPTests(StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(('127.0.0.1', 0), self.store)
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        self.cookie, self.csrf = '', ''
        self.source = self.evidence(b'private source content must not enter graph summaries')

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join()
        super().tearDown()

    def entity(self, **changes):
        return {'type': 'asset', 'label': 'أصل اصطناعي', 'description': 'وصف موثق',
                'source_evidence': self.source['id'], 'confidence': 80,
                'reference_evidence': None,
                'observed_at': '2026-10-23T10:00:00Z',
                'valid_from': '2026-10-01T00:00:00Z',
                'valid_until': '2026-12-01T00:00:00Z', **changes}

    def post_entity(self, **changes):
        return self.request('/api/graph/entities', {'project_id': self.pid, 'entity': self.entity(**changes)})

    def view(self, pid=None):
        status, _, raw = self.request('/api/graph?project=' + (pid or self.pid))
        self.assertEqual(status, 200, raw)
        return json.loads(raw)

    def test_authentication_precedes_graph_reads_and_writes(self):
        self.assertEqual(self.request('/api/graph?project=' + self.pid)[0], 401)
        self.assertEqual(self.post_entity()[0], 401)
        self.assertEqual(self.request('/api/graph/relations', {'project_id': self.pid, 'relation': {}})[0], 401)
        self.login()
        self.assertEqual(self.view()['entities'], [])

    def test_csrf_origin_and_exact_request_fields(self):
        self.login()
        body = {'project_id': self.pid, 'entity': self.entity()}
        self.assertEqual(self.request('/api/graph/entities', body, {'X-CSRF-Token': 'bad'})[0], 403)
        self.assertEqual(self.request('/api/graph/entities', body, {'Origin': 'https://invalid.test'})[0], 403)
        self.assertEqual(self.request('/api/graph/entities', {**body, 'command': 'ignored?'})[0], 400)
        self.assertEqual(self.request('/api/graph/entities', {'project_id': self.pid})[0], 400)
        for invalid_project in (None, {}, [], True, 12):
            self.assertEqual(self.request('/api/graph/entities', {**body, 'project_id': invalid_project})[0], 400)
        self.assertEqual(self.request('/api/graph/relations', {'project_id': self.pid, 'relation': {}, 'url': 'https://invalid.test'})[0], 400)
        self.assertEqual(self.view()['entities'], [])

    def test_all_six_entity_types_are_persisted_without_source_contents(self):
        self.login()
        kinds = ['asset', 'software', 'vulnerability', 'event', 'evidence', 'experiment']
        for kind in kinds:
            code, _, raw = self.post_entity(type=kind, label='عقدة ' + kind,
                                           reference_evidence=self.source['id'] if kind in ('evidence', 'experiment') else None)
            self.assertIn(code, (200, 201), raw)
        result = self.view()
        self.assertEqual({e['type'] for e in result['entities']}, set(kinds))
        self.assertEqual(len(result['entities']), 6)
        for entity in result['entities']:
            self.assertEqual(entity['confidence'], 80)
            self.assertEqual(entity['source_evidence'], self.source['id'])
            self.assertEqual(entity['observed_at'], '2026-10-23T10:00:00Z')
        self.assertNotIn('private source content', json.dumps(result))
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_project_isolation_applies_to_source_and_graph(self):
        self.login()
        other = self.store.create_project('مشروع آخر')['id']
        body = {'project_id': other, 'entity': self.entity()}
        self.assertEqual(self.request('/api/graph/entities', body)[0], 404)
        self.assertIn(self.post_entity()[0], (200, 201))
        self.assertEqual(self.view(other)['entities'], [])
        self.assertEqual(self.request('/api/graph?project=' + 'f' * 32)[0], 404)

    def test_invalid_types_times_confidence_and_unknown_fields_publish_nothing(self):
        self.login()
        changes = [{'confidence': True}, {'confidence': 101}, {'confidence': -1},
                   {'type': 'execute'}, {'observed_at': None}, {'observed_at': 'tomorrow'},
                   {'valid_from': '2027-01-01T00:00:00Z'}, {'label': ''},
                   {'label': 'x' * 10000}, {'network': True}]
        for change in changes:
            with self.subTest(change=change):
                code, _, raw = self.post_entity(**change)
                self.assertEqual(code, 400, raw)
        self.assertEqual(self.view()['entities'], [])

    def test_changed_original_cannot_be_published_or_displayed_as_verified(self):
        self.login()
        self.assertIn(self.post_entity()[0], (200, 201))
        path = self.store.blobs / self.source['id']
        path.chmod(0o600)
        path.write_bytes(b'changed original')
        self.assertNotEqual(self.request('/api/graph?project=' + self.pid)[0], 200)
        self.assertNotIn(self.post_entity(label='new')[0], (200, 201))

    def test_execution_gate_rejects_busy_graph_operations(self):
        self.login()
        self.app.execution_lock.acquire()
        try:
            self.assertEqual(self.request('/api/graph?project=' + self.pid)[0], 409)
            self.assertEqual(self.post_entity()[0], 409)
            self.assertEqual(self.request('/api/graph/relations', {'project_id': self.pid, 'relation': {}})[0], 409)
        finally:
            self.app.execution_lock.release()

    def test_heavy_slot_is_released_before_graph_response_is_published(self):
        self.login()
        observed = []
        original = Handler.reply

        def checked_reply(handler, *args, **kwargs):
            if handler.path.startswith('/api/graph'):
                observed.append(handler.server.execution_lock.locked())
            return original(handler, *args, **kwargs)

        with patch.object(Handler, 'reply', checked_reply):
            self.assertIn(self.post_entity()[0], (200, 201))
            for _ in range(3):
                self.view()
        self.assertEqual(observed, [False] * 4)

    def test_relations_and_conflicting_assertions_remain_distinct_and_visible(self):
        self.login()
        first = json.loads(self.post_entity()[2])['entity']['id']
        second = json.loads(self.post_entity(type='software', label='برنامج')[2])['entity']['id']
        common = {k: v for k, v in self.entity().items() if k not in ('label', 'type', 'reference_evidence')}
        relation = {**common, 'source': first, 'target': second, 'type': 'supports', 'conflicts_with': None}
        path = '/api/graph/relations'
        code, _, raw = self.request(path, {'project_id': self.pid, 'relation': relation})
        self.assertIn(code, (200, 201), raw)
        previous = json.loads(raw)['relation']['id']
        opposite = {**relation, 'type': 'contradicts', 'confidence': 20, 'conflicts_with': previous}
        code, _, raw = self.request(path, {'project_id': self.pid, 'relation': opposite})
        self.assertIn(code, (200, 201), raw)
        view = self.view()
        self.assertEqual(len(view['relations']), 2)
        self.assertEqual({r['type'] for r in view['relations']}, {'supports', 'contradicts'})
        self.assertTrue(any(previous in c['relations'] for c in view['conflicts']))
        self.assertTrue(all(r['source_evidence'] == self.source['id'] for r in view['relations']))

    def test_relation_cannot_reference_other_project_entity_or_conflict(self):
        self.login()
        first = json.loads(self.post_entity()[2])['entity']['id']
        second = json.loads(self.post_entity(label='ثان')[2])['entity']['id']
        common = {k: v for k, v in self.entity().items() if k not in ('label', 'type', 'reference_evidence')}
        relation = {**common, 'source': first, 'target': second, 'type': 'related_to', 'conflicts_with': None}
        other = self.store.create_project('آخر')['id']
        foreign_source = self.store.add_evidence(other, 'foreign.txt', b'source')
        foreign = {**relation, 'source_evidence': foreign_source['id']}
        self.assertEqual(self.request('/api/graph/relations', {'project_id': other, 'relation': foreign})[0], 404)
        invalid = {**relation, 'conflicts_with': 'f' * 32}
        self.assertEqual(self.request('/api/graph/relations', {'project_id': self.pid, 'relation': invalid})[0], 404)
        self.assertEqual(self.view()['relations'], [])

    def test_actual_evidence_reference_requires_owner_project_and_current_hash(self):
        self.login()
        self.assertEqual(self.post_entity(type='evidence')[0], 400)
        other = self.store.create_project('آخر')['id']
        foreign = self.store.add_evidence(other, 'foreign.txt', b'foreign')
        self.assertEqual(self.post_entity(type='evidence', reference_evidence=foreign['id'])[0], 404)
        reference = self.evidence(b'derived sample', 'reference.txt')
        code, _, raw = self.post_entity(type='evidence', reference_evidence=reference['id'])
        self.assertIn(code, (200, 201), raw)
        entity = json.loads(raw)['entity']
        self.assertEqual(entity['reference_evidence'], reference['id'])
        self.assertEqual(entity['reference_sha256'], reference['sha256'])
        path = self.store.blobs / reference['id']
        path.chmod(0o600)
        path.write_bytes(b'altered reference')
        self.assertNotEqual(self.request('/api/graph?project=' + self.pid)[0], 200)

    def test_mid_publication_source_change_rolls_back_graph_artifact_and_audit(self):
        self.login()
        original = self.store.audit
        before = {p.name for p in self.store.blobs.iterdir()}

        def mutate(action, details):
            original(action, details)
            if action == 'graph-entity.created':
                path = self.store.blobs / self.source['id']
                path.chmod(0o600)
                path.write_bytes(b'changed during publication')

        with patch.object(self.store, 'audit', mutate):
            code, _, _ = self.post_entity()
        self.assertNotIn(code, (200, 201))
        self.assertEqual(self.store.rows("SELECT * FROM evidence WHERE kind='graph-entity'"), [])
        self.assertEqual(self.store.rows("SELECT * FROM audit WHERE action='graph-entity.created'"), [])
        self.assertEqual({p.name for p in self.store.blobs.iterdir()}, before)

    def test_failing_audit_rolls_back_graph_entity_and_source_relation(self):
        self.login()
        before = {p.name for p in self.store.blobs.iterdir()}
        before_relations = self.store.rows('SELECT * FROM relations')
        original = self.store.audit

        def fail(action, details):
            original(action, details)
            if action == 'graph-entity.created':
                raise Problem('synthetic audit failure', 409)

        with patch.object(self.store, 'audit', fail):
            code, _, _ = self.post_entity()
        self.assertEqual(code, 409)
        self.assertEqual(self.store.rows("SELECT * FROM evidence WHERE kind='graph-entity'"), [])
        self.assertEqual(self.store.rows('SELECT * FROM relations'), before_relations)
        self.assertEqual({p.name for p in self.store.blobs.iterdir()}, before)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_encrypted_restore_preserves_full_graph_sources_and_conflicts(self):
        self.login()
        first = json.loads(self.post_entity()[2])['entity']['id']
        second = json.loads(self.post_entity(type='experiment', reference_evidence=self.source['id'])[2])['entity']['id']
        common = {k: v for k, v in self.entity().items() if k not in ('label', 'type', 'reference_evidence')}
        relation = {**common, 'source': first, 'target': second, 'type': 'supports', 'conflicts_with': None}
        knowledge_graph.create_relation(self.store, self.pid, relation)
        knowledge_graph.create_relation(self.store, self.pid, {**relation, 'type': 'contradicts'})
        at = '2026-10-23T10:00:00Z'
        before = knowledge_graph.status(self.store, self.pid, at)
        payload = backup.export(self.store, 'synthetic-graph-restore-123')
        destination = Path(self.temp.name) / 'restored-graph'
        backup.restore(payload, 'synthetic-graph-restore-123', destination)
        restored = Store(destination)
        try:
            self.assertEqual(knowledge_graph.status(restored, self.pid, at), before)
            self.assertEqual(restored.read_evidence(self.pid, self.source['id']),
                             b'private source content must not enter graph summaries')
            self.assertTrue(restored.verify_audit()['valid'])
        finally:
            restored.close()

