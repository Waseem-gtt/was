"""Agent concurrency and evidence provenance without installed model weights."""
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from cyber_platform import agents, local_ai
from cyber_platform.agent_roles import ROLES
from cyber_platform.store import Store, Problem


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "data")
        self.pid = self.store.create_project("فريق")['id']
        self.eid = self.store.add_evidence(self.pid, "owner.txt", b"owner evidence")['id']
        self.gate = threading.Lock()
        self.coordinator = agents.Coordinator(self.store, "http://127.0.0.1:1/v1", "fixture", self.gate)

    def tearDown(self):
        self.coordinator.close()
        self.store.close()
        self.temp.cleanup()

    def wait(self, job):
        self.coordinator.thread.join(10)
        self.assertFalse(self.coordinator.thread.is_alive())
        return self.coordinator.status(self.pid, job['id'])

    def test_forty_roles_overlap_bound_and_report_provenance(self):
        active = peak = 0
        lock = threading.Lock()
        calls = []
        def chat(store, pid, question, evidence_ids, url, model, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                calls.append(kwargs)
            time.sleep(.01)
            with lock:
                active -= 1
            return {'answer': 'review only', 'evidence': [{'id': self.eid}]}
        with patch('cyber_platform.agents.local_ai.chat', side_effect=chat):
            job = self.wait(self.coordinator.start(self.pid, 'سؤال', [self.eid], [r['id'] for r in ROLES]))
        self.assertEqual(peak, 2)
        self.assertEqual(len(calls), 40)
        self.assertTrue(all(c['timeout'] == 20 and c['role_instruction'] for c in calls))
        self.assertEqual(job['status'], 'succeeded')
        report = json.loads(self.store.read_evidence(self.pid, job['report_evidence_id']))
        self.assertFalse(report['execution_authority'])
        self.assertTrue(report['human_review_required'])
        self.assertEqual(report['provenance']['citations'][0]['id'], self.eid)
        self.assertEqual(report['provenance']['citations'][0]['sha256'], self.store.evidence(self.pid, self.eid)['sha256'])
        other = self.store.create_project('other')['id']
        with self.assertRaises(Problem):
            self.coordinator.status(other, job['id'])

    def test_reject_bad_inputs_before_creating_job(self):
        other = self.store.create_project('other')['id']
        bad = self.store.add_evidence(other, 'other.txt', b'private')['id']
        for question, evidence, roles in [('x', [bad], None), ('x', [], []), ('x', [], ['researcher'] * 2), ('x', [], ['unknown']), ('x' * 4001, [], None), (' ' * 4001 + 'x', [], None), ('   ', [], None)]:
            with self.assertRaises(Problem):
                self.coordinator.start(self.pid, question, evidence, roles)
        self.assertEqual(self.store.rows('SELECT * FROM jobs'), [])
        with self.assertRaises(Problem):
            self.coordinator.start([], 'x', [])

    def test_worker_persistence_error_becomes_interrupted_without_running_roles(self):
        save = self.coordinator._save
        counter = 0
        def transient_error(*args):
            nonlocal counter
            counter += 1
            if counter == 1:
                raise OSError('temporary storage failure')
            return save(*args)
        with patch.object(self.coordinator, '_save', side_effect=transient_error):
            job = self.wait(self.coordinator.start(self.pid, 'x', []))
        self.assertEqual(job['status'], 'interrupted')
        self.assertTrue(all(r['status'] == 'cancelled' for r in job['results']))
        self.assertFalse(self.gate.locked())

    def test_partial_worker_start_failure_holds_gate_until_sibling_stops(self):
        model_started = threading.Event()
        release = threading.Event()
        failed_start = threading.Event()
        original_start = threading.Thread.start
        worker_count = 0
        def start(thread):
            nonlocal worker_count
            if getattr(thread, '_target', None).__name__ == 'guarded_work':
                worker_count += 1
                if worker_count == 2:
                    self.assertTrue(model_started.wait(2))
                    failed_start.set()
                    raise RuntimeError('cannot start second worker')
            return original_start(thread)
        def chat(*args, **kwargs):
            model_started.set()
            release.wait(3)
            return {'answer': 'done', 'evidence': []}
        with patch('threading.Thread.start', new=start), patch('cyber_platform.agents.local_ai.chat', side_effect=chat):
            job = self.coordinator.start(self.pid, 'x', [])
            self.assertTrue(failed_start.wait(2))
            self.assertTrue(self.gate.locked())
            self.assertTrue(self.coordinator.thread.is_alive())
            release.set()
            self.coordinator.close()
        job = self.coordinator.status(self.pid, job['id'])
        self.assertEqual(job['status'], 'interrupted')
        self.assertTrue(all(r['status'] in ('succeeded', 'cancelled') for r in job['results']))
        self.assertFalse(self.gate.locked())

    def test_corrupt_evidence_blocked_before_start(self):
        path = self.store.blobs / self.eid
        path.chmod(0o600)
        path.write_bytes(b'changed')
        with self.assertRaises(Problem):
            self.coordinator.start(self.pid, 'x', [self.eid])
        self.assertFalse(self.gate.locked())

    def test_partial_failure_persisted_and_gate_released(self):
        def chat(*args, **kwargs):
            if kwargs['role_instruction'] == ROLES[1]['instructions']:
                raise Problem('unavailable', 503)
            return {'answer': 'ok', 'evidence': []}
        with patch('cyber_platform.agents.local_ai.chat', side_effect=chat):
            job = self.wait(self.coordinator.start(self.pid, 'x', []))
        self.assertEqual(job['status'], 'partial')
        self.assertEqual([r['status'] for r in job['results']], ['succeeded', 'failed', 'succeeded'])
        self.assertFalse(self.gate.locked())
        again = agents.Coordinator(self.store, 'http://127.0.0.1:1/v1', 'fixture', self.gate)
        self.assertEqual(again.status(self.pid, job['id'])['status'], 'partial')
        again.close()

    def test_missing_model_fails_visibly(self):
        with patch('cyber_platform.agents.local_ai.chat', side_effect=Problem('missing', 503)):
            job = self.wait(self.coordinator.start(self.pid, 'x', []))
        self.assertEqual(job['status'], 'failed')
        self.assertTrue(all('answer' not in r and r['error'] for r in job['results']))

    def test_shutdown_cancels_queued_roles_and_rejects_new(self):
        started = threading.Event()
        release = threading.Event()
        def chat(*args, **kwargs):
            started.set()
            release.wait(2)
            return {'answer': 'done', 'evidence': []}
        with patch('cyber_platform.agents.local_ai.chat', side_effect=chat):
            job = self.coordinator.start(self.pid, 'x', [], [r['id'] for r in ROLES])
            self.assertTrue(started.wait(2))
            with self.assertRaises(Problem) as error:
                self.coordinator.start(self.pid, 'busy', [])
            self.assertEqual(error.exception.status, 409)
            self.coordinator.cancel.set()
            release.set()
            self.coordinator.close()
        job = self.coordinator.status(self.pid, job['id'])
        self.assertEqual(job['status'], 'interrupted')
        self.assertGreaterEqual(sum(r['status'] == 'cancelled' for r in job['results']), 38)
        self.assertFalse(self.gate.locked())
        with self.assertRaises(Problem):
            self.coordinator.start(self.pid, 'closed', [])

    def test_model_loopback_http_malformed_and_total_deadline(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                received.append(payload)
                content = payload['messages'][1]['content']
                if 'slow' in content:
                    self.send_response(200)
                    self.end_headers()
                    for _ in range(30):
                        try:
                            self.wfile.write(b' ')
                            self.wfile.flush()
                        except OSError:
                            break
                        time.sleep(.1)
                    return
                body = b'{"choices":null}' if 'malformed' in content else b'{"choices":[{"message":{"content":"fixture review"}}]}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}/v1'
        try:
            response = local_ai.chat(self.store, self.pid, 'review', [self.eid], url, 'fixture', timeout=2, role_instruction='role')
            self.assertEqual(response['answer'], 'fixture review')
            self.assertIn('role', received[0]['messages'][0]['content'])
            self.assertIn('owner evidence', received[0]['messages'][1]['content'])
            for question in ('malformed', 'slow'):
                start = time.monotonic()
                with self.assertRaises(Problem) as error:
                    local_ai.chat(self.store, self.pid, question, [], url, 'fixture', timeout=1)
                self.assertEqual(error.exception.status, 503)
                self.assertLess(time.monotonic() - start, 2)
            with self.assertRaises(Problem):
                local_ai.chat(self.store, self.pid, 'x', [], 'http://example.com', 'fixture')
            for timeout in (0, 91, True, float('nan')):
                with self.assertRaises(Problem):
                    local_ai.chat(self.store, self.pid, 'x', [], url, 'fixture', timeout=timeout)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
