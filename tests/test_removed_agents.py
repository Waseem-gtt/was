"""Removed agent APIs stay unavailable; historical jobs remain inert."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import tests.test_platform as core
from cyber_platform import local_ai
from cyber_platform.server import App
from cyber_platform.store import Problem, encode, uid


class RemovedAgentsHTTPTests(core.StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        self.cookie, self.csrf = "", ""

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join()
        super().tearDown()

    def test_removed_endpoints_are_404_without_model_requests(self):
        self.login()
        with patch("cyber_platform.local_ai.chat") as model:
            for path in ("/api/agents/roles", "/api/agents", "/api/agents?project=" + self.pid):
                self.assertEqual(self.request(path)[0], 404)
            self.assertEqual(self.request("/api/agents/start", {"project_id": self.pid, "question": "review", "evidence_ids": []})[0], 404)
            model.assert_not_called()
        self.assertFalse(hasattr(self.app, "agents"))

    def test_historical_jobs_remain_inert_preserved_and_unresumable(self):
        identifiers = []
        with self.store.lock, self.store.db:
            for status in ("queued", "running", "succeeded", "failed"):
                identifier = uid()
                identifiers.append((identifier, status))
                self.store.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)", (
                    identifier, self.pid, "historical agent job", status,
                    encode({"schema": "was.agents/1", "roles": ["researcher"]}),
                    encode([{"role_id": "researcher", "status": "queued"}]), time.time()))
        with patch("cyber_platform.local_ai.chat") as model:
            recovered = App(("127.0.0.1", 0), self.store)
            try:
                self.login()
                for identifier, status in identifiers:
                    stored = self.store.rows("SELECT * FROM jobs WHERE id=?", (identifier,))[0]
                    self.assertEqual(stored["status"], "interrupted" if status in ("queued", "running") else status)
                    self.assertEqual(json.loads(stored["spec"])["schema"], "was.agents/1")
                    self.assertEqual(json.loads(stored["results"]), [{"role_id": "researcher", "status": "queued"}])
                    response = self.request("/api/workflows/resume", {"project_id": self.pid, "source_job_id": identifier, "steps": []})
                    self.assertEqual(response[0], 409)
                self.assertEqual(len(self.store.project_data(self.pid)["jobs"]), 4)
                model.assert_not_called()
            finally:
                recovered.server_close()

    def test_single_local_assistant_remains_available(self):
        self.login()
        with patch("cyber_platform.local_ai.chat", return_value={"answer": "fixture", "evidence": []}) as model:
            response = self.request("/api/chat", {"project_id": self.pid, "question": "review", "evidence_ids": []})
            self.assertEqual(response[0], 200)
            self.assertEqual(json.loads(response[2])["answer"], "fixture")
            model.assert_called_once()


class LocalModelDeadlineTests(core.StoreCase):
    def setUp(self):
        super().setUp()
        self.eid = self.evidence(b"owner evidence")["id"]

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
            response = local_ai.chat(self.store, self.pid, 'review', [self.eid], url, 'fixture', timeout=2)
            self.assertEqual(response['answer'], 'fixture review')
            self.assertIn('لا أدوات تنفيذ لديك', received[0]['messages'][0]['content'])
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
