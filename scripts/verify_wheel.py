"""Exercise an installed wheel using temporary data and a synthetic local model.

Run with the package dependencies installed: python scripts/verify_wheel.py TARGET.
TARGET is the directory populated by pip install --no-deps --target TARGET WHEEL.
No real model inference or owner data is used.
"""
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PACKAGE_ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(PACKAGE_ROOT))
import cyber_platform
from cyber_platform.server import App
from cyber_platform.store import Store


class SyntheticModel(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path == "/v1/chat/completions"
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert payload["model"] == "installed-wheel-fixture"
        body = json.dumps({"choices": [{"message": {"content": "Synthetic wheel review; human verification required."}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    assert Path(cyber_platform.__file__).resolve().is_relative_to(PACKAGE_ROOT), "Imported checkout instead of installed wheel"
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), SyntheticModel)
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()
    try:
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder)
            app = App(("127.0.0.1", 0), store, f"http://127.0.0.1:{fixture.server_port}/v1", "installed-wheel-fixture")
            thread = threading.Thread(target=app.serve_forever, daemon=True)
            thread.start()
            cookie, csrf = "", ""

            def request(path, body=None):
                connection = http.client.HTTPConnection("127.0.0.1", app.server_port, timeout=10)
                connection.request("GET" if body is None else "POST", path,
                                   None if body is None else json.dumps(body),
                                   {"Content-Type": "application/json", "Cookie": cookie, "X-CSRF-Token": csrf})
                response = connection.getresponse()
                raw, headers, status = response.read(), dict(response.getheaders()), response.status
                connection.close()
                assert status in (200, 201), (path, status)
                return raw, headers

            try:
                assert json.loads(request("/healthz")[0])["database"]
                assert b"agentsPage" in request("/app.js")[0]
                raw, headers = request("/api/setup", {"password": "Synthetic-wheel-password-123", "setup_token": store.setup_token()})
                cookie, csrf = headers["Set-Cookie"].split(";")[0], json.loads(raw)["csrf"]
                project = json.loads(request("/api/projects", {"name": "Synthetic installed wheel"})[0])
                pid = project["id"]
                evidence = store.add_evidence(pid, "synthetic.txt", b"192.0.2.55")
                job = json.loads(request("/api/run", {"project_id": pid, "steps": [{"tool": "ioc", "evidence_id": evidence["id"], "expect": {"ipv4.0": "192.0.2.55"}}]})[0])
                assert job["status"] == "succeeded", job
                report = json.loads(request("/api/maintenance", {"operation": "repair", "section_id": "01"})[0])
                assert report["passed"] and report["repair_transaction"]["verification"], report
                assert len(json.loads(request("/api/agents/roles")[0])["roles"]) == 40
                job = json.loads(request("/api/agents/start", {"project_id": pid, "question": "Review the selected synthetic evidence", "evidence_ids": [evidence["id"]]})[0])
                deadline = time.monotonic() + 10
                while job["status"] in ("queued", "running") and time.monotonic() < deadline:
                    time.sleep(.01)
                    job = json.loads(request(f"/api/agents?project={pid}&job={job['id']}")[0])
                assert job["status"] == "succeeded" and len(job["results"]) == 3, job
                artifact = json.loads(request(f"/api/evidence?project={pid}&id={job['report_evidence_id']}")[0])
                assert artifact["execution_authority"] is False
                assert store.verify_audit()["valid"]
                print(json.dumps({"version": cyber_platform.__version__, "installed_package": True, "health_and_auth": True,
                                  "bounded_analysis": True, "maintenance": True, "agents_fixture": True,
                                  "agent_report": True, "audit": True, "real_model_inference": False}))
            finally:
                app.shutdown()
                app.server_close()
                thread.join()
                store.close()
    finally:
        fixture.shutdown()
        fixture.server_close()
        fixture_thread.join()


if __name__ == "__main__":
    main()
