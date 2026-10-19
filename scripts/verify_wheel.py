"""Exercise an installed wheel using temporary data and a synthetic local model.

Run with the package dependencies installed: python scripts/verify_wheel.py TARGET.
TARGET is the directory populated by pip install --no-deps --target TARGET WHEEL.
No real model inference or owner data is used.
"""
import base64
import hashlib
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
from cyber_platform import release_admin, signed_release
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def verify_signing_fixture(folder):
    """Ephemeral test key only; never configure a real owner trust root."""
    root = Path(folder)
    data = b"synthetic signed artifact"
    (root / "signing-fixture.bin").write_bytes(data)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    identifier = signed_release.key_id(public)
    now = int(time.time())
    payload = {"schema": "was.release/1", "repository": signed_release.REPOSITORY, "sequence": 1,
               "version": "0.8.0", "commit": "e" * 40, "issued_at": now - 1, "expires_at": now + 600,
               "artifacts": [{"name": "signing-fixture.bin", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]}
    trust = {"schema": "was.trust/1", "repository": signed_release.REPOSITORY, "threshold": 1,
             "keys": [{"key_id": identifier, "public_key": base64.b64encode(public).decode()}]}
    envelope = {"signed": payload, "signatures": [{"key_id": identifier,
                "signature": base64.b64encode(key.sign(signed_release.canonical(payload))).decode()}]}
    for name, value in (("fixture-trust.json", trust), ("fixture-envelope.json", envelope)):
        path = root / name
        path.write_bytes(signed_release.canonical(value))
        path.chmod(0o600)
    result = release_admin.run_verify(root / "fixture-envelope.json", root / "fixture-trust.json", "e" * 40,
                                      root / "signature-state", artifacts=root, record=True,
                                      expected_trust_digest=hashlib.sha256(signed_release.canonical(trust)).hexdigest())
    assert result["recorded"] and result["artifacts_verified"] == 1


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
    assert not (PACKAGE_ROOT / "cyber_platform/agents.py").exists(), "Removed agent runtime leaked into wheel"
    assert not (PACKAGE_ROOT / "cyber_platform/agent_roles.py").exists(), "Removed roles leaked into wheel"
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), SyntheticModel)
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()
    try:
        with tempfile.TemporaryDirectory() as folder:
            verify_signing_fixture(folder)
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
                asset = request("/app.js")[0]
                assert b"maintenancePage" in asset and b"function agentsPage" not in asset
                raw, headers = request("/api/setup", {"password": "Synthetic-wheel-password-123", "setup_token": store.setup_token()})
                cookie, csrf = headers["Set-Cookie"].split(";")[0], json.loads(raw)["csrf"]
                project = json.loads(request("/api/projects", {"name": "Synthetic installed wheel"})[0])
                pid = project["id"]
                evidence = store.add_evidence(pid, "synthetic.txt", b"192.0.2.55")
                job = json.loads(request("/api/run", {"project_id": pid, "steps": [{"tool": "ioc", "evidence_id": evidence["id"], "expect": {"ipv4.0": "192.0.2.55"}}]})[0])
                assert job["status"] == "succeeded", job
                report = json.loads(request("/api/maintenance", {"operation": "repair", "section_id": "01"})[0])
                assert report["passed"] and report["repair_transaction"]["verification"], report
                scan = json.loads(request("/api/integrity/start", {"project_id": pid})[0])
                scan = json.loads(request("/api/integrity/advance", {"scan_id": scan["id"]})[0])
                assert scan["passed"] and scan["status"] == "completed", scan
                answer = json.loads(request("/api/chat", {"project_id": pid, "question": "Review the selected synthetic evidence", "evidence_ids": [evidence["id"]]})[0])
                assert isinstance(answer["answer"], str) and len(answer["evidence"]) == 1
                assert store.verify_audit()["valid"]
                print(json.dumps({"version": cyber_platform.__version__, "installed_package": True, "health_and_auth": True,
                                  "bounded_analysis": True, "maintenance": True, "single_chat_fixture": True,
                                  "runtime_agent_team_removed": True, "integrity_batches": True, "signed_release_fixture": True,
                                  "audit": True, "real_model_inference": False}))
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
