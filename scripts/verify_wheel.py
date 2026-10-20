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
               "version": cyber_platform.__version__, "commit": "e" * 40, "issued_at": now - 1, "expires_at": now + 600,
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
                quality_run = json.loads(request("/api/quality/start", {})[0])
                while quality_run["status"] in ("pending", "running"):
                    quality_run = json.loads(request("/api/quality/advance", {"run_id": quality_run["id"]})[0])
                assert quality_run["passed"] and quality_run["counts"]["completed"] == quality_run["counts"]["total"], quality_run
                compared = json.loads(request("/api/quality/compare", {"left_id": quality_run["id"], "right_id": quality_run["id"]})[0])
                assert not compared["regressions"] and not compared["improvements"]
                adapters = json.loads(request("/api/events/adapters")[0])["adapters"]
                assert len(adapters) == 3
                sample = next(a for a in adapters if a["id"] == "windows-json")
                original_events = store.add_evidence(pid, "synthetic-windows.json", sample["example_content"].encode())
                normalized = json.loads(request("/api/events/normalize", {"project_id":pid, "evidence_id":original_events["id"], "adapter":sample["id"]})[0])
                assert normalized["report"]["input_sha256"] == original_events["sha256"]
                library = json.loads(request("/api/detection/library?project=" + pid)[0])
                original_fixture = store.add_evidence(pid, "synthetic-detection.json", json.dumps(library["fixtures"][0]["input"]).encode())
                tested = json.loads(request("/api/detection/test", {"project_id":pid, "evidence_id":original_fixture["id"], "rule_ids":[r["id"] for r in library["rules"]]})[0])
                assert tested["report"]["passed"] and tested["report"]["evaluated_rules"] == 8
                asset = json.loads(request("/api/coverage/asset", {"project_id":pid, "name":"Synthetic wheel service", "kind":"service"})[0])
                assessed = json.loads(request("/api/coverage/assessment", {"project_id":pid, "asset_id":asset["id"], "threat":"Synthetic threat", "control":"Synthetic detection", "evidence_id":tested["evidence"]["id"]})[0])
                assert assessed["status"] == "supported"
                coverage = json.loads(request("/api/coverage?project=" + pid)[0])
                assert coverage["summary"]["supported"] == 1 and coverage["edges"]
                templates = json.loads(request("/api/plans/templates?project=" + pid)[0])
                assert len(templates["templates"]) == 8
                template_fixture = templates["fixtures"][0]
                bindings = {slot:store.add_evidence(pid, "synthetic-plan-" + slot + ".txt", content.encode())["id"] for slot,content in template_fixture["inputs"].items()}
                bound = json.loads(request("/api/plans/templates/instantiate", {"project_id":pid, "template_id":template_fixture["template_id"], "bindings":bindings})[0])
                run = json.loads(request("/api/plans/start", {"project_id":pid, "plan":bound["plan"], "instantiation_id":bound["evidence"]["id"]})[0])
                assert run["template_origin"]["evidence_id"] == bound["evidence"]["id"]
                for _ in range(20):
                    if run["status"] in ("completed", "failed"): break
                    run = json.loads(request("/api/plans/advance", {"project_id":pid, "run_id":run["id"]})[0])
                assert run["passed"] and run["status"] == "completed",run
                full_scan = json.loads(request("/api/coverage/scans/start", {"project_id":pid})[0])
                for _ in range(30):
                    if full_scan["status"] in ("completed", "failed"): break
                    full_scan = json.loads(request("/api/coverage/scans/advance", {"project_id":pid, "scan_id":full_scan["id"]})[0])
                assert full_scan["complete"] and full_scan["current_validity"] == "snapshot_only",full_scan
                project_report = json.loads(request("/api/case-reports/build", {"project_id":pid, "title":"Synthetic installed report", "evidence_ids":[original_fixture["id"]], "plan_run_ids":[run["id"]], "coverage_scan_id":full_scan["id"]})[0])
                assert json.loads(request("/api/case-reports/verify", {"project_id":pid, "report_id":project_report["evidence"]["id"]})[0])["passed"]
                html_report = request("/api/case-reports?project=" + pid + "&id=" + project_report["evidence"]["id"] + "&format=html")[0]
                assert b"<script" not in html_report.lower() and b"Content-Security-Policy" in html_report
                curriculum = json.loads(request("/api/curriculum")[0])
                assert len(curriculum["paths"]) == 5 and len(curriculum["lessons"]) == 20
                learning_path = curriculum["paths"][0]
                lesson = next(l for l in curriculum["lessons"] if l["id"] == learning_path["lesson_ids"][0])
                assessed = json.loads(request("/api/curriculum/attempt", {"project_id":pid, "path_id":learning_path["id"], "lesson_id":lesson["id"], "answer_index":lesson["choices"].index(lesson["defense"])})[0])
                assert assessed["result"]["correct"] and assessed["progress"]["counts"]["passed"] == 1
                plugin_manifest = {"id":"wheel.fixture", "version":"1.0.0", "license":"MIT", "source":"https://example.test/wheel-fixture", "permissions":["selected_evidence.read"]}
                plugin_source = store.add_evidence(pid, "synthetic-plugin.json", json.dumps(plugin_manifest).encode())
                registered = json.loads(request("/api/plugins/register", {"project_id":pid, "evidence_id":plugin_source["id"]})[0])
                assert registered["item"]["state"] == "pending"
                approved = json.loads(request("/api/plugins/transition", {"project_id":pid, "plugin_id":"wheel.fixture", "action":"approve", "reason":"Synthetic wheel review fixture"})[0])
                assert approved["item"]["state"] == "approved"
                registry = json.loads(request("/api/plugins?project=" + pid)[0])
                assert len(registry["items"]) == 1 and len(registry["items"][0]["history"]) == 2
                answer = json.loads(request("/api/chat", {"project_id": pid, "question": "Review the selected synthetic evidence", "evidence_ids": [evidence["id"]]})[0])
                assert isinstance(answer["answer"], str) and len(answer["evidence"]) == 1
                assert store.verify_audit()["valid"]
                print(json.dumps({"version": cyber_platform.__version__, "installed_package": True, "health_and_auth": True,
                                  "bounded_analysis": True, "maintenance": True, "single_chat_fixture": True,
                                  "runtime_agent_team_removed": True, "integrity_batches": True, "signed_release_fixture": True,
                                  "quality_center": True, "event_adapters": True, "detection_library": True, "defense_coverage": True, "branching_plans": True, "immutable_template_origin": True, "full_coverage_scan": True, "project_reports_json_html": True, "curriculum_progress": True, "plugin_metadata_governance": True, "plugin_code_execution": False, "audit": True, "real_model_inference": False}))
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
