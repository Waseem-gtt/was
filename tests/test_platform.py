import base64
import hashlib
import http.client
import io
import json
import os
import struct
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cyber_platform import backup, engine, local_ai, sandbox, tools
from cyber_platform.server import App, CATALOG
from cyber_platform.store import Problem, Store, encode


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "data")
        self.project = self.store.create_project("مختبر", "ملفات اصطناعية")
        self.pid = self.project["id"]

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def evidence(self, data=b"test", name="sample.txt"):
        return self.store.add_evidence(self.pid, name, data)


class StorageTests(StoreCase):
    def test_password_salted_and_verified(self):
        self.store.initialize("long-password-123")
        self.assertTrue(self.store.check_password("long-password-123"))
        self.assertFalse(self.store.check_password("wrong"))
        self.assertNotIn("long-password-123", encode(self.store.setting("owner")))
        with self.assertRaises(Problem):
            self.store.initialize("second-password-123")

    def test_evidence_persistence(self):
        evidence = self.evidence("دليل عربي".encode())
        self.assertEqual(self.store.read_evidence(self.pid, evidence["id"]), "دليل عربي".encode())
        self.assertEqual(evidence["sha256"], hashlib.sha256("دليل عربي".encode()).hexdigest())
        other = Store(self.store.root)
        try:
            self.assertEqual(other.read_evidence(self.pid, evidence["id"]), "دليل عربي".encode())
        finally:
            other.close()

    def test_cross_project_rejected(self):
        e = self.evidence()
        other = self.store.create_project("other")
        with self.assertRaises(Problem):
            self.store.read_evidence(other["id"], e["id"])
        with self.assertRaises(Problem):
            engine.run(self.store, other["id"], [{"tool": "hashes", "evidence_id": e["id"]}])

    def test_tampered_original_blocks_analysis(self):
        e = self.evidence()
        path = self.store.blobs / e["id"]
        path.chmod(0o600)
        path.write_bytes(b"changed")
        job = engine.run(self.store, self.pid, [{"tool": "hashes", "evidence_id": e["id"]}])
        self.assertEqual(job["status"], "failed")
        self.assertIn("بصمة", job["results"][0]["error"])

    def test_symlink_evidence_rejected(self):
        e = self.evidence()
        path = self.store.blobs / e["id"]
        path.unlink()
        path.symlink_to("/etc/hostname")
        with self.assertRaises(Problem):
            self.store.read_evidence(self.pid, e["id"])

    def test_filename_traversal_and_quota(self):
        with self.assertRaises(Problem):
            self.evidence(name="../../escape")
        self.store.quota = 2
        with self.assertRaises(Problem):
            self.evidence(b"large")
        self.assertEqual(self.store.rows("SELECT * FROM evidence"), [])

    def test_audit_detects_mutation(self):
        self.evidence()
        self.assertTrue(self.store.verify_audit()["valid"])
        with self.store.db:
            self.store.db.execute("UPDATE audit SET action='tampered' WHERE seq=1")
        self.assertFalse(self.store.verify_audit()["valid"])


class WorkflowTests(StoreCase):
    def test_acceptance_and_provenance(self):
        e = self.evidence(b"192.0.2.4")
        job = engine.run(self.store, self.pid, [{"tool": "ioc", "evidence_id": e["id"], "expect": {"ipv4.0": "192.0.2.4"}},
                                                {"tool": "hashes", "from_step": 0}])
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["executed"], 2)
        self.assertEqual(job["results"][0]["output"]["acceptance"], "passed")
        self.assertEqual(job["results"][1]["output"]["acceptance"], "not_evaluated")
        self.assertEqual(len(self.store.project_data(self.pid)["relations"]), 2)
        self.assertEqual(self.store.read_evidence(self.pid, e["id"]), b"192.0.2.4")

    def test_failed_acceptance_stops_and_preserves_result(self):
        e = self.evidence()
        job = engine.run(self.store, self.pid, [{"tool": "hashes", "evidence_id": e["id"], "expect": {"bytes": 999}},
                                                {"tool": "hashes", "from_step": 0}])
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["executed"], 1)
        output_id = job["results"][0]["evidence_id"]
        self.assertEqual(json.loads(self.store.read_evidence(self.pid, output_id))["acceptance"], "failed")

    def test_invalid_tools_and_forward_references(self):
        e = self.evidence()
        for spec in [[{"tool": "shell", "evidence_id": e["id"]}], [{"tool": "hashes", "from_step": 1}],
                     [{"tool": "hashes", "evidence_id": e["id"], "command": "id"}]]:
            with self.assertRaises(Problem):
                engine.run(self.store, self.pid, spec)

    def test_malformed_input_fails_with_record(self):
        e = self.evidence(b"not json")
        job = engine.run(self.store, self.pid, [{"tool": "events", "evidence_id": e["id"]}])
        self.assertEqual(job["status"], "failed")
        self.assertEqual(self.store.project_data(self.pid)["jobs"][0]["status"], "failed")

    def test_wrong_json_shape_is_a_recorded_failure(self):
        e = self.evidence(b'[17]')
        job = engine.run(self.store, self.pid, [{"tool": "events", "evidence_id": e["id"]}])
        self.assertEqual(job["status"], "failed")
        self.assertEqual(self.store.project_data(self.pid)["jobs"][0]["status"], "failed")


class AnalyzerTests(unittest.TestCase):
    def test_catalog_exact_hierarchy(self):
        self.assertEqual(len(CATALOG), 20)
        platforms = [p for s in CATALOG for p in s["platforms"]]
        self.assertEqual(len(platforms), 69)
        labs = [l for p in platforms for l in p["labs"]]
        self.assertEqual(len(labs) + sum(len(l["children"]) for l in labs), 207)
        ids = [s["id"] for s in CATALOG] + [p["id"] for p in platforms] + [l["id"] for l in labs] + [c["id"] for l in labs for c in l["children"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ioc_validation(self):
        self.assertEqual(tools.analyze("ioc", b"192.0.2.1 999.0.0.1")["ipv4"], ["192.0.2.1"])

    def test_http_headers(self):
        self.assertEqual(len(tools.analyze("http", b'{"headers":{}}')["missing_headers"]), 3)

    def test_events_preserve_original(self):
        e = {"user": "lab", "outcome": "failure", "extra": "original"}
        output = tools.analyze("events", json.dumps([e]).encode())
        self.assertEqual(output["events"][0]["original"], e)
        self.assertEqual(output["failed"], 1)

    def test_known_hash(self):
        self.assertEqual(tools.analyze("hashes", b"abc")["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_elf_and_invalid_pe(self):
        data = b"\x7fELF\x02\x01" + b"\0" * 12 + struct.pack("<H", 62)
        self.assertEqual(tools.analyze("executable", data)["machine"], 62)
        with self.assertRaises(ValueError):
            tools.analyze("executable", b"MZ" + b"\0" * 100)

    def test_flow_totals(self):
        output = tools.analyze("flows", b"protocol,destination,bytes\nTLS,192.0.2.1,512\nDNS,192.0.2.2,64")
        self.assertEqual(output["bytes"], 576)
        self.assertEqual(output["protocols"], {"TLS": 1, "DNS": 1})

    def test_identity(self):
        self.assertTrue(tools.analyze("identity", b'[{"name":"test","active":false}]')["review"][0]["stale"])

    def test_container(self):
        self.assertEqual(tools.analyze("container", b'{"user":"1000","read_only":true}')["count"], 0)

    def test_sbom_formats(self):
        for value in [{"bomFormat": "CycloneDX", "components": [{"name": "test", "version": "1.0"}]},
                      {"spdxVersion": "SPDX-2.3", "packages": [{"name": "test", "versionInfo": "1.0"}]}]:
            output = tools.analyze("sbom", json.dumps(value).encode())
            self.assertEqual(output["components"][0]["version"], "1.0")

    def test_tlv_bounds(self):
        self.assertEqual(tools.analyze("tlv", b"\x01\x02AB")["count"], 1)
        with self.assertRaises(ValueError):
            tools.analyze("tlv", b"\x01\xffAB")

    def test_crypto_inventory(self):
        self.assertIn("Ed25519", tools.analyze("crypto", b"TLSv1.3 Ed25519")["algorithms"])

    def test_firmware_entropy(self):
        self.assertEqual(tools.analyze("firmware", bytes(range(256)))["entropy_bits_per_byte"], 8.0)
        self.assertEqual(tools.analyze("firmware", b"xxhsqs")["signatures"]["SquashFS-le"], 2)

    def test_thermal_model(self):
        output = tools.analyze("twin", b'{"steps":60,"target":35}')
        self.assertEqual(len(output["trace"]), 60)
        self.assertGreater(output["final"], 20)
        self.assertLess(output["final"], 35)

    def test_spectrum_known_sinusoid(self):
        self.assertEqual(tools.analyze("spectrum", b"[0,1,0,-1,0,1,0,-1]")["peak_bin"], 2)

    def test_telemetry_wrap_and_gap(self):
        output = tools.analyze("telemetry", b"sequence,value\n255,1\n0,2\n2,3")
        self.assertEqual(len(output["gaps"]), 1)

    def test_can_frame(self):
        output = tools.analyze("can", b"(1.0) vcan0 123#AABB\ninvalid")
        self.assertEqual(output["frames"][0]["id"], 0x123)
        self.assertEqual(output["invalid_lines"], [2])

    def test_ccsds_bounds(self):
        self.assertEqual(tools.analyze("ccsds", struct.pack(">HHH", 1, 2, 0) + b"A")["packets"][0]["bytes"], 7)
        with self.assertRaises(ValueError):
            tools.analyze("ccsds", b"\0" * 6)

    def test_ai_citation_does_not_invent_support(self):
        value = {"excerpts": {"e1": "known reference"}, "claims": [{"source": "e1", "quote": "not present"}]}
        self.assertEqual(tools.analyze("ai-audit", json.dumps(value).encode())["unsupported"], 1)

    def test_privacy_keeps_input_unchanged(self):
        data = b"owner@example.test Bearer SOME_SECRET_TOKEN"
        output = tools.analyze("privacy", data)
        self.assertNotIn("owner@example.test", output["redacted"])
        self.assertIn(b"SOME_SECRET_TOKEN", data)

    def test_manifest_not_activated(self):
        output = tools.analyze("manifest", b'{"id":"example"}')
        self.assertFalse(output["activated"])
        self.assertIn("license", output["missing"])

    def test_oversized_analysis_rejected(self):
        with self.assertRaises(ValueError):
            tools.analyze("hashes", b"x" * (4 * 1024 * 1024 + 1))


class BackupTests(StoreCase):
    def test_encrypted_roundtrip_and_tamper(self):
        e = self.evidence(b"private evidence")
        payload = backup.export(self.store, "backup-password-123")
        self.assertNotIn(b"private evidence", payload)
        destination = Path(self.temp.name) / "restored"
        backup.restore(payload, "backup-password-123", destination)
        other = Store(destination)
        try:
            self.assertEqual(other.read_evidence(self.pid, e["id"]), b"private evidence")
            self.assertTrue(other.verify_audit()["valid"])
        finally:
            other.close()
        for damaged, password in [(payload[:-1] + bytes([payload[-1] ^ 1]), "backup-password-123"), (payload, "incorrect-password")]:
            with self.assertRaises(Problem):
                backup.restore(damaged, password, Path(self.temp.name) / "invalid")
            self.assertFalse((Path(self.temp.name) / "invalid").exists())
        with self.assertRaises(Problem):
            backup.restore(payload, "backup-password-123", destination)

    def test_authenticated_zip_traversal_rejected(self):
        files = {"platform.db": b"not-db", "../../escape": b"bad"}
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
            archive.writestr("manifest.json", encode({n: hashlib.sha256(d).hexdigest() for n, d in files.items()}))
        salt, nonce = os.urandom(16), os.urandom(12)
        header = backup.MAGIC + salt + nonce
        payload = header + AESGCM(backup.key("backup-password-123", salt)).encrypt(nonce, stream.getvalue(), header)
        with self.assertRaises(Problem):
            backup.restore(payload, "backup-password-123", Path(self.temp.name) / "invalid")


class HTTPTests(StoreCase):
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

    def request(self, path, data=None, extra=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.app.server_port, timeout=10)
        headers = {"Content-Type": "application/json", "Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        headers.update(extra or {})
        connection.request("POST" if data is not None else "GET", path, None if data is None else json.dumps(data), headers)
        response = connection.getresponse()
        payload = response.read()
        result = (response.status, dict(response.getheaders()), payload)
        connection.close()
        return result

    def login(self):
        status, headers, body = self.request("/api/setup", {"password": "http-password-123"})
        self.assertEqual(status, 200)
        self.cookie = headers["Set-Cookie"].split(";")[0]
        self.csrf = json.loads(body)["csrf"]

    def test_auth_csrf_and_origin(self):
        self.assertEqual(self.request("/api/bootstrap")[0], 401)
        self.login()
        self.assertEqual(self.request("/api/bootstrap")[0], 200)
        self.assertEqual(self.request("/api/projects", {"name": "x"}, {"X-CSRF-Token": "bad"})[0], 403)
        self.assertEqual(self.request("/api/projects", {"name": "x"}, {"Origin": "https://evil.test"})[0], 403)
        self.assertEqual(self.request("/api/bootstrap", extra={"Host": "evil.test"})[0], 403)
        self.assertEqual(self.request("/api/logout", {})[0], 200)
        self.assertEqual(self.request("/api/bootstrap")[0], 401)

    def test_full_upload_analyze_download_flow(self):
        self.login()
        status, _, body = self.request("/api/upload", {"project_id": self.pid, "name": "example.txt", "base64": base64.b64encode(b"192.0.2.8").decode()})
        self.assertEqual(status, 201)
        eid = json.loads(body)["id"]
        status, _, body = self.request("/api/run", {"project_id": self.pid, "steps": [{"tool": "ioc", "evidence_id": eid, "expect": {"ipv4.0": "192.0.2.8"}}]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "succeeded")
        status, headers, body = self.request(f"/api/evidence?project={self.pid}&id={eid}")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"192.0.2.8")
        self.assertEqual(headers["X-Evidence-SHA256"], hashlib.sha256(body).hexdigest())

    def test_all_twenty_tools_through_http(self):
        self.login()
        for tool in tools.describe():
            with self.subTest(tool=tool["id"]):
                data = tool["sample"].encode() if tool["sample"] is not None else (
                    b'\x01\x02AB' if tool["id"] == 'tlv' else struct.pack('>HHH', 1, 2, 0) + b'A')
                e = self.evidence(data, tool["id"] + '.sample')
                status, _, body = self.request('/api/run', {'project_id': self.pid, 'steps': [{'tool': tool['id'], 'evidence_id': e['id']}]})
                self.assertEqual(status, 200)
                job = json.loads(body)
                self.assertEqual(job['status'], 'succeeded')
                output = self.store.read_evidence(self.pid, job['results'][0]['evidence_id'])
                self.assertEqual(json.loads(output)['input_sha256'], hashlib.sha256(data).hexdigest())

    def test_bad_input_and_security_headers(self):
        self.login()
        self.assertEqual(self.request("/api/upload", {"project_id": self.pid, "name": "test", "base64": "!invalid!"})[0], 400)
        status, headers, _ = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_report_redacts_owner_metadata(self):
        self.login()
        p = self.store.create_project("owner@example.test")
        _, _, body = self.request("/api/report?project=" + p["id"])
        self.assertNotIn(b"owner@example.test", body)

    def test_remote_ai_url_rejected(self):
        for url in ("https://example.test/v1", "http://169.254.169.254/v1", "http://localhost/v1", "http://127.0.0.1.evil.test/v1"):
            with self.assertRaises(Problem):
                local_ai.chat(self.store, self.pid, "test", [], url, "test")


class SandboxTests(unittest.TestCase):
    def test_fail_closed_or_verified_isolation(self):
        code = 'import os,socket\nassert not os.path.exists("/workspace/was")\nassert not os.path.exists("/home/agent")\nprint("isolated")\n'
        try:
            output = sandbox.run(code)
        except Problem as exc:
            self.assertEqual(exc.status, 503)
            self.assertIn("عزل", str(exc))
            return  # This validates rejection; it does not claim successful isolation.
        self.assertEqual(output["exit_code"], 0)
        self.assertEqual(output["stdout"].strip(), "isolated")


if __name__ == "__main__":
    unittest.main()
