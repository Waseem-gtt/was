"""Owner-triggered bounded checks and conservative repair; no code installation."""
import hashlib
import json
import os
import sqlite3
import stat
import time
from contextlib import ExitStack
from pathlib import Path
from . import __version__, tools, worker
from .store import Problem, encode, uid

CATALOG = json.loads((Path(__file__).parent / "catalog.json").read_text())


def scope(section_id):
    if section_id is None:
        return CATALOG
    if not isinstance(section_id, str):
        raise Problem("معرف القسم غير صالح")
    selected = [s for s in CATALOG if s["id"] == section_id]
    if not selected:
        raise Problem("القسم غير موجود", 404)
    return selected


def history(store):
    return {"runs": [{**r, "report": json.loads(r["report"])} for r in store.rows(
                "SELECT * FROM maintenance_runs ORDER BY created DESC LIMIT 10")],
            "tasks": store.rows("SELECT * FROM development_tasks ORDER BY updated DESC LIMIT 100"),
            "version": __version__, "code_upgrade": "linux_verified_release_command"}


def task(store, body):
    if set(body) == {"section_id", "title"}:
        scope(body["section_id"])
        if body["section_id"] is None:
            raise Problem("اختر قسمًا لطلب التطوير")
        title = body["title"]
        if not isinstance(title, str) or not 3 <= len(title.strip()) <= 300 or any(ord(c) < 32 for c in title):
            raise Problem("طلب التطوير يحتاج عنوانًا بين3 و300حرف")
        identifier, now = uid(), time.time()
        with store.lock, store.db:
            if store.db.execute("SELECT count(*) FROM development_tasks").fetchone()[0] >= 1000:
                raise Problem("بلغت طلبات التطوير حد1000طلب", 409)
            store.db.execute("INSERT INTO development_tasks VALUES(?,?,?,?,?,?)",
                             (identifier, now, now, body["section_id"], title.strip(), "open"))
            store.audit("development.created", {"id": identifier, "section": body["section_id"]})
    elif set(body) == {"id", "status"}:
        if body["status"] not in ("open", "in_progress", "done") or not isinstance(body["id"], str):
            raise Problem("حالة الطلب غير صالحة")
        identifier = body["id"]
        with store.lock, store.db:
            if not store.db.execute("SELECT 1 FROM development_tasks WHERE id=?", (identifier,)).fetchone():
                raise Problem("طلب التطوير غير موجود", 404)
            store.db.execute("UPDATE development_tasks SET status=?,updated=? WHERE id=?",
                             (body["status"], time.time(), identifier))
            store.audit("development.updated", {"id": identifier, "status": body["status"]})
    else:
        raise Problem("حقول طلب التطوير غير صالحة")
    return {"id": identifier, "tasks": history(store)["tasks"]}


# Reviewed outcomes for fixed synthetic samples, independent of analyzer execution.
_TOOL_EXPECTATIONS = {
    "har": {"schema":"was.har-analysis/1", "entry_count":1, "network":False, "content_exported":False,
            "findings":[{"entry":0,"code":"missing_csp"}]},
    "har-diff": {"schema":"was.har-diff/1", "complete":True, "normalized_metadata_equal":False,
                 "changed_entries":[{"index":0,"fields":["status"]}]},
    "email": {"schema":"was.email-analysis/1", "part_count":3, "attachment_count":1,
              "network":False, "content_exported":False},
    "kubernetes": {"schema":"was.kubernetes-review/1", "resource_count":2, "container_count":1,
                   "network":False, "applied":False, "summary":{"findings":12,"high":2,"medium":10}},
    "kubernetes-diff": {"schema":"was.kubernetes-diff/1", "complete":True, "normalized_review_equal":False,
                        "changed_resources":[{"id":"apps/v1/Deployment/demo/synthetic-web","fields":["configuration_sha256"]}]},
    "systemd": {"schema":"was.systemd-review/1", "network":False, "applied":False,
                "summary":{"findings":15,"high":1,"medium":14}},
    "sarif": {"schema":"was.sarif-analysis/1", "finding_count":1, "network":False, "snippets_exported":False,
              "summary":{"warning":1,"error":0,"note":0,"none":0}},
    "sarif-diff": {"schema":"was.sarif-diff/1", "complete":True, "normalized_findings_equal":False,
                   "counts":{"added":0,"resolved":0,"unchanged":0,"severity_changed":1}},
    "archive": {"schema":"was.archive-review/1", "member_count":1, "network":False, "extracted":False,
                "content_exported":False, "crc_verified":False,
                "summary":{"declared_expanded_bytes":33,"stored_bytes":33,"encrypted_members":0,"links":0}},
    "ssh-keys": {"schema":"was.ssh-key-review/1", "key_count":1, "network":False, "authenticated":False,
                 "keys":[{"type":"Ed25519","bits":256,"option_names":["restrict"]}]},
    "dns": {"schema":"was.dns-analysis/1", "question_count":1, "record_count":1,
            "network":False, "dnssec_verified":False},
    "supply-chain-diff": {"schema":"was.supply-chain-diff/1", "complete":True, "normalized_inventory_equal":False,
                          "added_components":[], "removed_components":[], "changed_components":[{"id":"library", "fields":["version"]}]},
    "pcap": {"schema":"was.pcap-analysis/1", "packet_count":1, "protocols":{"UDP":1}, "payload_exported":False, "live_capture":False,
             "flows":[{"source":"192.0.2.1", "destination":"198.51.100.2", "source_port":53000, "destination_port":53, "protocol":"UDP", "packets":1}]},
    "certificate": {"schema":"was.certificate-analysis/1", "certificate_count":1, "trust":"not_evaluated", "network":False,
                    "certificates":[{"time_status":"within_validity_period", "self_signature":"valid", "key":{"type":"EC", "bits":256}}]},
    "supply-chain": {"schema":"was.supply-chain/1", "format":"CycloneDX-1.6", "component_count":2, "network":False,
                     "dependencies":[{"source":"app", "target":"library"}], "issues":[], "summary":{"missing_versions":0, "missing_licenses":0, "missing_hashes":0}},
    "ioc": {"ipv4": ["192.0.2.1"], "urls": ["https://example.test/path"], "sha256": [], "source_bytes": 50},
    "http": {"missing_headers": ["content-security-policy", "referrer-policy"], "status": 200},
    "events": {"schema": "was.event/1", "count": 1, "failed": 1,
               "events": [{"actor": "lab", "action": "login", "outcome": "failure",
                           "original": {"user": "lab", "action": "login", "outcome": "failure"}}]},
    "hashes": {"sha256": "17a05404605a3886f457bc4f73099617301c87f817ee673a3aafb77800c84e4f", "bytes": 25,
               "sha512": "ef80a35b62e7a2db998dd5aa589d1f3e0cb3bf7fc7a0170101063a3deca8e5f653982817c2750412d492cfe098d43fc13ead8ad0addf422941c4418c20efe4f5"},
    "executable": {"format": "unknown", "strings": ["Static analysis sample, never executed"], "executed": False},
    "flows": {"flows": 2, "bytes": 576, "protocols": {"TLS": 1, "DNS": 1},
              "destinations": {"192.0.2.1": 1, "192.0.2.2": 1}},
    "identity": {"review": [{"name": "lab-admin", "admin": True, "stale": False, "mfa_missing": True}]},
    "container": {"findings": ["privileged", "root_user", "host_network", "writable_root"], "count": 4},
    "sbom": {"format": "CycloneDX", "count": 1,
             "components": [{"name": "example", "version": "1.0", "licenses": [{"license": {"id": "MIT"}}]}]},
    "tlv": {"records": [{"type": 1, "length": 2, "hex": "4142"}], "count": 1},
    "crypto": {"algorithms": ["AES", "Ed25519", "ML-KEM", "TLSv1.3"], "private_key_markers": 0},
    "firmware": {"bytes": 23, "entropy_bits_per_byte": 3.49706, "signatures": {"SquashFS-le": 19}},
    "twin": {"final": 32.973},
    "spectrum": {"power": [0.0, 0.0, 2.0, 0.0, 0.0], "peak_bin": 2, "normalized_frequency": 0.25},
    "telemetry": {"records": 3, "gaps": [{"row": 3, "previous": 2, "current": 4}]},
    "can": {"count": 2, "invalid_lines": [], "frames": [{"id": 291, "data": "01020304", "length": 4},
                                                        {"id": 292, "data": "AABB", "length": 2}]},
    "ccsds": {"count": 1, "packets": [{"version": 0, "apid": 1, "sequence": 0, "bytes": 7}]},
    "ai-audit": {"unsupported": 0, "claims": [{"claim": "Result is 42", "source": "e1", "quote_present": True}]},
    "privacy": {"redacted": "Contact [REDACTED:email]; [REDACTED:bearer]",
                "matches": {"email": 1, "bearer": 1, "private_key": 0}},
    "manifest": {"missing": [], "valid_structure": True, "permissions": ["selected_evidence.read"], "activated": False},
    "rules": {"schema": "was.rules/1", "event_count": 2, "evaluated_rules": 1,
              "rules": [{"id": "failed-login", "matched_event_indexes": [0],
                         "metrics": {"true_positive": 1, "false_positive": 0, "false_negative": 0,
                                     "true_negative": 1, "passed": True}}]},
}


def _tool_selfcheck(tool, result, raw):
    """Require known semantic results, never count an arbitrary dict as success."""
    def matches(actual, expected):
        if type(actual) is not type(expected):
            return False
        if isinstance(expected, dict):
            return all(key in actual and matches(actual[key], value) for key, value in expected.items())
        if isinstance(expected, list):
            return len(actual) == len(expected) and all(matches(a, e) for a, e in zip(actual, expected))
        return actual == expected

    expected = _TOOL_EXPECTATIONS.get(tool)
    if expected is None or not matches(result, expected):
        return False
    if tool == "hashes" and (len(raw) != 25 or hashlib.sha256(raw).hexdigest() != expected["sha256"]):
        return False
    if tool == "twin":
        trace = result.get("trace")
        return isinstance(trace, list) and len(trace) == 60 and matches(trace[0], {"step": 0, "temperature": 20.8, "power": 1}) and matches(trace[-1], {"step": 59, "temperature": 32.973, "power": 0.405})
    return True


class _UnsafeRepair(Exception):
    pass


def _permission_transaction(store, operation, records, healthy):
    """Pin verified objects until commit/rollback; never repair paths after reopening."""
    transaction = {"status": "not_needed", "planned": [], "applied": [],
                   "verification": False, "rollback_errors": [], "errors": []}
    verified, bad, unresolved = [], [], []
    complete, consumed = True, 0
    deadline = time.monotonic() + 3
    entries, changed = [], []

    def identity(info):
        return info.st_dev, info.st_ino

    def limited():
        if time.monotonic() > deadline:
            raise _UnsafeRepair("time_limit")

    def validate(entry, content=False):
        nonlocal consumed
        limited()
        info = os.fstat(entry["fd"])
        current = os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)
        if identity(info) != identity(current):
            raise _UnsafeRepair("path_replaced:" + entry["label"])
        if entry["directory"]:
            if not stat.S_ISDIR(info.st_mode):
                raise _UnsafeRepair("not_directory:" + entry["label"])
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise _UnsafeRepair("unsafe_file:" + entry["label"])
        record = entry.get("record")
        if record and content:
            if info.st_size != record["size"] or not 0 <= info.st_size <= 16 * 1024 * 1024:
                raise _UnsafeRepair("evidence_size:" + entry["label"])
            digest = hashlib.sha256()
            os.lseek(entry["fd"], 0, os.SEEK_SET)
            remaining = info.st_size
            while remaining:
                limited()
                available = 64 * 1024 * 1024 - consumed
                if available <= 0:
                    raise _UnsafeRepair("byte_limit")
                chunk = os.read(entry["fd"], min(65536, remaining, available))
                consumed += len(chunk)
                if not chunk:
                    raise _UnsafeRepair("evidence_short_read:" + entry["label"])
                remaining -= len(chunk)
                digest.update(chunk)
            after = os.fstat(entry["fd"])
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or digest.hexdigest() != record["sha256"]:
                raise _UnsafeRepair("evidence_integrity:" + entry["label"])

    with ExitStack() as stack:
        def opened(name, parent=None, directory=False, record=None, mode=0o600, label=None):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory:
                flags |= os.O_DIRECTORY
            fd = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            entry = {"fd": fd, "name": name, "parent": parent, "directory": directory,
                     "mode": mode, "before": stat.S_IMODE(os.fstat(fd).st_mode),
                     "label": label or str(name), "record": record}
            entries.append(entry)
            validate(entry, content=True)
            return entry

        try:
            root = opened(str(store.root), directory=True, mode=0o700, label=store.root.name)
            blobs = opened("evidence", root["fd"], directory=True, mode=0o700)
            opened("platform.db", root["fd"])
            baseline = getattr(store, "storage_identity", {})
            for key, entry in zip(("root", "evidence", "platform.db"), entries):
                if key in baseline and identity(os.fstat(entry["fd"])) != tuple(baseline[key]):
                    raise _UnsafeRepair("storage_replaced:" + key)
            for record in records:
                if len(verified) + len(bad) >= 500 or consumed + record["size"] > 64 * 1024 * 1024 or time.monotonic() > deadline:
                    complete = False
                    break
                if not isinstance(record["id"], str) or len(record["id"]) != 32 or any(c not in "0123456789abcdef" for c in record["id"]):
                    bad.append(record["id"])
                    continue
                try:
                    opened(record["id"], blobs["fd"], record=record, mode=0o400)
                    verified.append(record["id"])
                except (OSError, _UnsafeRepair) as error:
                    if isinstance(error, _UnsafeRepair) and str(error) in ("time_limit", "byte_limit"):
                        complete = False
                        break
                    bad.append(record["id"])
            for entry in entries:
                if entry["before"] != entry["mode"]:
                    transaction["planned"].append({"file": entry["label"], "before": oct(entry["before"]), "after": oct(entry["mode"])})
                    unresolved.append(entry["label"])
            if not healthy or bad or not complete:
                raise _UnsafeRepair("preflight_failed")
            # Validate every pathname against the pinned inode before any mutation.
            for entry in entries:
                validate(entry)
            if operation == "repair":
                for entry in entries:
                    if entry["before"] != entry["mode"]:
                        for anchor in entries[:3]:
                            validate(anchor)
                        validate(entry, content=True)
                        changed.append(entry)
                        os.fchmod(entry["fd"], entry["mode"])
                        transaction["applied"].append({"file": entry["label"], "before": oct(entry["before"]), "after": oct(entry["mode"]), "verified": stat.S_IMODE(os.fstat(entry["fd"]).st_mode) == entry["mode"]})
                for entry in entries:
                    validate(entry, content=True)
                    if stat.S_IMODE(os.fstat(entry["fd"]).st_mode) != entry["mode"]:
                        raise _UnsafeRepair("mode_verification:" + entry["label"])
                transaction["status"] = "applied" if changed else "not_needed"
                unresolved = []
                transaction["verification"] = True
            else:
                transaction["verification"] = not unresolved
        except (OSError, _UnsafeRepair) as error:
            transaction["errors"].append(str(error) if isinstance(error, _UnsafeRepair) else "filesystem_error")
            if isinstance(error, _UnsafeRepair):
                candidate = str(error).partition(":")[2]
                if candidate in verified:
                    verified.remove(candidate)
                    bad.append(candidate)
                if str(error) in ("time_limit", "byte_limit"):
                    complete = False
            complete = complete and len(verified) + len(bad) == len(records)
            for entry in reversed(changed):
                try:
                    os.fchmod(entry["fd"], entry["before"])
                    if stat.S_IMODE(os.fstat(entry["fd"]).st_mode) != entry["before"]:
                        raise _UnsafeRepair("rollback_mode")
                except (OSError, _UnsafeRepair):
                    transaction["rollback_errors"].append(entry["label"])
            transaction["status"] = ("rollback_failed" if transaction["rollback_errors"] else "rolled_back") if changed else "blocked"
            unresolved = sorted(set(unresolved + [entry["label"] for entry in changed]))
        transaction["storage_valid"] = len(entries) >= 3
        try:
            baseline = getattr(store, "storage_identity", {})
            for key, entry in zip(("root", "evidence", "platform.db"), entries[:3]):
                info = os.fstat(entry["fd"])
                path_info = os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)
                if identity(info) != identity(path_info) or (key in baseline and identity(info) != tuple(baseline[key])):
                    transaction["storage_valid"] = False
        except OSError:
            transaction["storage_valid"] = False
    repairs = [{"kind": "permissions", "file": entry["label"], "mode": oct(entry["mode"])} for entry in changed] if transaction["status"] == "applied" else []
    return transaction, repairs, {"verified": len(verified), "damaged": bad, "total": len(records),
                                  "complete": complete, "bytes_read": consumed,
                                  "limits": {"files": 500, "bytes_read": 64 * 1024 * 1024, "seconds": 3}}, unresolved, len(entries)


def check(store, operation="check", section_id=None):
    sections = scope(section_id)
    if operation not in ("check", "repair"):
        raise Problem("عملية الصيانة غير مسجلة")
    checks, repairs = [], []

    def add(identifier, passed, detail):
        checks.append({"id": identifier, "status": "passed" if passed else "failed", "detail": detail})

    with store.lock:
        database_ok = store.rows("PRAGMA quick_check(1)")[0]["quick_check"] == "ok"
        foreign_ok = not store.rows("PRAGMA foreign_key_check")
        audit_ok = store.verify_audit()["valid"]
        add("database", database_ok and foreign_ok, "فحص SQLite والمفاتيح المرجعية")
        add("audit", audit_ok, "تحقق سلسلة التدقيق المحلية")
        records = store.rows("SELECT id,project_id,size,sha256 FROM evidence ORDER BY id")
        transaction, repairs, evidence_detail, permissions_bad, checked = _permission_transaction(
            store, operation, records, database_ok and foreign_ok and audit_ok)
        add("evidence", not evidence_detail["damaged"] and evidence_detail["complete"], evidence_detail)
        add("permissions", transaction["verification"], {"unresolved": permissions_bad, "checked": checked})

    ids = sorted({t for s in sections for p in s["platforms"] for t in p["tool_ids"]})
    samples = {s["id"]: s["sample"] for s in tools.describe()}
    for tool in ids:
        try:
            sample = samples[tool]
            raw = sample.encode() if sample is not None else (b"\x01\x02AB" if tool == "tlv" else b"\x00\x01\xc0\x00\x00\x00A")
            result = worker.analyze(tool, raw, timeout=3)
            passed = _tool_selfcheck(tool, result, raw)
            add("tool:" + tool, passed, "تشغيل عينة ثابتة ضمن عامل محدود؛ ليس تقييم تغطية التخصص")
        except (ValueError, KeyError, OSError):
            add("tool:" + tool, False, "فشل الاختبار الوظيفي الثابت للأداة")
    report = {"id": uid(), "version": __version__, "created": time.time(), "operation": operation,
              "section_id": section_id, "sections": [{"id": s["id"], "name": s["name"]} for s in sections],
              "checks": checks, "repairs": repairs, "repair_transaction": transaction, "passed": all(c["status"] == "passed" for c in checks),
              "limitation": "فحص محدود للقدرات الموجودة؛ لا يثبت خلو كل النظام من الأخطاء أو الثغرات. الفحص العام للبيانات يشمل جميع المشاريع حتى عند اختيار قسم."}
    if not transaction["storage_valid"]:
        report["persistence"] = {"status": "blocked", "reason": "storage_identity_unverified"}
        report["passed"] = False
        return report
    report["persistence"] = {"status": "saved"}
    try:
        with store.lock, store.db:
            store.db.execute("INSERT INTO maintenance_runs VALUES(?,?,?,?,?)",
                             (report["id"], report["created"], operation, section_id, encode(report)))
            if audit_ok:
                store.audit("maintenance." + operation, {"id": report["id"], "passed": report["passed"], "section": section_id})
            store.db.execute("DELETE FROM maintenance_runs WHERE id NOT IN (SELECT id FROM maintenance_runs ORDER BY created DESC LIMIT 50)")
    except sqlite3.Error:
        report["persistence"] = {"status": "failed", "reason": "database_unavailable"}
        report["passed"] = False
    return report
