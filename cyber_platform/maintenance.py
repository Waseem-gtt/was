"""Owner-triggered bounded checks and conservative repair; no code installation."""
import hashlib
import json
import os
import stat
import time
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
        records = store.rows("SELECT id,project_id,size FROM evidence ORDER BY id")
        verified, bad, examined_bytes = [], [], 0
        started = time.monotonic()
        for record in records:
            if len(verified) + len(bad) >= 500 or examined_bytes + record["size"] > 64 * 1024 * 1024 or time.monotonic() - started > 3:
                break
            examined_bytes += record["size"]
            try:
                store.read_evidence(record["project_id"], record["id"])
                verified.append(record["id"])
            except Problem:
                bad.append(record["id"])
        complete = len(verified) + len(bad) == len(records)
        add("evidence", not bad and complete, {"verified": len(verified), "damaged": bad,
                                               "total": len(records), "complete": complete})
        # Repair only permissions on known regular files after content validation.
        # Do not reconstruct evidence, delete files or rewrite a broken audit chain.
        paths = [(store.root, 0o700, True), (store.blobs, 0o700, True)]
        if database_ok and audit_ok:
            paths.append((store.root / "platform.db", 0o600, False))
        paths.extend((store.blobs / eid, 0o400, False) for eid in verified)
        permissions_bad = []
        for path, mode, directory in paths:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                permissions_bad.append(path.name)
                continue
            try:
                info = os.fstat(fd)
                valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
                if not valid_type:
                    permissions_bad.append(path.name)
                elif stat.S_IMODE(info.st_mode) != mode:
                    if operation == "repair":
                        os.fchmod(fd, mode)
                        repairs.append({"kind": "permissions", "file": path.name, "mode": oct(mode)})
                    else:
                        permissions_bad.append(path.name)
            finally:
                os.close(fd)
        add("permissions", not permissions_bad, {"unresolved": permissions_bad, "checked": len(paths)})

    ids = sorted({t for s in sections for p in s["platforms"] for t in p["tool_ids"]})
    samples = {s["id"]: s["sample"] for s in tools.describe()}
    for tool in ids:
        try:
            sample = samples[tool]
            raw = sample.encode() if sample is not None else (b"\x01\x02AB" if tool == "tlv" else b"\x00\x01\xc0\x00\x00\x00A")
            result = worker.analyze(tool, raw, timeout=3)
            passed = isinstance(result, dict)
            if tool == "hashes":
                passed = result["sha256"] == hashlib.sha256(raw).hexdigest() and result["bytes"] == len(raw)
            if tool == "ioc":
                passed = result["ipv4"] == ["192.0.2.1"]
            add("tool:" + tool, passed, "تشغيل عينة ثابتة ضمن عامل محدود؛ ليس تقييم تغطية التخصص")
        except (ValueError, KeyError, OSError):
            add("tool:" + tool, False, "فشل الاختبار الوظيفي الثابت للأداة")
    report = {"id": uid(), "version": __version__, "created": time.time(), "operation": operation,
              "section_id": section_id, "sections": [{"id": s["id"], "name": s["name"]} for s in sections],
              "checks": checks, "repairs": repairs, "passed": all(c["status"] == "passed" for c in checks),
              "limitation": "فحص محدود للقدرات الموجودة؛ لا يثبت خلو كل النظام من الأخطاء أو الثغرات. الفحص العام للبيانات يشمل جميع المشاريع حتى عند اختيار قسم."}
    with store.lock, store.db:
        store.db.execute("INSERT INTO maintenance_runs VALUES(?,?,?,?,?)",
                         (report["id"], report["created"], operation, section_id, encode(report)))
        store.audit("maintenance." + operation, {"id": report["id"], "passed": report["passed"], "section": section_id})
        store.db.execute("DELETE FROM maintenance_runs WHERE id NOT IN (SELECT id FROM maintenance_runs ORDER BY created DESC LIMIT 50)")
    return report
