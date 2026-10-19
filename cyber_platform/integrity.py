"""Resumable, read-only integrity checks of a fixed metadata snapshot."""
import hashlib
import os
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from .store import Problem, encode, uid

PREFIX = "integrity_scan:"
MAX_RECORDS = 10000
MAX_SCANS = 20
MAX_FILE = 16 * 1024 * 1024
MAX_BYTES = 64 * 1024 * 1024


def _manifest(store, project_id):
    query = "SELECT id,project_id,sha256,size FROM evidence"
    args = ()
    if project_id is not None:
        query += " WHERE project_id=?"
        args = (project_id,)
    rows = store.rows(query + " ORDER BY id LIMIT 10001", args)
    if len(rows) > MAX_RECORDS:
        raise Problem("نطاق الفحص يتجاوز10000دليل؛ اختر مشروعًا أصغر", 413)
    return rows


def _public(scan):
    return {k: v for k, v in scan.items() if k != "manifest"}


def _load(store, scan_id):
    if not isinstance(scan_id, str) or not re.fullmatch(r"[a-f0-9]{32}", scan_id):
        raise Problem("معرف الفحص غير صالح", 404)
    scan = store.setting(PREFIX + scan_id)
    if scan is None:
        raise Problem("الفحص غير موجود", 404)
    if not isinstance(scan, dict):
        raise Problem("حالة الفحص المخزنة غير صالحة", 409)
    manifest = scan.get("manifest")
    counters = [scan.get(k) for k in ("total", "cursor", "scanned", "verified", "failed")]
    if not isinstance(manifest, list) or len(manifest) > MAX_RECORDS or any(type(n) is not int or not 0 <= n <= MAX_RECORDS for n in counters):
        raise Problem("حالة فحص الأدلة المخزنة غير صالحة", 409)
    if len(manifest) != scan["total"] or scan["cursor"] != scan["scanned"] or scan["verified"] + scan["failed"] != scan["cursor"] or scan["cursor"] > scan["total"] or hashlib.sha256(encode(manifest).encode()).hexdigest() != scan.get("manifest_sha256"):
        raise Problem("بصمة لقطة الفحص أو عداداتها غير سليمة", 409)
    if any(not isinstance(r, dict) or set(r) != {"id", "project_id", "sha256", "size"} for r in manifest):
        raise Problem("حقول لقطة الأدلة غير صالحة", 409)
    if scan.get("status") not in ("pending", "running", "completed", "failed") or type(scan.get("passed")) is not bool or type(scan.get("scope_changed")) is not bool:
        raise Problem("حالة الفحص غير صالحة", 409)
    if scan["passed"] != (scan["status"] == "completed") or scan["passed"] and (scan["cursor"] != scan["total"] or scan["failed"] or scan["scope_changed"]):
        raise Problem("نتيجة الفحص المخزنة غير متسقة", 409)
    return scan


def _audit_guard(store):
    if not store.verify_audit()["valid"]:
        raise Problem("سلسلة التدقيق غير سليمة؛ أوقف الفحص دون تغيير الأدلة", 409)


def _save(store, scan, action):
    scan["updated"] = time.time()
    with _directories(store) as (_, validate):
        validate()
        scan["persistence"] = "saved"
        store.db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (PREFIX + scan["id"], encode(scan)))
        store.audit(action, {"id": scan["id"], "cursor": scan["cursor"], "status": scan["status"]})


@contextmanager
def _directories(store):
    root_fd = blobs_fd = db_fd = None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        root_fd = os.open(store.root, flags)
        blobs_fd = os.open("evidence", flags, dir_fd=root_fd)
        db_fd = os.open("platform.db", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)

        def validate():
            for name, fd, current in (
                ("root", root_fd, os.stat(store.root, follow_symlinks=False)),
                ("evidence", blobs_fd, os.stat("evidence", dir_fd=root_fd, follow_symlinks=False)),
            ):
                info = os.fstat(fd)
                identity = (info.st_dev, info.st_ino)
                if not stat.S_ISDIR(current.st_mode) or identity != (current.st_dev, current.st_ino) or identity != tuple(store.storage_identity[name]):
                    raise OSError("storage_replaced")
            info = os.fstat(db_fd)
            current = os.stat("platform.db", dir_fd=root_fd, follow_symlinks=False)
            identity = (info.st_dev, info.st_ino)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not stat.S_ISREG(current.st_mode) or identity != (current.st_dev, current.st_ino) or identity != tuple(store.storage_identity["platform.db"]):
                raise OSError("database_replaced")
        validate()
        yield blobs_fd, validate
    finally:
        if db_fd is not None:
            os.close(db_fd)
        if blobs_fd is not None:
            os.close(blobs_fd)
        if root_fd is not None:
            os.close(root_fd)


def start(store, project_id=None):
    with store.lock, store.db:
        try:
            with _directories(store):
                pass
        except OSError:
            raise Problem("التخزين تغيّر أو غير آمن", 409) from None
        _audit_guard(store)
        if project_id is not None:
            if not isinstance(project_id, str) or not re.fullmatch(r"[a-f0-9]{32}", project_id):
                raise Problem("معرف المشروع غير صالح")
            store.project(project_id)
        manifest = _manifest(store, project_id)
        try:
            with _directories(store):
                pass
        except OSError:
            raise Problem("مجلدات التخزين تغيّرت أو غير آمنة", 409) from None
        retained = [store.setting(r["key"]) for r in store.rows("SELECT key FROM settings WHERE key LIKE ?", (PREFIX + "%",))]
        if len(retained) >= MAX_SCANS:
            terminal = sorted((s for s in retained if s["status"] in ("completed", "failed")), key=lambda s: s["created"])
            if not terminal:
                raise Problem("يوجد20فحصًا نشطًا؛ أكمل أحدها أولًا", 409)
            store.db.execute("DELETE FROM settings WHERE key=?", (PREFIX + terminal[0]["id"],))
        scan = {"id": uid(), "project_id": project_id, "scope": "all" if project_id is None else "project",
                "status": "pending", "created": time.time(), "cursor": 0, "total": len(manifest),
                "verified": 0, "failed": 0, "scanned": 0, "manifest": manifest,
                "manifest_sha256": hashlib.sha256(encode(manifest).encode()).hexdigest(),
                "scope_changed": False, "passed": False, "issues": [],
                "last_batch": {"checked": 0, "bytes": 0, "incomplete": False},
                "limitation": "فحص لقطة أدلة متتابع؛ لا يضمن عدم تغيّر ملفات سبق فحصها لاحقًا ولا يفحص ملفات خارج السجل"}
        _save(store, scan, "integrity.started")
        return _public(scan)


def status(store, scan_id):
    with store.lock:
        return _public(_load(store, scan_id))


def _check_file(blobs_fd, record, batch, deadline):
    """Return None for timeout, an issue string for failure, or empty for verified."""
    fd = None
    try:
        if type(record["size"]) is not int or not 0 <= record["size"] <= MAX_FILE or not isinstance(record["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", record["sha256"]):
            return "invalid_metadata"
        if not isinstance(record["id"], str) or not re.fullmatch(r"[a-f0-9]{32}", record["id"]):
            return "unsafe_id"
        fd = os.open(record["id"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=blobs_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != record["size"] or not 0 <= info.st_size <= MAX_FILE:
            return "unsafe_file_or_size"
        digest, remaining = hashlib.sha256(), info.st_size
        while remaining:
            if time.monotonic() >= deadline:
                return None
            chunk = os.read(fd, min(65536, remaining))
            batch["bytes"] += len(chunk)
            if not chunk:
                return "short_read"
            remaining -= len(chunk)
            digest.update(chunk)
        if time.monotonic() >= deadline:
            return None
        after = os.fstat(fd)
        current = os.stat(record["id"], dir_fd=blobs_fd, follow_symlinks=False)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        if signature(info) != signature(after) or signature(after) != signature(current):
            return "file_changed"
        return "" if digest.hexdigest() == record["sha256"] else "hash_mismatch"
    except OSError:
        return "missing_or_unsafe_file"
    finally:
        if fd is not None:
            os.close(fd)


def advance(store, scan_id, *, max_files=100, max_bytes=MAX_BYTES, max_seconds=3):
    if type(max_files) is not int or not 1 <= max_files <= 100 or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 3:
        raise Problem("حدود دفعة الفحص غير صالحة")
    with store.lock, store.db:
        _audit_guard(store)
        scan = _load(store, scan_id)
        if scan["status"] in ("completed", "failed"):
            return _public(scan)
        scan["status"] = "running"
        batch = scan["last_batch"] = {"checked": 0, "bytes": 0, "incomplete": False}
        deadline = time.monotonic() + max_seconds
        try:
            with _directories(store) as (blobs_fd, validate):
                while scan["cursor"] < scan["total"]:
                    record = scan["manifest"][scan["cursor"]]
                    reserved = record["size"] if type(record["size"]) is int and 0 <= record["size"] <= MAX_FILE else 0
                    if batch["checked"] >= max_files or time.monotonic() >= deadline or batch["bytes"] + reserved > max_bytes:
                        batch["incomplete"] = True
                        break
                    issue = _check_file(blobs_fd, record, batch, deadline)
                    if issue is None:
                        batch["incomplete"] = True
                        break
                    batch["checked"] += 1
                    scan["cursor"] += 1
                    scan["scanned"] += 1
                    if issue:
                        scan["failed"] += 1
                        scan["issues"].append({"id": record["id"], "reason": issue})
                    else:
                        scan["verified"] += 1
                validate()
        except OSError:
            scan["status"] = "failed"
            scan["issues"].append({"id": None, "reason": "storage_replaced_or_unsafe"})
            batch["incomplete"] = True
            scan["persistence"] = "blocked_unsafe_storage"
            scan["updated"] = time.time()
            return _public(scan)
        if scan["cursor"] == scan["total"] and scan["status"] != "failed":
            try:
                scan["scope_changed"] = _manifest(store, scan["project_id"]) != scan["manifest"]
            except Problem:
                scan["scope_changed"] = True
            scan["passed"] = not scan["failed"] and not scan["scope_changed"]
            scan["status"] = "completed" if scan["passed"] else "failed"
        try:
            _save(store, scan, "integrity.advanced")
        except (OSError, sqlite3.Error):
            store.db.rollback()
            scan["status"], scan["passed"] = "failed", False
            scan["persistence"] = "blocked_unsafe_storage"
            scan["issues"].append({"id": None, "reason": "storage_or_persistence_failed"})
        return _public(scan)
