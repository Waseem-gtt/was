"""SQLite records, immutable evidence blobs, hash-linked audit events."""
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
import uuid
from pathlib import Path


class Problem(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def uid():
    return uuid.uuid4().hex


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()


class Store:
    def __init__(self, root, quota=2_000_000_000):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.blobs = self.root / "evidence"
        self.blobs.mkdir(exist_ok=True, mode=0o700)
        self.quota = quota
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / "platform.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), name TEXT NOT NULL,
          sha256 TEXT NOT NULL, size INTEGER NOT NULL, kind TEXT NOT NULL, parent_id TEXT REFERENCES evidence(id), created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), name TEXT NOT NULL,
          status TEXT NOT NULL, spec TEXT NOT NULL, results TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS relations(id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), source TEXT NOT NULL,
          target TEXT NOT NULL, label TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, time REAL NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL,
          previous TEXT NOT NULL, hash TEXT NOT NULL);
        """)
        self.db.commit()
        os.chmod(self.root / "platform.db", 0o600)

    def close(self):
        self.db.close()

    def rows(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args)]

    def setting(self, key, default=None):
        rows = self.rows("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def audit(self, action, details):
        # Caller holds lock and owns the surrounding database transaction.
        row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else "0" * 64
        now, detail = time.time(), encode(details)
        digest = hashlib.sha256(encode([now, action, detail, previous]).encode()).hexdigest()
        self.db.execute("INSERT INTO audit(time,action,details,previous,hash) VALUES(?,?,?,?,?)", (now, action, detail, previous, digest))

    def verify_audit(self):
        previous = "0" * 64
        rows = self.rows("SELECT * FROM audit ORDER BY seq")
        for row in rows:
            digest = hashlib.sha256(encode([row["time"], row["action"], row["details"], previous]).encode()).hexdigest()
            if row["previous"] != previous or not hmac.compare_digest(row["hash"], digest):
                return {"valid": False, "broken_at": row["seq"], "count": len(rows)}
            previous = digest
        return {"valid": True, "count": len(rows), "head": previous,
                "limitation": "سلسلة محلية؛ ليست توقيعًا خارجيًا ضد مدير الجهاز"}

    def initialize(self, password):
        if not isinstance(password, str) or not 12 <= len(password) <= 256:
            raise Problem("كلمة المرور يجب أن تكون بين 12 و256 حرفًا")
        with self.lock, self.db:
            if self.setting("owner"):
                raise Problem("تم إعداد حساب المالك مسبقًا", 409)
            salt = secrets.token_bytes(16)
            self.db.execute("INSERT INTO settings VALUES('owner',?)", (encode({"salt": salt.hex(), "hash": password_hash(password, salt)}),))
            self.audit("owner.initialized", {})

    def check_password(self, password):
        owner = self.setting("owner")
        if not owner or not isinstance(password, str) or len(password) > 256:
            return False
        return hmac.compare_digest(owner["hash"], password_hash(password, bytes.fromhex(owner["salt"])))

    def project(self, project_id):
        rows = self.rows("SELECT * FROM projects WHERE id=?", (project_id,))
        if not rows:
            raise Problem("المشروع غير موجود", 404)
        return rows[0]

    def create_project(self, name, description=""):
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120:
            raise Problem("اسم المشروع مطلوب، بحد أقصى 120 حرفًا")
        if not isinstance(description, str) or len(description) > 4000:
            raise Problem("الوصف طويل جدًا")
        project_id = uid()
        with self.lock, self.db:
            self.db.execute("INSERT INTO projects VALUES(?,?,?,?)", (project_id, name.strip(), description, time.time()))
            self.audit("project.created", {"id": project_id})
        return self.project(project_id)

    def resources(self):
        used = sum(f.stat().st_size for f in self.blobs.iterdir() if f.is_file())
        disk = shutil.disk_usage(self.root)
        return {"evidence_bytes": used, "evidence_quota": self.quota, "filesystem_free": disk.free,
                "filesystem_total": disk.total, "cpu_count": os.cpu_count(), "project_limit_target": 35_000_000_000,
                "limitation": "حصة أدلة محلية؛ ليست حصة نظام الضيف الكامل"}

    def add_evidence(self, project_id, name, data, kind="original", parent_id=None):
        self.project(project_id)
        if not isinstance(name, str) or not 1 <= len(name) <= 200 or any(c in name for c in ("/", "\\", "\0")):
            raise Problem("اسم الملف غير صالح")
        if len(data) > 16 * 1024 * 1024:
            raise Problem("حد الملف 16 MiB", 413)
        with self.lock:
            resources = self.resources()
            if resources["evidence_bytes"] + len(data) > self.quota or resources["filesystem_free"] < len(data) + 256 * 1024 * 1024:
                raise Problem("المساحة أو حصة الأدلة لا تكفي", 409)
            if parent_id:
                self.evidence(project_id, parent_id)
            eid = uid()
            path = self.blobs / eid
            try:
                with path.open("xb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                path.chmod(0o400)
                with self.db:
                    self.db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)", (eid, project_id, name, hashlib.sha256(data).hexdigest(), len(data), kind, parent_id, time.time()))
                    self.audit("evidence.created", {"id": eid, "project": project_id, "kind": kind})
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        return self.evidence(project_id, eid)

    def evidence(self, project_id, eid):
        if not isinstance(eid, str) or not re.fullmatch(r"[a-f0-9]{32}", eid):
            raise Problem("معرف الدليل غير صالح", 404)
        rows = self.rows("SELECT * FROM evidence WHERE id=? AND project_id=?", (eid, project_id))
        if not rows:
            raise Problem("الدليل غير موجود في المشروع", 404)
        return rows[0]

    def read_evidence(self, project_id, eid):
        record = self.evidence(project_id, eid)
        path = self.blobs / record["id"]
        if path.is_symlink() or not path.is_file():
            raise Problem("ملف الدليل مفقود أو غير آمن", 409)
        data = path.read_bytes()
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise Problem("فشل تحقق بصمة الدليل؛ أُوقف الاستخدام", 409)
        return data

    def link(self, project_id, source, target, label):
        self.evidence(project_id, source)
        self.evidence(project_id, target)
        if not isinstance(label, str) or not 1 <= len(label) <= 100:
            raise Problem("وصف العلاقة مطلوب")
        with self.lock, self.db:
            self.db.execute("INSERT INTO relations VALUES(?,?,?,?,?)", (uid(), project_id, source, target, label))
            self.audit("relation.created", {"project": project_id, "source": source, "target": target})

    def project_data(self, project_id):
        return {"project": self.project(project_id),
                "evidence": self.rows("SELECT * FROM evidence WHERE project_id=? ORDER BY created DESC", (project_id,)),
                "jobs": [{**r, "spec": json.loads(r["spec"]), "results": json.loads(r["results"])} for r in self.rows("SELECT * FROM jobs WHERE project_id=? ORDER BY created DESC", (project_id,))],
                "relations": self.rows("SELECT * FROM relations WHERE project_id=?", (project_id,))}
