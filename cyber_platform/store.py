"""SQLite records, immutable evidence blobs, hash-linked audit events."""
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
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


PASSWORD_COST = 131072


def password_hash(password, salt, cost=16384):
    if type(cost) is not int or cost not in (16384, PASSWORD_COST):
        raise Problem("صيغة اشتقاق كلمة المرور غير مدعومة", 409)
    return hashlib.scrypt(password.encode(), salt=salt, n=cost, r=8, p=1, maxmem=256 * 1024 * 1024).hex()


class Store:
    def __init__(self, root, quota=2_000_000_000):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.stat().st_mode & 0o077:
            raise Problem("مجلد البيانات يجب أن يكون خاصًا بصلاحيات0700")
        self.blobs = self.root / "evidence"
        if self.blobs.is_symlink() or (self.root / "platform.db").is_symlink():
            raise Problem("روابط رمزية غير مسموحة لمجلد الأدلة أو قاعدة البيانات")
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
        CREATE TABLE IF NOT EXISTS maintenance_runs(id TEXT PRIMARY KEY, created REAL NOT NULL, operation TEXT NOT NULL,
          section_id TEXT, report TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS development_tasks(id TEXT PRIMARY KEY, created REAL NOT NULL, updated REAL NOT NULL,
          section_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL);
        """)
        self.db.commit()
        os.chmod(self.root / "platform.db", 0o600)
        self.storage_identity = {}
        for name, path in (("root", self.root), ("evidence", self.blobs), ("platform.db", self.root / "platform.db")):
            info = path.stat(follow_symlinks=False)
            self.storage_identity[name] = (info.st_dev, info.st_ino)

    def close(self):
        self.db.close()

    def setup_token(self):
        """Owner-local enrollment secret; never returned by an HTTP endpoint."""
        path = self.root / "setup-token"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                raise Problem("ملف رمز التهيئة غير آمن") from None
            with os.fdopen(fd, "rb") as file:
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 128:
                    raise Problem("ملف رمز التهيئة غير آمن")
                try:
                    token = file.read(129).decode("ascii").strip()
                except UnicodeDecodeError:
                    raise Problem("ملف رمز التهيئة غير صالح") from None
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
                    raise Problem("ملف رمز التهيئة غير صالح")
                return token
        else:
            token = secrets.token_urlsafe(32)
            with os.fdopen(fd, "wb") as file:
                file.write(token.encode("ascii"))
                file.flush()
                os.fsync(file.fileno())
            return token

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
            self.db.execute("INSERT INTO settings VALUES('owner',?)", (encode({"salt": salt.hex(), "hash": password_hash(password, salt, PASSWORD_COST), "n": PASSWORD_COST}),))
            self.audit("owner.initialized", {})

    def check_password(self, password):
        # Serialize KDF work with the store lock to bound simultaneous memory use.
        with self.lock:
            owner = self.setting("owner")
            if not owner or not isinstance(password, str) or len(password) > 256:
                return False
            cost = owner.get("n", 16384)
            valid = hmac.compare_digest(owner["hash"], password_hash(password, bytes.fromhex(owner["salt"]), cost))
            if valid and cost != PASSWORD_COST:
                salt = secrets.token_bytes(16)
                upgraded = {"salt": salt.hex(), "hash": password_hash(password, salt, PASSWORD_COST), "n": PASSWORD_COST}
                with self.db:
                    self.db.execute("UPDATE settings SET value=? WHERE key='owner'", (encode(upgraded),))
                    self.audit("owner.kdf_upgraded", {})
            return valid

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
        if not isinstance(name, str) or not 1 <= len(name) <= 200 or any(c in name for c in ("/", "\\")) or any(ord(c) < 32 or ord(c) == 127 for c in name):
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
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise Problem("ملف الدليل مفقود أو غير آمن", 409) from None
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != record["size"] or info.st_size > 16 * 1024 * 1024:
                raise Problem("فشل تحقق بصمة الدليل أو حجمه أو نوع ملفه", 409)
            data = file.read(16 * 1024 * 1024 + 1)
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
