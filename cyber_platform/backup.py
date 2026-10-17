"""Password-encrypted exports. Restoration always targets a new directory."""
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .store import Problem, Store, encode

MAGIC = b"WASBACKUP1\0"
MAX_SIZE = 128 * 1024 * 1024


def key(password, salt):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise Problem("كلمة حماية النسخة تحتاج 12–256 حرفًا")
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)


def export(store, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    derived = key(password, salt)
    with store.lock:
        if store.resources()["evidence_bytes"] > MAX_SIZE - 8 * 1024 * 1024:
            raise Problem("حد النسخ في هذه النسخة 120 MiB من الأدلة", 409)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "platform.db"
            conn = sqlite3.connect(path)
            store.db.backup(conn)
            conn.close()
            files = {"platform.db": path.read_bytes()}
            for record in store.rows("SELECT id,project_id FROM evidence"):
                files["evidence/" + record["id"]] = store.read_evidence(record["project_id"], record["id"])
            manifest = {n: hashlib.sha256(data).hexdigest() for n, data in files.items()}
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
                archive.writestr("manifest.json", encode(manifest))
            payload = stream.getvalue()
            if len(payload) > MAX_SIZE or sum(map(len, files.values())) > MAX_SIZE:
                raise Problem("تجاوز حد النسخة الاحتياطية", 413)
        with store.db:
            store.audit("backup.exported", {"files": len(files)})
    header = MAGIC + salt + nonce
    return header + AESGCM(derived).encrypt(nonce, payload, header)


def restore(payload, password, destination):
    destination = Path(destination)
    if destination.exists():
        raise Problem("الاستعادة تحتاج مجلدًا جديدًا غير موجود")
    if not payload.startswith(MAGIC) or len(payload) > MAX_SIZE + 1024:
        raise Problem("صيغة النسخة أو حجمها غير صالح")
    offset = len(MAGIC)
    salt, nonce = payload[offset:offset + 16], payload[offset + 16:offset + 28]
    header = payload[:offset + 28]
    try:
        plain = AESGCM(key(password, salt)).decrypt(nonce, payload[offset + 28:], header)
    except (InvalidTag, ValueError):
        raise Problem("كلمة الحماية أو سلامة النسخة غير صحيحة") from None
    try:
        with zipfile.ZipFile(io.BytesIO(plain)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or len(names) > 20000 or sum(i.file_size for i in archive.infolist()) > MAX_SIZE:
                raise Problem("محتوى النسخة يتجاوز الحدود")
            if "manifest.json" not in names or "platform.db" not in names:
                raise Problem("بيان النسخة مفقود")
            manifest = json.loads(archive.read("manifest.json"))
            if set(names) != set(manifest) | {"manifest.json"}:
                raise Problem("ملفات النسخة لا تطابق البيان")
            files = {}
            for name, digest in manifest.items():
                if name != "platform.db" and not (__import__("re").fullmatch(r"evidence/[a-f0-9]{32}", name)):
                    raise Problem("مسار غير مسموح في النسخة")
                data = archive.read(name)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise Problem("فشل بصمة النسخة")
                files[name] = data
    except (zipfile.BadZipFile, KeyError, TypeError, json.JSONDecodeError):
        raise Problem("النسخة غير صالحة") from None
    # Validate the database and the evidence in staging, before publishing destination.
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        stage = Path(temp) / "restore"
        stage.mkdir(mode=0o700)
        for name, data in files.items():
            path = stage / name
            path.parent.mkdir(exist_ok=True, mode=0o700)
            path.write_bytes(data)
            path.chmod(0o600)
        store = Store(stage)
        try:
            if store.rows("PRAGMA integrity_check")[0]["integrity_check"] != "ok" or not store.verify_audit()["valid"]:
                raise Problem("فشل تحقق قاعدة البيانات")
            for record in store.rows("SELECT id,project_id FROM evidence"):
                store.read_evidence(record["project_id"], record["id"])
            with store.lock, store.db:
                store.audit("backup.restored", {})
        finally:
            store.close()
        if destination.exists():
            raise Problem("مجلد الاستعادة موجود")
        stage.rename(destination)
