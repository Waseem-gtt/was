"""Explicit offline publisher operations; never generate or trust a key on startup."""
import base64
import hashlib
import os
from pathlib import Path
import stat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from . import plugin_installations, plugin_registry
from .store import Problem, encode


def _read(path, limit, private=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit or private and info.st_mode & 0o077:
                raise Problem('ملف إعداد الحزمة أو المفتاح غير آمن أو يتجاوز الحد')
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise Problem('ملف إعداد الحزمة يتجاوز الحد')
            return data
    except OSError:
        raise Problem('تعذر فتح ملف إعداد الحزمة بأمان') from None


def _write(path, data):
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if created:
            Path(path).unlink(missing_ok=True)
        raise


def generate_key(output):
    """Called only by the explicit offline plugin-keygen command."""
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _write(output, raw)
    return {'public_key': base64.b64encode(public).decode(),
            'key_id': hashlib.sha256(public).hexdigest(), 'private_key_path': str(output),
            'notice': 'المفتاح الخاص محفوظ بصلاحيات0600؛ لا ترفعه إلىGit. لم تُمنح ثقة تلقائية للناشر.'}


def build(key_path, manifest_path, module_path, fixtures_path, output):
    """Sign a local compiled module without executing it or changing owner trust."""
    try:
        key = serialization.load_pem_private_key(_read(key_path, 16384, private=True), password=None)
    except (ValueError, TypeError):
        raise Problem('المفتاح الخاص يحتاج صيغةEd25519 PKCS8صحيحة') from None
    if not isinstance(key, Ed25519PrivateKey):
        raise Problem('نوع مفتاح الناشر يحتاجEd25519')
    manifest = plugin_registry._manifest(plugin_installations._strict(_read(manifest_path, 16384)))
    module = _read(module_path, plugin_installations.LIMITS['module_bytes'])
    if not module.startswith(b'\0asm\x01\0\0\0'):
        raise Problem('ملف الإضافة يحتاجWebAssemblyثنائيًا؛ لا يُنفذ كودPythonأوShell')
    fixtures = plugin_installations._strict(_read(fixtures_path, plugin_installations.LIMITS['package_bytes']))
    signed = {'schema': 'was.plugin-package/1', 'manifest': manifest,
              'module_sha256': hashlib.sha256(module).hexdigest(), 'fixtures': fixtures}
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    package = {'signed': signed, 'module_base64': base64.b64encode(module).decode(),
               'public_key': base64.b64encode(public).decode(),
               'signature': base64.b64encode(key.sign(encode(signed).encode())).decode()}
    raw = encode(package).encode()
    plugin_installations._package(raw)  # Structural/signature validation only, never executes the module.
    _write(output, raw)
    return {'output': str(output), 'sha256': hashlib.sha256(raw).hexdigest(),
            'public_key': package['public_key'], 'key_id': hashlib.sha256(public).hexdigest(),
            'notice': 'حزمة موقعة فقط؛ اعتماد الناشر والتثبيت والاختبار والتفعيل عمليات مالك مستقلة.'}
