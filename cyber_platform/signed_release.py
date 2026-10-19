"""Offline Ed25519 release verification; no downloading, installation or code execution.

Signatures cover canonical UTF-8 JSON of ``signed`` only. The caller must persist
``next_state`` atomically after successful activation, and protect trust/state
files separately from the release artifact. This format is not a TUF client.
"""
import base64
import binascii
import hashlib
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .store import Problem

REPOSITORY = "Waseem-gtt/was"
MAX_JSON = 32 * 1024
MAX_ARTIFACT = 128 * 1024 * 1024
MAX_LIFETIME = 30 * 24 * 60 * 60
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\Z")


def _bad(message="بيانات الإصدار الموقّع غير صالحة", status=400):
    raise Problem(message, status)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _bad("مفاتيح JSON مكررة")
        result[key] = value
    return result


def _constant(_value):
    _bad("أرقام JSON غير منتهية غير مسموحة")


def load_json(data):
    """Decode a bounded strict JSON object; never accept duplicate keys."""
    if not isinstance(data, (bytes, str)):
        _bad()
    try:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if len(raw) > MAX_JSON:
            _bad("ملف الإصدار أكبر من الحد المسموح")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        _bad("ملف JSON غير صالح")
    if type(value) is not dict:
        _bad("يجب أن يكون ملف JSON كائنًا")
    return value


def canonical(value):
    """Canonical representation for this narrowly specified JSON protocol."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _bad("تعذر ترميز بيانات الإصدار")


def key_id(public_bytes):
    if type(public_bytes) is not bytes or len(public_bytes) != 32:
        _bad("مفتاح Ed25519 العام غير صالح")
    return hashlib.sha256(public_bytes).hexdigest()


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        _bad("حقول الإصدار غير مطابقة للصيغة")


def _integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        _bad("قيمة عددية غير صالحة")


def _match(value, pattern):
    if type(value) is not str or not pattern.fullmatch(value):
        _bad("صيغة نصية غير صالحة")


def _scope(value):
    if value != REPOSITORY or type(value) is not str:
        _bad("الإصدار لا يخص المستودع المعتمد")


def _decode(value, length):
    if type(value) is not str or len(value) != ((length + 2) // 3) * 4:
        _bad("ترميز المفتاح أو التوقيع غير صالح")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        _bad("ترميز المفتاح أو التوقيع غير صالح")
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        _bad("ترميز المفتاح أو التوقيع غير معياري")
    return decoded


def validate_payload(payload):
    _fields(payload, ("schema", "repository", "sequence", "version", "commit", "issued_at", "expires_at", "artifacts"))
    if payload["schema"] != "was.release/1":
        _bad("صيغة إصدار غير مدعومة")
    _scope(payload["repository"])
    _integer(payload["sequence"], 1, 2**63 - 1)
    _match(payload["version"], _VERSION)
    _match(payload["commit"], _COMMIT)
    _integer(payload["issued_at"], 1, 2**63 - 1)
    _integer(payload["expires_at"], 1, 2**63 - 1)
    if not 0 < payload["expires_at"] - payload["issued_at"] <= MAX_LIFETIME:
        _bad("مدة صلاحية الإصدار غير مقبولة")
    artifacts = payload["artifacts"]
    if type(artifacts) is not list or not 1 <= len(artifacts) <= 16:
        _bad("قائمة حزم الإصدار غير صالحة")
    names = set()
    for artifact in artifacts:
        _fields(artifact, ("name", "sha256", "size"))
        name = artifact["name"]
        _match(name, _NAME)
        if ".." in name or name in names:
            _bad("اسم حزمة غير آمن أو مكرر")
        names.add(name)
        _match(artifact["sha256"], _HEX64)
        _integer(artifact["size"], 0, MAX_ARTIFACT)
    if len(canonical(payload)) > MAX_JSON:
        _bad("بيانات الإصدار أكبر من الحد المسموح")
    return payload


def _trust(trust):
    _fields(trust, ("schema", "repository", "threshold", "keys"))
    if trust["schema"] != "was.trust/1":
        _bad("صيغة ثقة غير مدعومة")
    _scope(trust["repository"])
    if type(trust["keys"]) is not list or not 1 <= len(trust["keys"]) <= 8:
        _bad("قائمة مفاتيح الثقة غير صالحة")
    _integer(trust["threshold"], 1, len(trust["keys"]))
    keys = {}
    for entry in trust["keys"]:
        _fields(entry, ("key_id", "public_key"))
        raw = _decode(entry["public_key"], 32)
        identifier = key_id(raw)
        if entry["key_id"] != identifier or identifier in keys:
            _bad("هوية مفتاح الثقة غير مطابقة أو مكررة")
        keys[identifier] = Ed25519PublicKey.from_public_bytes(raw)
    return keys


def verify(envelope, trust, expected_commit=None, previous=None, now=None):
    """Validate scope, freshness, signer threshold and persisted rollback state.

    Invalid or unknown signatures fail closed, even if enough other signatures
    would pass. Replaying the identical payload at the same sequence is allowed
    only while it remains valid. No state or filesystem is changed here.
    """
    _fields(envelope, ("signed", "signatures"))
    if len(canonical(envelope)) > MAX_JSON or len(canonical(trust)) > MAX_JSON:
        _bad("بيانات التوقيع أكبر من الحد المسموح")
    payload = validate_payload(envelope["signed"])
    keys = _trust(trust)
    current = int(time.time()) if now is None else now
    _integer(current, 1, 2**63 - 1)
    if not payload["issued_at"] <= current < payload["expires_at"]:
        _bad("الإصدار منتهي الصلاحية أو مؤرخ في المستقبل")
    if expected_commit is not None:
        _match(expected_commit, _COMMIT)
        if payload["commit"] != expected_commit:
            _bad("الإصدار لا يطابق تثبيت Git المطلوب")
    signed = canonical(payload)
    digest = hashlib.sha256(signed).hexdigest()
    signatures = envelope["signatures"]
    if type(signatures) is not list or not 1 <= len(signatures) <= 8:
        _bad("قائمة التوقيعات غير صالحة")
    signers = []
    for entry in signatures:
        _fields(entry, ("key_id", "signature"))
        identifier = entry["key_id"]
        _match(identifier, _HEX64)
        if identifier not in keys or identifier in signers:
            _bad("موقّع غير موثوق أو مكرر")
        signature = _decode(entry["signature"], 64)
        try:
            keys[identifier].verify(signature, signed)
        except InvalidSignature:
            _bad("توقيع الإصدار غير صحيح")
        signers.append(identifier)
    if len(signers) < trust["threshold"]:
        _bad("لم يتحقق الحد المطلوب من الموقّعين")
    if previous is not None:
        _fields(previous, ("schema", "repository", "sequence", "digest"))
        if previous["schema"] != "was.release-state/1":
            _bad("صيغة حالة الإصدار غير مدعومة")
        _scope(previous["repository"])
        _integer(previous["sequence"], 1, 2**63 - 1)
        _match(previous["digest"], _HEX64)
        if payload["sequence"] < previous["sequence"]:
            _bad("رفض الرجوع إلى تسلسل إصدار أقدم", 409)
        if payload["sequence"] == previous["sequence"] and digest != previous["digest"]:
            _bad("تعارض بيانات الإصدار عند التسلسل نفسه", 409)
    return {"payload": json.loads(signed), "digest": digest, "signers": sorted(signers),
            "next_state": {"schema": "was.release-state/1", "repository": REPOSITORY,
                           "sequence": payload["sequence"], "digest": digest}}
