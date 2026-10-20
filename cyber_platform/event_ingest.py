"""Preserve event inputs and normalized derivatives with verifiable provenance."""
import hashlib
from pathlib import Path
from . import __version__, event_adapters, tools, worker
from .integrity import _directories
from .store import Problem, encode


def fingerprint():
    root = Path(__file__).parent
    return hashlib.sha256(encode({"version": __version__, "files": {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("event_ingest.py", "event_adapters.py", "tools.py", "worker.py") + tools.ANALYZER_FILES}}).encode()).hexdigest()


def _input(store, project_id, evidence_id, adapter):
    if not isinstance(adapter, str) or adapter not in {a["id"] for a in event_adapters.catalog()}:
        raise Problem("اختر محول أحداث مسجلًا")
    record = store.evidence(project_id, evidence_id)
    if record["size"] > event_adapters.MAX_BYTES:
        raise Problem("مدخل الأحداث يتجاوز1MiB", 413)
    raw = store.read_evidence(project_id, evidence_id)
    try:
        content = raw.decode("utf-8")
    except UnicodeError:
        raise Problem("سجل الأحداث يحتاجUTF-8صالحًا") from None
    return raw, encode({"adapter": adapter, "content": content}).encode()


def normalize(store, project_id, evidence_id, adapter):
    store.project(project_id)
    try:
        with store.lock, _directories(store):
            if not store.verify_audit()["valid"]:
                raise Problem("سلسلة التدقيق غير سليمة", 409)
            raw, payload = _input(store, project_id, evidence_id, adapter)
            before = fingerprint()
        result = worker.analyze("events", payload, timeout=3)
        if fingerprint() != before:
            raise Problem("تغير محول الأحداث أثناء التنفيذ؛ أعد المحاولة", 409)
        if not isinstance(result, dict) or result.get("input_sha256") != hashlib.sha256(raw).hexdigest() or result.get("schema") != "was.event/1" or result.get("adapter") != adapter:
            raise Problem("فشل التحقق من ناتج محول الأحداث", 409)
        report = {"schema": "was.event-evidence/1", "adapter": adapter,
                  "input_evidence": evidence_id, "input_sha256": hashlib.sha256(raw).hexdigest(),
                  "adapter_sha256": before, "result": result}
        with store.lock, _directories(store):
            if not store.verify_audit()["valid"]:
                raise Problem("سلسلة التدقيق غير سليمة", 409)
            if hashlib.sha256(store.read_evidence(project_id, evidence_id)).hexdigest() != report["input_sha256"]:
                raise Problem("تغير أصل الأحداث أثناء التنفيذ", 409)
            # Share the library's pinned-directory transaction and rollback cleanup.
            # Store.add_evidence commits internally, so it cannot wrap this operation.
            from .detection import _persist
            artifact = _persist(store, project_id, report, "events", evidence_id)
        return {"evidence": artifact, "report": report}
    except OSError:
        raise Problem("التخزين تغيّر أو غير آمن", 409) from None
    except (ValueError, TypeError, KeyError, RecursionError):
        raise Problem("تعذر توحيد الأحداث؛ راجع الصيغة وحدود المحول") from None


def verify(store, project_id, evidence_id):
    """Replay fixed normalization in a bounded worker before trusting a derivative."""
    record = store.evidence(project_id, evidence_id)
    if record["kind"] != "events" or record["size"] > 4 * 1024 * 1024:
        raise Problem("ليس دليل أحداث موحدًا مدعومًا", 409)
    try:
        report = event_adapters.strict_json(store.read_evidence(project_id, evidence_id).decode("utf-8"))
        fields = {"schema", "adapter", "input_evidence", "input_sha256", "adapter_sha256", "result"}
        if not isinstance(report, dict) or set(report) != fields or report["schema"] != "was.event-evidence/1" or report["input_evidence"] != record["parent_id"] or report["adapter_sha256"] != fingerprint():
            raise Problem("مصدر الأحداث الموحدة أو محولها تغير", 409)
        raw, payload = _input(store, project_id, report["input_evidence"], report["adapter"])
        if report["input_sha256"] != hashlib.sha256(raw).hexdigest():
            raise Problem("بصمة أصل الأحداث غير مطابقة", 409)
        actual = worker.analyze("events", payload, timeout=3)
        if encode(actual) != encode(report["result"]) or report["adapter_sha256"] != fingerprint():
            raise Problem("ناتج الأحداث الموحدة لا يطابق الأصل", 409)
        return report
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise Problem("دليل الأحداث الموحد غير صالح", 409) from None
