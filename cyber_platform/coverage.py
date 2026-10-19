"""Evidence-backed, static defense coverage; never a live protection claim."""
import hashlib
import json
import re
import time
from . import integrity
from .store import Problem, encode, uid

PREFIX = "coverage:"
MAX_BYTES = 256 * 1024
MAX_VERIFICATION_BYTES = 64 * 1024 * 1024
MAX_REPLAYS = 3
MAX_VIEW_SECONDS = 3
KINDS = {"host", "service", "data", "network"}
SNAPSHOT_KEYS = {"evidence_id", "evidence_sha256", "input_evidence", "input_sha256", "rules_sha256", "engine_sha256", "bundle_sha256", "evidence_kind"}
LIMITATION = "تغطية ثابتة مرتبطة باختبارات محفوظة؛ ليست فحصًا حيًا أو ضمان حماية أو تطبيقًا كاملًا لـD3FEND"


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def _title(value):
    return isinstance(value, str) and 1 <= len(value.strip()) <= 120 and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _snapshot_valid(value):
    if not isinstance(value, dict) or set(value) != SNAPSHOT_KEYS:
        return False
    if not _identifier(value["evidence_id"]) or not isinstance(value["evidence_kind"], str) or len(value["evidence_kind"]) > 100:
        return False
    for key in SNAPSHOT_KEYS - {"evidence_id", "evidence_kind"}:
        item = value[key]
        if item is None and key != "evidence_sha256":
            continue
        pattern = r"[a-f0-9]{32}" if key == "input_evidence" else r"[a-f0-9]{64}"
        if not isinstance(item, str) or not re.fullmatch(pattern, item):
            return False
    return True


def _load(store, pid):
    if not _identifier(pid):
        raise Problem("معرف المشروع غير صالح")
    store.project(pid)
    rows = store.rows("SELECT value FROM settings WHERE key=?", (PREFIX + pid,))
    if not rows:
        return {"schema": "was.coverage/1", "project_id": pid, "assets": [], "assessments": []}
    try:
        raw = rows[0]["value"]
        if len(raw.encode()) > MAX_BYTES:
            raise ValueError()
        state = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(state, dict) or set(state) != {"schema", "project_id", "assets", "assessments", "digest"}:
            raise ValueError()
        digest = state.pop("digest")
        if digest != _digest(state) or state["schema"] != "was.coverage/1" or state["project_id"] != pid:
            raise ValueError()
        assets, assessments = state["assets"], state["assessments"]
        if not isinstance(assets, list) or len(assets) > 100 or not isinstance(assessments, list) or len(assessments) > 200:
            raise ValueError()
        ids = set()
        for item in assets:
            if not isinstance(item, dict) or set(item) != {"id", "name", "kind", "created"} or not _identifier(item["id"]) or item["id"] in ids or not _title(item["name"]) or item["kind"] not in KINDS or type(item["created"]) not in (int, float) or not 0 < item["created"] < 1e12:
                raise ValueError()
            ids.add(item["id"])
        assessment_ids = set()
        for item in assessments:
            if not isinstance(item, dict) or set(item) != {"id", "asset_id", "threat", "control", "evidence_id", "snapshot", "created"} or not _identifier(item["id"]) or item["id"] in assessment_ids or item["asset_id"] not in ids or not _title(item["threat"]) or not _title(item["control"]) or not _snapshot_valid(item["snapshot"]) or item["evidence_id"] != item["snapshot"]["evidence_id"] or type(item["created"]) not in (int, float) or not 0 < item["created"] < 1e12:
                raise ValueError()
            assessment_ids.add(item["id"])
        return state
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise Problem("بيانات التغطية المحفوظة غير سليمة", 409) from None


def _save(store, state, action, details):
    saved = dict(state, digest=_digest(state))
    raw = encode(saved)
    if len(raw.encode()) > MAX_BYTES:
        raise Problem("تجاوز حجم خريطة التغطية المحدود", 413)
    store.db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (PREFIX + state["project_id"], raw))
    store.audit(action, dict(details, project=state["project_id"], digest=saved["digest"]))


def _reference(store, pid, eid):
    record = store.evidence(pid, eid)
    store.read_evidence(pid, eid)
    snapshot = {key: None for key in SNAPSHOT_KEYS}
    snapshot.update(evidence_id=eid, evidence_sha256=record["sha256"], evidence_kind=record["kind"])
    if record["kind"] != "detection-test":
        return {"status": "unverified", "snapshot": snapshot}
    from . import detection
    result = detection.verify_report(store, pid, eid)
    if result["status"] not in {"supported", "gap", "unverified", "stale"}:
        raise Problem("نتيجة تحقق الكشف غير صالحة", 409)
    snapshot.update(result["snapshot"])
    if not _snapshot_valid(snapshot):
        raise Problem("لقطة تحقق الكشف غير صالحة", 409)
    return {"status": result["status"], "snapshot": snapshot}


def asset(store, pid, name, kind):
    if not _title(name) or not isinstance(kind, str) or kind not in KINDS:
        raise Problem("اسم الأصل أو نوعه غير صالح")
    try:
        with store.lock, store.db, integrity._directories(store) as (_, validate):
            integrity._audit_guard(store)
            state = _load(store, pid)
            if len(state["assets"]) >= 100:
                raise Problem("حد المشروع100أصل", 413)
            item = {"id": uid(), "name": name.strip(), "kind": kind, "created": time.time()}
            state["assets"].append(item)
            validate()
            _save(store, state, "coverage.asset", {"id": item["id"]})
            return item
    except OSError:
        raise Problem("التخزين تغيّر أو غير آمن", 409) from None


def assess(store, pid, asset_id, threat, control, evidence_id):
    if not _identifier(asset_id) or not _identifier(evidence_id) or not _title(threat) or not _title(control):
        raise Problem("بيانات التقييم غير صالحة")
    try:
        with store.lock, store.db, integrity._directories(store) as (_, validate):
            integrity._audit_guard(store)
            state = _load(store, pid)
            if not any(a["id"] == asset_id for a in state["assets"]):
                raise Problem("الأصل غير موجود في المشروع", 404)
            if len(state["assessments"]) >= 200:
                raise Problem("حد المشروع200تقييم", 413)
            reference = _reference(store, pid, evidence_id)
            if reference["status"] == "stale":
                raise Problem("تقرير الكشف غير صالح أو متقادم؛ أعد اختباره", 409)
            item = {"id": uid(), "asset_id": asset_id, "threat": threat.strip(), "control": control.strip(), "evidence_id": evidence_id, "snapshot": reference["snapshot"], "created": time.time()}
            state["assessments"].append(item)
            validate()
            _save(store, state, "coverage.assessed", {"id": item["id"], "evidence": evidence_id})
            return dict(item, status=reference["status"])
    except OSError:
        raise Problem("التخزين تغيّر أو غير آمن", 409) from None


def remove(store, pid, assessment_id):
    if not _identifier(assessment_id):
        raise Problem("معرف التقييم غير صالح")
    try:
        with store.lock, store.db, integrity._directories(store) as (_, validate):
            integrity._audit_guard(store)
            state = _load(store, pid)
            previous = len(state["assessments"])
            state["assessments"] = [a for a in state["assessments"] if a["id"] != assessment_id]
            if len(state["assessments"]) == previous:
                raise Problem("التقييم غير موجود", 404)
            validate()
            _save(store, state, "coverage.removed", {"id": assessment_id})
            return {"removed": assessment_id, "evidence_preserved": True}
    except OSError:
        raise Problem("التخزين تغيّر أو غير آمن", 409) from None


def view(store, pid):
    try:
        with store.lock, integrity._directories(store) as (_, validate):
            integrity._audit_guard(store)
            state = _load(store, pid)
            cache, used, assessments = {}, 0, []
            replays, deadline = 0, time.monotonic() + MAX_VIEW_SECONDS
            for saved in state["assessments"]:
                eid = saved["evidence_id"]
                if eid not in cache:
                    try:
                        records = [store.evidence(pid, eid)]
                        source = saved["snapshot"]["input_evidence"]
                        if source:
                            records.append(store.evidence(pid, source))
                        size = sum(r["size"] for r in records)
                        is_test = records[0]["kind"] == "detection-test"
                        if type(size) is not int or size < 0 or used + size > MAX_VERIFICATION_BYTES or time.monotonic() >= deadline or is_test and replays >= MAX_REPLAYS:
                            cache[eid] = {"status": "unverified", "reason": "verification_budget", "snapshot": saved["snapshot"]}
                        else:
                            used += size
                            replays += int(is_test)
                            cache[eid] = _reference(store, pid, eid)
                    except (Problem, ValueError, TypeError, KeyError):
                        cache[eid] = {"status": "stale", "snapshot": None}
                result = cache[eid]
                status = result["status"] if result["snapshot"] == saved["snapshot"] else "stale"
                assessments.append(dict(saved, status=status, reason=result.get("reason", status)))
            groups = {}
            for item in assessments:
                groups.setdefault((item["asset_id"], item["threat"], item["control"]), []).append(item)
            for group in groups.values():
                if {a["status"] for a in group} >= {"supported", "gap"}:
                    for item in group:
                        if item["status"] in {"supported", "gap"}:
                            item.update(status="conflict", reason="contradictory_current_tests")
            assets, gaps = [], []
            priority = ("conflict", "stale", "gap", "unverified", "supported")
            for original in state["assets"]:
                own = [a for a in assessments if a["asset_id"] == original["id"]]
                status = next((s for s in priority if any(a["status"] == s for a in own)), "untested")
                assets.append(dict(original, status=status, assessment_count=len(own)))
                if not own:
                    gaps.append({"asset_id": original["id"], "assessment_id": None, "status": "untested", "reason": "no_assessment"})
            for item in assessments:
                if item["status"] != "supported":
                    gaps.append({"asset_id": item["asset_id"], "assessment_id": item["id"], "status": item["status"], "reason": item["reason"]})
            summary = {"assets": len(assets), "assessments": len(assessments)}
            summary.update({s: sum(a["status"] == s for a in assessments) for s in priority})
            summary["untested"] = sum(a["status"] == "untested" for a in assets)
            nodes = [{"id": a["id"], "label": a["name"], "kind": a["kind"]} for a in assets]
            nodes += [{"id": a["id"], "label": a["control"], "kind": "assessment"} for a in assessments]
            edges = [{"source": a["asset_id"], "target": a["id"], "label": a["threat"], "status": a["status"]} for a in assessments]
            validate()
            return {"schema": "was.coverage-view/1", "project_id": pid, "assets": assets, "assessments": assessments, "gaps": gaps, "summary": summary, "nodes": nodes, "edges": edges, "limitation": LIMITATION}
    except OSError:
        raise Problem("التخزين تغيّر أو غير آمن", 409) from None
