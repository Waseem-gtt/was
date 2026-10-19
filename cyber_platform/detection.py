"""Versioned exact-match defensive rules; explicit labels, bounded trusted workers."""
import hashlib
import json
import math
import os
import re
import time
from pathlib import Path
from . import tools, worker
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode, uid

LIMITS = {"owner_rules": 50, "revisions_per_rule": 10, "rules_per_test": 50,
          "events": 10000, "input_bytes": 4 * 1024 * 1024, "output_bytes": 4 * 1024 * 1024}
NOTICE = "مكتبة مطابقة حقول دقيقة على بيانات مقدمة؛ ليست Sigma كاملة أو مراقبة حية. التسميات المرجعية يحددها مصدر البيانات وليست حقيقة مستقلة أو إثبات حماية شاملة."
PREFIX = "detection.library."
FIELDS = {"id", "title", "version", "license", "source", "selection"}


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _bad(message="صيغة قاعدة الكشف أو بيانات الاختبار غير صالحة", status=400):
    raise Problem(message, status)


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("Duplicate JSON key")
        result[k] = v
    return result


def _finite(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite")
    return number


def _json(raw):
    if len(raw) > LIMITS["input_bytes"]:
        _bad("حد بيانات الاختبار 4 MiB", 413)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_float=_finite,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite")))
        encode(value).encode("utf-8")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _bad("JSON غير صالح أو مفاتيح مكررة")


def _rule(rule):
    if not isinstance(rule, dict) or set(rule) != FIELDS:
        _bad()
    limits = {"id": 80, "title": 200, "version": 40, "license": 100, "source": 500}
    for k, maximum in limits.items():
        value = rule[k]
        if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
            _bad()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,79}", rule["id"]) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", rule["version"]):
        _bad()
    selection = rule["selection"]
    if not isinstance(selection, dict) or not 1 <= len(selection) <= 20:
        _bad()
    for key, value in selection.items():
        if not isinstance(key, str) or not 1 <= len(key) <= 100 or any(ord(c) < 32 for c in key) or type(value) not in (str, int, float, bool, type(None)):
            _bad()
        if isinstance(value, str) and len(value) > 1000 or type(value) is float and not math.isfinite(value) or type(value) is int and abs(value) > 2 ** 63 - 1:
            _bad()
    try:
        raw = encode(rule).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        _bad()
    return json.loads(raw)


def _pack():
    raw = Path(__file__).with_name("detection_packs.json").read_bytes()
    pack = _json(raw)
    if not isinstance(pack, dict) or set(pack) != {"schema", "rules", "fixtures"} or pack["schema"] != "was.detection-pack/1" or not isinstance(pack["rules"], list) or not 1 <= len(pack["rules"]) <= 50:
        _bad("المكتبة المدمجة غير صالحة", 409)
    rules = [_rule(r) for r in pack["rules"]]
    if len({r["id"] for r in rules}) != len(rules) or any(not r["id"].startswith("was-") for r in rules):
        _bad("معرفات المكتبة المدمجة غير صالحة", 409)
    return pack, hashlib.sha256(raw).hexdigest()


def _index(store, pid):
    index = store.setting(PREFIX + pid) or {}
    if not isinstance(index, dict) or len(index) > LIMITS["owner_rules"]:
        _bad("فهرس قواعد المالك غير صالح", 409)
    for rid, revisions in index.items():
        if not isinstance(rid, str) or not isinstance(revisions, list) or not 1 <= len(revisions) <= LIMITS["revisions_per_rule"] or any(not isinstance(eid, str) or not re.fullmatch(r"[a-f0-9]{32}", eid) for eid in revisions) or len(set(revisions)) != len(revisions):
            _bad("فهرس مراجعات قواعد المالك غير صالح", 409)
    return index


def _owner_rule(store, pid, rid, eid, revision):
    evidence = store.evidence(pid, eid)
    saved = _json(store.read_evidence(pid, eid))
    if evidence["kind"] != "detection-rule" or not isinstance(saved, dict) or set(saved) != {"schema", "rule", "revision", "previous_evidence", "rule_sha256"} or saved["schema"] != "was.detection-rule/1" or saved["revision"] != revision or saved["rule_sha256"] != _digest(saved["rule"]):
        _bad("مراجعة قاعدة الكشف غير صالحة", 409)
    rule = _rule(saved["rule"])
    if rule["id"] != rid or rid.startswith("was-"):
        _bad("هوية مراجعة قاعدة الكشف غير صالحة", 409)
    return {**rule, "origin": "owner", "evidence_id": eid, "revision": revision}


def library(store, project_id):
    with store.lock:
        store.project(project_id)
        pack, digest = _pack()
        index = _index(store, project_id)
        rules = [{**r, "origin": "builtin", "evidence_id": None, "revision": 1} for r in pack["rules"]]
        for rid, revisions in index.items():
            # Verify all retained revision bytes and the immutable chain.
            previous = None
            for revision, eid in enumerate(revisions, 1):
                current = _owner_rule(store, project_id, rid, eid, revision)
                saved = _json(store.read_evidence(project_id, eid))
                if saved["previous_evidence"] != previous:
                    _bad("تغيّر تسلسل مراجعات القاعدة", 409)
                previous = eid
            rules.append(current)
        return {"schema": "was.detection-library/1", "rules": rules,
                "fixtures": pack["fixtures"], "bundle_sha256": digest,
                "limits": dict(LIMITS), "notice": NOTICE}


def _persist(store, pid, value, kind, parent=None, setting=None):
    """One database transaction, pinned blob directory, unlink on any rollback."""
    data = encode(value).encode()
    if len(data) > LIMITS["output_bytes"]:
        _bad("حجم نتيجة الكشف يتجاوز 4 MiB", 413)
    eid = uid()
    with store.lock:
        try:
            with _directories(store) as (blobs_fd, validate):
                created = False
                try:
                    with store.db:
                        _guard(store)
                        store.project(pid)
                        if parent:
                            store.evidence(pid, parent)
                        resources = store.resources()
                        if resources["evidence_bytes"] + len(data) > store.quota or resources["filesystem_free"] < len(data) + 256 * 1024 * 1024:
                            _bad("المساحة أو حصة الأدلة لا تكفي", 409)
                        fd = os.open(eid, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=blobs_fd)
                        created = True
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(data)
                            stream.flush()
                            os.fsync(stream.fileno())
                        store.db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)", (eid, pid, kind + ".json", hashlib.sha256(data).hexdigest(), len(data), kind, parent, time.time()))
                        if setting is not None:
                            key, index, rid = setting
                            index.setdefault(rid, []).append(eid)
                            store.db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, encode(index)))
                        if parent:
                            store.db.execute("INSERT INTO relations VALUES(?,?,?,?,?)", (uid(), pid, parent, eid, kind))
                        store.audit(kind + ".created", {"project": pid, "id": eid, "sha256": hashlib.sha256(data).hexdigest()})
                        validate()
                except BaseException:
                    if created:
                        os.unlink(eid, dir_fd=blobs_fd)
                    raise
        except OSError:
            _bad("التخزين تغيّر أو غير آمن", 409)
    return store.evidence(pid, eid)


def save(store, project_id, rule):
    rule = _rule(rule)
    if rule["id"].startswith("was-"):
        _bad("قواعد المكتبة المدمجة لا تقبل الاستبدال", 409)
    with store.lock:
        library(store, project_id)
        index = _index(store, project_id)
        revisions = index.get(rule["id"], [])
        if not revisions and len(index) >= LIMITS["owner_rules"] or len(revisions) >= LIMITS["revisions_per_rule"]:
            _bad("وصلت المكتبة إلى حد القواعد أو المراجعات", 409)
        for eid in revisions:
            prior = _json(store.read_evidence(project_id, eid))["rule"]
            if prior["version"] == rule["version"]:
                _bad("الإصدار محفوظ؛ استخدم رقم إصدار جديد", 409)
        revision = len(revisions) + 1
        record = {"schema": "was.detection-rule/1", "rule": rule, "revision": revision,
                  "previous_evidence": revisions[-1] if revisions else None, "rule_sha256": _digest(rule)}
        evidence = _persist(store, project_id, record, "detection-rule", parent=record["previous_evidence"],
                            setting=(PREFIX + project_id, index, rule["id"]))
        return {"evidence": evidence, "rule": {**rule, "origin": "owner", "evidence_id": evidence["id"], "revision": revision}, "revision": revision}


def _events(value):
    # Normalized evidence keeps events under result; arbitrary truth is not
    # inherited from adapter metadata or HTTP test options.
    if isinstance(value, dict) and value.get("schema") == "was.event-evidence/1":
        value = value.get("result")
    expected = {}
    if isinstance(value, dict):
        if value.get("schema") != "was.event/1" or "events" not in value:
            _bad("اختر مصفوفة أحداث أو was.event/1")
        expected = value.get("expected_matches", {})
        events = value["events"]
    else:
        events = value
    if not isinstance(events, list) or len(events) > LIMITS["events"] or any(not isinstance(event, dict) for event in events) or not isinstance(expected, dict) or len(expected) > 100:
        _bad()
    for rid, indexes in expected.items():
        if not isinstance(rid, str) or not isinstance(indexes, list) or len(indexes) > len(events) or any(type(i) is not int or not 0 <= i < len(events) for i in indexes) or len(set(indexes)) != len(indexes):
            _bad("تسميات المطابقات المرجعية غير صالحة")
    return events, expected


def _input_value(store, project_id, evidence_id, raw):
    value = _json(raw)
    if isinstance(value, dict) and value.get("schema") == "was.event-evidence/1":
        from . import event_ingest
        value = event_ingest.verify(store, project_id, evidence_id)
    return value


def _engine():
    root = Path(__file__).parent
    return _digest({name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                    for name in ("detection.py", "tools.py", "worker.py", "event_adapters.py", "event_ingest.py")})


def _execute(events, expected, snapshots):
    rules = [{k: r[k] for k in FIELDS} for r in snapshots]
    for rule in rules:
        if rule["id"] in expected:
            rule["expected_event_indexes"] = expected[rule["id"]]
    data = encode({"events": events, "rules": rules}).encode()
    if len(data) > LIMITS["input_bytes"]:
        _bad("مدخل محرك القواعد يتجاوز 4 MiB", 413)
    try:
        result = worker.analyze("rules", data)
    except ValueError as exc:
        raise Problem("تعذر إكمال اختبار قواعد الكشف ضمن الحدود", 409) from exc
    for rule in result["rules"]:
        metrics = rule["metrics"]
        if metrics is not None:
            tp, fp, fn = (metrics[k] for k in ("true_positive", "false_positive", "false_negative"))
            metrics["precision"] = tp / (tp + fp) if tp + fp else None
            metrics["recall"] = tp / (tp + fn) if tp + fn else None
    return result


def _evaluation(result):
    count = result["evaluated_rules"]
    passed = bool(count and count == len(result["rules"]) and all(r["metrics"]["passed"] for r in result["rules"]))
    return count, passed, "passed" if passed else "failed" if count else "not_evaluated"


def test(store, project_id, evidence_id, rule_ids):
    if not isinstance(rule_ids, list) or not 1 <= len(rule_ids) <= LIMITS["rules_per_test"] or any(not isinstance(rid, str) for rid in rule_ids) or len(set(rule_ids)) != len(rule_ids):
        _bad("حدد 1 إلى50 قاعدة دون تكرار")
    with store.lock:
        _guard(store)
        catalog = library(store, project_id)
        available = {r["id"]: r for r in catalog["rules"]}
        if any(rid not in available for rid in rule_ids):
            _bad("قاعدة غير موجودة في مكتبة المشروع", 404)
        original = store.evidence(project_id, evidence_id)
        raw = store.read_evidence(project_id, evidence_id)
        events, expected = _events(_input_value(store, project_id, evidence_id, raw))
        snapshots = [available[rid] for rid in rule_ids]
        engine_before = _engine()
        result = _execute(events, expected, snapshots)
        if engine_before != _engine() or _pack()[1] != catalog["bundle_sha256"]:
            _bad("تغير محرك الكشف أو مكتبة القواعد أثناء الاختبار", 409)
        count, passed, status = _evaluation(result)
        report = {"schema": "was.detection-test/1", "input_evidence": evidence_id,
                  "input_sha256": original["sha256"], "rules_sha256": _digest(snapshots),
                  "engine_sha256": engine_before, "bundle_sha256": catalog["bundle_sha256"],
                  "rules": snapshots, "result": result, "passed": passed,
                  "evaluation_status": status, "evaluated_rules": count, "notice": NOTICE}
        # Reject a concurrent modification of the original before publication.
        store.read_evidence(project_id, evidence_id)
        evidence = _persist(store, project_id, report, "detection-test", parent=evidence_id)
        return {"evidence": evidence, "report": report}


def verify_report(store, project_id, evidence_id):
    """Revalidate current provenance and replay in the bounded worker for coverage."""
    try:
        with store.lock:
            _guard(store)
            evidence = store.evidence(project_id, evidence_id)
            if evidence["kind"] != "detection-test":
                return {"status": "unverified", "snapshot": {}}
            report = _json(store.read_evidence(project_id, evidence_id))
            fields = {"schema", "input_evidence", "input_sha256", "rules_sha256", "engine_sha256", "bundle_sha256", "rules", "result", "passed", "evaluation_status", "evaluated_rules", "notice"}
            if not isinstance(report, dict) or set(report) != fields or report["schema"] != "was.detection-test/1" or not isinstance(report["rules"], list) or not 1 <= len(report["rules"]) <= 50:
                _bad()
            source = store.evidence(project_id, report["input_evidence"])
            raw = store.read_evidence(project_id, source["id"])
            catalog = library(store, project_id)
            current = {r["id"]: r for r in catalog["rules"]}
            snapshots = report["rules"]
            if evidence["parent_id"] != source["id"] or source["sha256"] != report["input_sha256"] or _digest(snapshots) != report["rules_sha256"] or report["engine_sha256"] != _engine() or report["bundle_sha256"] != catalog["bundle_sha256"] or any(r != current.get(r["id"]) for r in snapshots) or len({r["id"] for r in snapshots}) != len(snapshots):
                _bad()
            events, expected = _events(_input_value(store, project_id, source["id"], raw))
            result = _execute(events, expected, snapshots)
            if report["engine_sha256"] != _engine() or report["bundle_sha256"] != _pack()[1]:
                _bad("تغير نطاق الكشف أثناء إعادة التحقق", 409)
            count, passed, status = _evaluation(result)
            if encode(result) != encode(report["result"]) or type(report["passed"]) is not bool or report["passed"] != passed or type(report["evaluated_rules"]) is not int or report["evaluated_rules"] != count or report["evaluation_status"] != status:
                _bad()
            snapshot = {k: report[k] for k in ("input_evidence", "input_sha256", "rules_sha256", "engine_sha256", "bundle_sha256")}
            snapshot.update(evidence_id=evidence_id, evidence_sha256=evidence["sha256"])
            positive = passed and all(r["metrics"]["true_positive"] > 0 for r in result["rules"])
            return {"status": "supported" if positive else "unverified" if passed or not count else "gap", "snapshot": snapshot, "report": report}
    except (Problem, OSError, ValueError, TypeError, KeyError, RecursionError):
        return {"status": "stale", "snapshot": {}, "reason": "provenance_or_replay_invalid"}
