"""Versioned data-only analysis templates; binding evidence never executes a plan."""
import hashlib
import json
import re
from pathlib import Path
from . import detection, plans
from .quality import _guard
from .store import Problem, encode

PREFIX = "plans.templates."
LIMITS = {"owner_templates": 30, "revisions_per_template": 10, "template_bytes": 65536,
          "bundle_bytes": 256 * 1024, "slots": 20}
NOTICE = "قوالب بيانات لخطة تحليل محلية؛ ربط الأدلة ينشئ خطة ولا يشغّلها. أمثلة المدخلات اصطناعية، ولا يمثل نجاحها حماية أو إتقان تخصص."
FIELDS = {"id", "title", "version", "description", "plan"}
_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,79}")
_HEX = re.compile(r"[a-f0-9]{32}")
_HASH = re.compile(r"[a-f0-9]{64}")


def _bad(message="قالب التحليل أو بيانات ربطه غير صالحة", status=400):
    raise Problem(message, status)


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _json(raw, maximum):
    if len(raw) > maximum:
        _bad("حجم بيانات القالب يتجاوز الحد", 413)
    return detection._json(raw)


def _template(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        _bad()
    limits = {"id": 80, "title": 200, "version": 40, "description": 1000}
    for key, maximum in limits.items():
        item = value[key]
        if not isinstance(item, str) or not 1 <= len(item) <= maximum or any(ord(c) < 32 or ord(c) == 127 for c in item):
            _bad()
    if not _ID.fullmatch(value["id"]) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"]):
        _bad()
    try:
        copied = _json(encode(value).encode(), LIMITS["template_bytes"])
        copied["plan"] = plans.validate(copied["plan"], allow_slots=True)
        if any("evidence_id" in n["input"] for n in copied["plan"]["nodes"]):
            _bad("القالب يستخدم خانات أدلة فقط؛ لا تحفظ معرف دليل داخله")
        if not _slots(copied["plan"]):
            _bad("القالب يحتاج خانة دليل واحدة على الأقل")
        if len(encode(copied).encode()) > LIMITS["template_bytes"]:
            _bad("حجم القالب بعد التطبيع يتجاوز الحد", 413)
        return copied
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _bad()


def _slots(plan):
    return sorted({n["input"]["slot"] for n in plan["nodes"] if "slot" in n["input"]})


def _pack():
    raw = Path(__file__).with_name("plan_templates.json").read_bytes()
    pack = _json(raw, LIMITS["bundle_bytes"])
    if not isinstance(pack, dict) or set(pack) != {"schema", "templates", "fixtures"} or pack["schema"] != "was.plan-template-pack/1" or not isinstance(pack["templates"], list) or not 1 <= len(pack["templates"]) <= 30 or not isinstance(pack["fixtures"], list) or len(pack["fixtures"]) > 30:
        _bad("حزمة القوالب المدمجة غير صالحة", 409)
    templates = [_template(t) for t in pack["templates"]]
    indexed = {t["id"]: t for t in templates}
    if len(indexed) != len(templates) or any(not identifier.startswith("was-") for identifier in indexed):
        _bad("معرفات القوالب المدمجة غير صالحة", 409)
    fixtures, ids = [], set()
    for fixture in pack["fixtures"]:
        if not isinstance(fixture, dict) or set(fixture) != {"id", "title", "template_id", "inputs"} or not isinstance(fixture["id"], str) or not _ID.fullmatch(fixture["id"]) or fixture["id"] in ids or fixture["template_id"] not in indexed or not isinstance(fixture["title"], str) or not 1 <= len(fixture["title"]) <= 200:
            _bad("مثال القالب غير صالح", 409)
        inputs = fixture["inputs"]
        if not isinstance(inputs, dict) or set(inputs) != set(_slots(indexed[fixture["template_id"]]["plan"])) or any(not isinstance(v, str) or len(v.encode()) > LIMITS["template_bytes"] for v in inputs.values()):
            _bad("مدخلات مثال القالب غير صالحة", 409)
        ids.add(fixture["id"])
        fixtures.append(fixture)
    return templates, fixtures, hashlib.sha256(raw).hexdigest()


def _index(store, project_id):
    rows = store.rows("SELECT value FROM settings WHERE key=?", (PREFIX + project_id,))
    if not rows:
        return {}
    try:
        index = _json(rows[0]["value"].encode(), LIMITS["template_bytes"])
        if not isinstance(index, dict) or len(index) > LIMITS["owner_templates"]:
            raise ValueError()
        all_evidence = set()
        for identifier, revisions in index.items():
            if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or identifier.startswith("was-") or not isinstance(revisions, list) or not 1 <= len(revisions) <= LIMITS["revisions_per_template"]:
                raise ValueError()
            for eid in revisions:
                if not isinstance(eid, str) or not _HEX.fullmatch(eid) or eid in all_evidence:
                    raise ValueError()
                all_evidence.add(eid)
        return index
    except (Problem, ValueError, TypeError):
        _bad("فهرس مراجعات القوالب غير صالح", 409)


def _revision(store, pid, identifier, eid, revision, previous):
    record = store.evidence(pid, eid)
    saved = _json(store.read_evidence(pid, eid), LIMITS["template_bytes"] + 1024)
    fields = {"schema", "template", "revision", "previous_evidence", "template_sha256"}
    if record["kind"] != "plan-template" or record["parent_id"] != previous or not isinstance(saved, dict) or set(saved) != fields or saved["schema"] != "was.plan-template/1" or type(saved["revision"]) is not int or saved["revision"] != revision or saved["previous_evidence"] != previous:
        _bad("مراجعة القالب أو تسلسلها غير صالح", 409)
    template = _template(saved["template"])
    if template["id"] != identifier or saved["template_sha256"] != _digest(template):
        _bad("بصمة مراجعة القالب غير مطابقة", 409)
    return dict(template, origin="owner", evidence_id=eid, revision=revision, template_sha256=saved["template_sha256"])


def library(store, project_id):
    with store.lock:
        store.project(project_id)
        templates, fixtures, bundle = _pack()
        result = [dict(t, origin="builtin", evidence_id=None, revision=1, template_sha256=_digest(t)) for t in templates]
        for identifier, revisions in _index(store, project_id).items():
            previous, versions, latest = None, set(), None
            for revision, eid in enumerate(revisions, 1):
                latest = _revision(store, project_id, identifier, eid, revision, previous)
                if latest["version"] in versions:
                    _bad("تكرار إصدار في تسلسل مراجعات القالب", 409)
                versions.add(latest["version"])
                previous = eid
            result.append(latest)
        return {"schema": "was.plan-template-library/1", "templates": result, "fixtures": fixtures,
                "bundle_sha256": bundle, "limits": dict(LIMITS), "notice": NOTICE}


def save(store, project_id, template):
    template = _template(template)
    if template["id"].startswith("was-"):
        _bad("القوالب المدمجة لا تقبل الاستبدال", 409)
    with store.lock:
        _guard(store)
        library(store, project_id)
        index = _index(store, project_id)
        revisions = index.get(template["id"], [])
        if not revisions and len(index) >= LIMITS["owner_templates"] or len(revisions) >= LIMITS["revisions_per_template"]:
            _bad("وصلت القوالب إلى حد المعرفات أو المراجعات", 409)
        for eid in revisions:
            prior = _json(store.read_evidence(project_id, eid), LIMITS["template_bytes"] + 1024)
            if prior["template"]["version"] == template["version"]:
                _bad("رقم الإصدار محفوظ؛ استخدم إصدارًا جديدًا", 409)
        revision = len(revisions) + 1
        digest = _digest(template)
        saved = {"schema": "was.plan-template/1", "template": template, "revision": revision,
                 "previous_evidence": revisions[-1] if revisions else None, "template_sha256": digest}
        record = detection._persist(store, project_id, saved, "plan-template", parent=saved["previous_evidence"],
                                    setting=(PREFIX + project_id, index, template["id"]))
        return {"evidence": record, "template": dict(template, origin="owner", evidence_id=record["id"], revision=revision, template_sha256=digest), "revision": revision}


def instantiate(store, project_id, template_id, bindings):
    if not isinstance(template_id, str) or not _ID.fullmatch(template_id) or not isinstance(bindings, dict):
        _bad()
    with store.lock:
        _guard(store)
        catalog = library(store, project_id)
        chosen = next((t for t in catalog["templates"] if t["id"] == template_id), None)
        if chosen is None:
            _bad("القالب غير موجود في مكتبة المشروع", 404)
        if set(bindings) != set(_slots(chosen["plan"])):
            _bad("اربط جميع خانات الأدلة المطلوبة فقط")
        proof = {}
        for slot, eid in bindings.items():
            if not isinstance(eid, str) or not _HEX.fullmatch(eid):
                _bad("معرف دليل الربط غير صالح")
            record = store.evidence(project_id, eid)
            if record["size"] > 4 * 1024 * 1024:
                _bad("مدخل خطة التحليل يتجاوز4MiB", 413)
            store.read_evidence(project_id, eid)
            proof[slot] = {"evidence_id": eid, "sha256": record["sha256"]}
        plan = json.loads(encode(chosen["plan"]))
        for node in plan["nodes"]:
            if "slot" in node["input"]:
                node["input"] = {"evidence_id": bindings[node["input"]["slot"]]}
        plan = plans.validate(plan)
        saved = {"schema": "was.plan-instantiation/1", "plan": plan, "template_id": template_id,
                 "template_sha256": chosen["template_sha256"], "revision": chosen["revision"],
                 "bindings": proof, "bundle_sha256": catalog["bundle_sha256"]}
        artifact = detection._persist(store, project_id, saved, "plan-instantiation",
                                      parent=proof[sorted(proof)[0]]["evidence_id"])
        return {k: v for k, v in saved.items() if k != "schema"} | {"evidence": artifact}


def verify_instantiation(store, project_id, evidence_id, plan):
    """Authenticate a retained template revision and its exact concrete bindings."""
    try:
        with store.lock:
            _guard(store)
            record = store.evidence(project_id, evidence_id)
            if record["kind"] != "plan-instantiation":
                _bad("ليس دليل ربط قالب محفوظًا", 409)
            saved = _json(store.read_evidence(project_id, evidence_id), LIMITS["template_bytes"] + 32768)
            fields = {"schema", "plan", "template_id", "template_sha256", "revision", "bindings", "bundle_sha256"}
            if not isinstance(saved, dict) or set(saved) != fields or saved["schema"] != "was.plan-instantiation/1" or not isinstance(saved["template_id"], str) or not _ID.fullmatch(saved["template_id"]) or type(saved["revision"]) is not int or not 1 <= saved["revision"] <= LIMITS["revisions_per_template"]:
                _bad()
            if any(not isinstance(saved[k], str) or not _HASH.fullmatch(saved[k]) for k in ("template_sha256", "bundle_sha256")):
                _bad()
            catalog = library(store, project_id)
            if saved["template_id"].startswith("was-"):
                original = next((t for t in catalog["templates"] if t["id"] == saved["template_id"]), None)
                if original is None or saved["revision"] != 1 or saved["bundle_sha256"] != catalog["bundle_sha256"]:
                    _bad()
            else:
                revisions = _index(store, project_id).get(saved["template_id"], [])
                revision = saved["revision"]
                if revision > len(revisions):
                    _bad()
                original = _revision(store, project_id, saved["template_id"], revisions[revision - 1], revision,
                                     revisions[revision - 2] if revision > 1 else None)
            if original["template_sha256"] != saved["template_sha256"]:
                _bad()
            bindings = saved["bindings"]
            if not isinstance(bindings, dict) or set(bindings) != set(_slots(original["plan"])):
                _bad()
            concrete = json.loads(encode(original["plan"]))
            for slot, value in bindings.items():
                if not isinstance(value, dict) or set(value) != {"evidence_id", "sha256"}:
                    _bad()
                bound = store.evidence(project_id, value["evidence_id"])
                store.read_evidence(project_id, bound["id"])
                if bound["size"] > 4 * 1024 * 1024 or bound["sha256"] != value["sha256"]:
                    _bad()
            if record["parent_id"] != bindings[sorted(bindings)[0]]["evidence_id"]:
                _bad()
            for node in concrete["nodes"]:
                if "slot" in node["input"]:
                    node["input"] = {"evidence_id": bindings[node["input"]["slot"]]["evidence_id"]}
            normalized = plans.validate(concrete)
            if encode(normalized) != encode(saved["plan"]) or encode(normalized) != encode(plans.validate(plan)):
                _bad()
            return {"evidence_id": evidence_id, "sha256": record["sha256"], "template_id": saved["template_id"],
                    "template_sha256": saved["template_sha256"], "revision": saved["revision"], "bundle_sha256": saved["bundle_sha256"]}
    except (Problem, ValueError, TypeError, KeyError, IndexError, UnicodeError, RecursionError):
        _bad("مصدر ربط القالب أو الأدلة أو الخطة تغير", 409)
