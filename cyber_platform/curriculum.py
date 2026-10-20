"""Evidence-backed, ordered learning paths on fixed synthetic exercises only."""
import base64
import hashlib
import re
from pathlib import Path

from . import __version__, learning, tools
from .detection import _json, _persist
from .quality import _guard
from .store import Problem, encode

PREFIX = "curriculum.attempts."
LIMITS = {"attempts": 200, "attempts_per_lesson": 20, "assessment_bytes": 32768,
          "progress_read_bytes": 200 * 32768, "worker_seconds": 3,
          "worker_cpu_seconds": 3, "worker_memory_bytes": 384 * 1024 * 1024}
NOTICE = "تقدم في عشرين تمرين فهم ثابت على بيانات اصطناعية؛ لا شهادة إتقان أو تصريح اختبار أو إثبات حماية. نجاح الإجابة يفتح الدرس التالي داخل المسار فقط. تتوقف صلاحية التقدم عند تغير المنهج أو المحلل؛ المحاولات القديمة تبقى محفوظة."
PATHS = (
    ("foundations", "أسس التعامل مع الأدلة", "سلامة الأصل والسياق وحدود الاستنتاج قبل الكشف.", (4, 1, 2, 3)),
    ("investigation", "مراجعة الأنظمة والاتصالات", "تحليل ساكن وتدفقات وهوية وإعدادات حاويات.", (5, 6, 7, 8)),
    ("software", "البرمجيات والبروتوكولات", "الجرد والحدود والتشفير وسلامة البرامج الثابتة.", (9, 10, 11, 12)),
    ("physical", "الأنظمة المادية والإشارات", "حدود النماذج والقياسات والتسجيلات دون اتصال حي.", (13, 14, 15, 16)),
    ("governance", "المصادر والذكاء الاصطناعي والحوكمة", "قراءة الرسائل ومراجعة الاستنتاج والخصوصية ومصدر الإضافات.", (17, 18, 19, 20)),
)
_FIELDS = {"schema", "path_id", "lesson_id", "lesson", "lesson_sha256", "engine_sha256",
           "answer_index", "correct", "exercise", "exercise_sha256", "record_sha256"}
_EXERCISE = {"lesson_id", "answer_index", "correct", "explanation", "tool", "synthetic",
             "input_base64", "input_sha256", "analyzer_sha256", "analysis", "source", "assessment"}


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _bad(message="سجل التقدم التعليمي غير صالح أو تغير", status=409):
    raise Problem(message, status)


def _engine():
    root = Path(__file__).parent
    return _digest({"version": __version__, "files": {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("curriculum.py", "learning.py", "tools.py", "worker.py", "event_adapters.py") + tools.ANALYZER_FILES}})


def catalog():
    return {"schema": "was.curriculum/1", "paths": [
        {"id": pid, "title": title, "description": description,
         "lesson_ids": [f"lesson.{number:02}" for number in numbers]}
        for pid, title, description, numbers in PATHS], "lessons": learning.lessons(),
        "limits": dict(LIMITS), "notice": NOTICE}


def _path(path_id, lesson_id=None):
    if not isinstance(path_id, str):
        _bad("معرف المسار غير صالح", 400)
    path = next((p for p in catalog()["paths"] if p["id"] == path_id), None)
    if path is None:
        _bad("المسار غير موجود", 404)
    if lesson_id is not None and (not isinstance(lesson_id, str) or lesson_id not in path["lesson_ids"]):
        _bad("الدرس لا ينتمي إلى المسار", 400)
    return path


def _index(store, pid):
    saved = store.rows("SELECT value FROM settings WHERE key=?", (PREFIX + pid,))
    index = _json(saved[0]["value"]) if saved else {}
    valid_ids = {lesson["id"] for lesson in learning.lessons()}
    if not isinstance(index, dict) or set(index) - valid_ids:
        _bad()
    seen = set()
    for ids in index.values():
        if not isinstance(ids, list) or not 1 <= len(ids) <= LIMITS["attempts_per_lesson"]:
            _bad()
        for eid in ids:
            if not isinstance(eid, str) or not re.fullmatch(r"[a-f0-9]{32}", eid) or eid in seen:
                _bad()
            seen.add(eid)
    if len(seen) > LIMITS["attempts"]:
        _bad()
    stored = store.rows("SELECT id FROM evidence WHERE project_id=? AND kind=? LIMIT ?",
                        (pid, "learning-assessment", LIMITS["attempts"] + 1))
    if {row["id"] for row in stored} != seen:
        _bad("فهرس المحاولات لا يطابق النتائج المحفوظة")
    return index


def _read(store, pid, lesson_id, eid, engine):
    metadata = store.evidence(pid, eid)
    if metadata["kind"] != "learning-assessment" or metadata["parent_id"] is not None or type(metadata["size"]) is not int or not 0 < metadata["size"] <= LIMITS["assessment_bytes"]:
        _bad()
    details = encode({"project": pid, "id": eid, "sha256": metadata["sha256"]})
    if not store.rows("SELECT seq FROM audit WHERE action=? AND details=? LIMIT 1",
                      ("learning-assessment.created", details)):
        _bad("المحاولة لا تحمل سجل إنشاء موثقًا")
    value = _json(store.read_evidence(pid, eid))
    try:
        if not isinstance(value, dict) or set(value) != _FIELDS or value["schema"] != "was.learning-assessment/1" or value["lesson_id"] != lesson_id:
            _bad()
        if not isinstance(value["path_id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,79}", value["path_id"]):
            _bad()
        current_path = next((p for p in catalog()["paths"] if lesson_id in p["lesson_ids"]), None)
        lesson = value["lesson"]
        exercise = value["exercise"]
        current_lesson = next(l for l in learning.lessons() if l["id"] == lesson_id)
        if not isinstance(lesson, dict) or set(lesson) != set(current_lesson) or lesson["id"] != lesson_id or not isinstance(lesson["choices"], list) or len(lesson["choices"]) != 3 or any(not isinstance(c, str) for c in lesson["choices"]) or lesson["choices"].count(lesson["defense"]) != 1:
            _bad()
        answer = value["answer_index"]
        if type(answer) is not int or not 0 <= answer < 3 or type(value["correct"]) is not bool or value["correct"] != (lesson["choices"][answer] == lesson["defense"]):
            _bad()
        if not isinstance(exercise, dict) or set(exercise) != _EXERCISE or type(exercise["correct"]) is not bool or type(exercise["answer_index"]) is not int or exercise["correct"] != value["correct"] or exercise["answer_index"] != answer or exercise["lesson_id"] != lesson_id or exercise["synthetic"] is not True or exercise["tool"] != lesson["tool_id"] or exercise["source"] != lesson["source"] or exercise["assessment"] != lesson["assessment"] or exercise["explanation"] != lesson["concept"] + " " + lesson["defense"] or not isinstance(exercise["analysis"], dict):
            _bad()
        if not isinstance(exercise["input_base64"], str) or len(exercise["input_base64"]) > 16384 or not _hash(exercise["analyzer_sha256"]):
            _bad()
        data = base64.b64decode(exercise["input_base64"], validate=True)
        if not _hash(exercise["input_sha256"]) or exercise["input_sha256"] != hashlib.sha256(data).hexdigest():
            _bad()
        if any(not _hash(value[k]) for k in ("engine_sha256", "lesson_sha256", "exercise_sha256", "record_sha256")) or value["lesson_sha256"] != _digest(lesson) or value["exercise_sha256"] != _digest(exercise) or value["record_sha256"] != _digest({k: v for k, v in value.items() if k != "record_sha256"}):
            _bad()
        current = value["engine_sha256"] == engine and lesson == current_lesson and current_path is not None and current_path["id"] == value["path_id"]
        if current:
            _, _, fixed = learning.fixture(lesson_id)
            if fixed != data or exercise["analyzer_sha256"] != hashlib.sha256(Path(learning.tools.__file__).read_bytes()).hexdigest():
                _bad()
        return {"evidence_id": eid, "path_id": value["path_id"], "lesson_id": lesson_id,
                "answer_index": answer, "correct": value["correct"], "current": current,
                "created": metadata["created"]}
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        _bad()


def _records(store, pid, engine):
    store.project(pid)
    _guard(store)
    index = _index(store, pid)
    # Index cardinality and per-record size bound the complete proof read to
    # 6.25 MiB. A client-uploaded kind alone never enrolls a result in this index.
    records = [_read(store, pid, lid, eid, engine) for lid, ids in index.items() for eid in ids]
    return records, index


def history(store, project_id):
    with store.lock:
        records, _ = _records(store, project_id, _engine())
        return {"schema": "was.curriculum-history/1",
                "attempts": sorted(records, key=lambda r: (r["created"], r["evidence_id"]), reverse=True),
                "limits": dict(LIMITS), "notice": NOTICE}


def _progress(records, engine):
    lessons = {l["id"]: l for l in learning.lessons()}
    all_counts = dict.fromkeys(("passed", "attempted", "available", "locked", "stale", "total"), 0)
    paths = []
    for path in catalog()["paths"]:
        rows = []
        counts = dict.fromkeys(all_counts, 0)
        unlocked = True
        for lid in path["lesson_ids"]:
            attempts = [r for r in records if r["lesson_id"] == lid]
            current = [r for r in attempts if r["current"]]
            correct = [r for r in current if r["correct"]]
            status = "passed" if correct else "attempted" if current else "stale" if attempts else "available" if unlocked else "locked"
            rows.append({"lesson_id": lid, "title": lessons[lid]["title"], "status": status,
                         "attempts": len(attempts), "correct_attempts": len(correct),
                         "latest_evidence_id": max(attempts, key=lambda r: r["created"])["evidence_id"] if attempts else None})
            unlocked = unlocked and bool(correct)
            counts[status] += 1
            counts["total"] += 1
        for key in counts:
            all_counts[key] += counts[key]
        paths.append({**path, "lessons": rows, "counts": counts})
    return {"schema": "was.curriculum-progress/1", "paths": paths, "counts": all_counts,
            "engine_sha256": engine, "limits": dict(LIMITS), "notice": NOTICE}


def progress(store, project_id):
    with store.lock:
        engine = _engine()
        records, _ = _records(store, project_id, engine)
        return _progress(records, engine)


def attempt(store, project_id, path_id, lesson_id, answer_index):
    path = _path(path_id, lesson_id)
    if type(answer_index) is not int or not 0 <= answer_index < 3:
        _bad("اختر إجابة من الخيارات المسجلة", 400)
    with store.lock:
        engine = _engine()
        records, index = _records(store, project_id, engine)
        prior = path["lesson_ids"][:path["lesson_ids"].index(lesson_id)]
        if any(not any(r["lesson_id"] == lid and r["current"] and r["correct"] for r in records) for lid in prior):
            _bad("أكمل الإجابات الصحيحة للدروس السابقة في المسار أولًا")
        if len(records) >= LIMITS["attempts"] or len(index.get(lesson_id, [])) >= LIMITS["attempts_per_lesson"]:
            _bad("بلغت حد المحاولات المحفوظة؛ لا تحذف النتائج تلقائيًا")
        lesson = next(l for l in learning.lessons() if l["id"] == lesson_id)
        exercise = learning.exercise(lesson_id, answer_index)
        if _engine() != engine:
            _bad("تغير المنهج أثناء التمرين؛ لم تحفظ نتيجة")
        result = {"schema": "was.learning-assessment/1", "path_id": path_id, "lesson_id": lesson_id,
                  "lesson": lesson, "lesson_sha256": _digest(lesson), "engine_sha256": engine,
                  "answer_index": answer_index, "correct": exercise["correct"],
                  "exercise": exercise, "exercise_sha256": _digest(exercise)}
        result["record_sha256"] = _digest(result)
        if len(encode(result).encode()) > LIMITS["assessment_bytes"]:
            _bad("نتيجة التمرين تتجاوز حد الحفظ", 413)
        evidence = _persist(store, project_id, result, "learning-assessment",
                            setting=(PREFIX + project_id, index, lesson_id))
        records.append(_read(store, project_id, lesson_id, evidence["id"], engine))
        return {"result": result, "evidence": evidence, "progress": _progress(records, engine)}
