"""Bounded synthetic regression checks; no evidence inputs or arbitrary suites."""
import base64
import hashlib
import json
import math
import re
import stat
import threading
import time
from pathlib import Path
from . import __version__, tools, worker
from .store import Problem, encode, uid
from .integrity import _directories

PREFIX = "quality.run."
LIMITS = {"cases": 50, "runs": 20, "batch_cases": 3, "batch_seconds": 3,
          "worker_seconds": 3, "worker_cpu_seconds": 3, "worker_memory_bytes": 384 * 1024 * 1024, "input_bytes": 65536}
NOTICE = "اختبارات انحدار اصطناعية ثابتة؛ لا تستخدم أدلة المالك ولا تقيس تغطية كل تخصص أو تثبت أمان النظام. مهلة الدفعة تفحص بين الحالات؛ لكل عامل مهلة مستقلة. النتائج تتحقق من حقول مختارة وقوائم كاملة؛ الذاكرة حد مفروض وليست قياسًا للاستهلاك."
_LOCK = threading.Lock()
_HEX = re.compile(r"[a-f0-9]{64}")


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _matches(actual, expected):
    """Object subsets, exact ordered lists and exact scalar types."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return all(k in actual and _matches(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(_matches(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _suite():
    path = Path(__file__).with_name("quality_cases.json")
    raw = path.read_bytes()
    if len(raw) > 256 * 1024:
        raise Problem("حجم مجموعة الجودة غير صالح", 409)
    try:
        suite = json.loads(raw)
        cases = suite["cases"]
        if set(suite) != {"schema", "cases"} or suite["schema"] != "was.quality-cases/1" or not isinstance(cases, list) or not 1 <= len(cases) <= LIMITS["cases"]:
            raise ValueError("suite")
        ids = set()
        for case in cases:
            if not isinstance(case, dict):
                raise ValueError("case")
            inp = "input_utf8" if "input_utf8" in case else "input_base64"
            expectation = {"reject", "error_message"} if "reject" in case else {"expected"}
            if set(case) != {"id", "tool", "title", inp} | expectation:
                raise ValueError("fields")
            if not isinstance(case["id"], str) or not re.fullmatch(r"[a-z0-9-]{1,80}", case["id"]) or case["id"] in ids or case["tool"] not in tools.REGISTRY or not isinstance(case["title"], str) or not 1 <= len(case["title"]) <= 200:
                raise ValueError("identity")
            ids.add(case["id"])
            if not isinstance(case[inp], str) or len(case[inp]) > LIMITS["input_bytes"] * 2:
                raise ValueError("input type")
            data = _input(case)
            if len(data) > LIMITS["input_bytes"]:
                raise ValueError("input")
            if "reject" in case and (case["reject"] != "ValueError" or not isinstance(case["error_message"], str) or not 1 <= len(case["error_message"]) <= 300):
                raise ValueError("rejection")
            if "expected" in case and (not isinstance(case["expected"], dict) or not case["expected"]):
                raise ValueError("expected")
            encode(case)
        if {c["tool"] for c in cases} != set(tools.REGISTRY):
            raise ValueError("coverage")
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        raise Problem("مجموعة الجودة الثابتة غير صالحة", 409) from exc
    return cases, hashlib.sha256(raw).hexdigest()


def _input(case):
    if "input_utf8" in case:
        return case["input_utf8"].encode("utf-8")
    return base64.b64decode(case["input_base64"], validate=True)


def _engine():
    root = Path(__file__).parent
    return _digest({"version": __version__, "files": {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("quality.py", "tools.py", "worker.py")}})


def catalog():
    cases, suite = _suite()
    return {"suite_sha256": suite, "engine_sha256": _engine(),
            "cases": [{k: c[k] for k in ("id", "tool", "title")} for c in cases],
            "limits": dict(LIMITS), "notice": NOTICE}


def _manifest(cases):
    return [{"case_id": c["id"], "tool": c["tool"],
             "input_sha256": hashlib.sha256(_input(c)).hexdigest(),
             "expected_sha256": _digest({k: c[k] for k in ("expected", "reject", "error_message") if k in c})}
            for c in cases]


def _guard(store):
    try:
        _storage_guard(store)
    except OSError:
        raise Problem("تغيّر التخزين؛ أوقف فحص الجودة", 409) from None


def _storage_guard(store):
    for name, path in (("root", store.root), ("platform.db", store.root / "platform.db")):
        info = path.stat(follow_symlinks=False)
        good = stat.S_ISDIR(info.st_mode) if name == "root" else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        if not good or (info.st_dev, info.st_ino) != tuple(store.storage_identity[name]):
            raise Problem("تغيّر التخزين؛ أوقف فحص الجودة", 409)
    if not store.verify_audit()["valid"]:
        raise Problem("سلسلة التدقيق غير سليمة", 409)


def _save(store, run, action):
    run["updated"] = time.time()
    run["record_sha256"] = _digest({k: v for k, v in run.items() if k != "record_sha256"})
    # Share the integrity subsystem's pinned-directory/database identity guard.
    with store.lock, store.db, _directories(store) as (_, validate):
        _guard(store)
        store.db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (PREFIX + run["id"], encode(run)))
        store.audit(action, {"id": run["id"], "completed": run["counts"]["completed"], "status": run["status"]})
        validate()


def _invalid():
    raise Problem("تقرير الجودة المحفوظ غير صالح أو غير متسق", 409)


def _hash(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _load(store, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise Problem("معرف فحص الجودة غير صالح", 400)
    try:
        run = store.setting(PREFIX + identifier)
        if run is None:
            raise Problem("فحص الجودة غير موجود", 404)
        fields = {"schema", "id", "created", "updated", "version", "suite_sha256", "engine_sha256", "manifest", "manifest_sha256", "status", "passed", "counts", "results", "in_flight", "notice", "record_sha256"}
        if not isinstance(run, dict) or not fields <= set(run) or set(run) - fields - {"error_code"} or run["schema"] != "was.quality-run/1" or run["id"] != identifier or not _hash(run["record_sha256"]) or run["record_sha256"] != _digest({k: v for k, v in run.items() if k != "record_sha256"}):
            _invalid()
        if any(type(run[k]) not in (int, float) or not math.isfinite(run[k]) or run[k] <= 0 for k in ("created", "updated")) or run["updated"] < run["created"] or not isinstance(run["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", run["version"]):
            _invalid()
        if any(not _hash(run[k]) for k in ("suite_sha256", "engine_sha256", "manifest_sha256")) or run["status"] not in ("pending", "running", "completed", "failed") or type(run["passed"]) is not bool:
            _invalid()
        manifest, results, counts = run["manifest"], run["results"], run["counts"]
        if not isinstance(manifest, list) or not 1 <= len(manifest) <= LIMITS["cases"] or _digest(manifest) != run["manifest_sha256"] or not isinstance(results, list) or len(results) > len(manifest) or not isinstance(counts, dict) or set(counts) != {"total", "completed", "passed", "failed"} or any(type(n) is not int or not 0 <= n <= LIMITS["cases"] for n in counts.values()):
            _invalid()
        ids = set()
        for m in manifest:
            if not isinstance(m, dict) or set(m) != {"case_id", "tool", "input_sha256", "expected_sha256"} or not isinstance(m["case_id"], str) or not re.fullmatch(r"[a-z0-9-]{1,80}", m["case_id"]) or m["case_id"] in ids or not isinstance(m["tool"], str) or not re.fullmatch(r"[a-z0-9-]{1,80}", m["tool"]) or not _hash(m["input_sha256"]) or not _hash(m["expected_sha256"]):
                _invalid()
            ids.add(m["case_id"])
        for i, result in enumerate(results):
            fields = {"case_id", "tool", "status", "elapsed_ms", "input_sha256", "expected_sha256", "result_sha256"}
            if not isinstance(result, dict) or not fields <= set(result) or set(result) - fields - {"error_code"} or any(result[k] != manifest[i][k] for k in manifest[i]) or result["status"] not in ("passed", "failed") or type(result["elapsed_ms"]) is not int or not 0 <= result["elapsed_ms"] <= 3600000 or not _hash(result["result_sha256"]):
                _invalid()
            if (result["status"] == "failed") != ("error_code" in result) or "error_code" in result and result["error_code"] not in ("expectation_mismatch", "expected_rejection_missing", "worker_error"):
                _invalid()
        expected_counts = {"total": len(manifest), "completed": len(results), "passed": sum(r["status"] == "passed" for r in results), "failed": sum(r["status"] == "failed" for r in results)}
        if counts != expected_counts or run["passed"] != (run["status"] == "completed" and counts["completed"] == counts["total"] and counts["failed"] == 0):
            _invalid()
        if run["status"] == "completed" and counts["completed"] != counts["total"] or run["status"] == "pending" and (results or run["in_flight"] is not None) or run["status"] == "running" and counts["completed"] == counts["total"]:
            _invalid()
        if run["in_flight"] is not None and (run["status"] != "running" or counts["completed"] >= counts["total"] or run["in_flight"] != manifest[counts["completed"]]["case_id"]):
            _invalid()
        if (run["status"] == "failed") != ("error_code" in run) or "error_code" in run and run["error_code"] not in ("interrupted_case", "engine_changed", "suite_changed"):
            _invalid()
        return run
    except (ValueError, TypeError, KeyError, OverflowError):
        _invalid()


def _public(run):
    return {k: v for k, v in run.items() if k not in ("manifest", "manifest_sha256", "record_sha256", "in_flight")}


def start(store):
    cases, suite = _suite()
    with store.lock, store.db:
        _guard(store)
        runs = [_load(store, row["key"][len(PREFIX):]) for row in store.rows("SELECT key FROM settings WHERE key LIKE ? LIMIT 21", (PREFIX + "%",))]
        if len(runs) > LIMITS["runs"]:
            _invalid()
        if len(runs) >= LIMITS["runs"]:
            terminal = sorted((r for r in runs if r["status"] in ("completed", "failed")), key=lambda r: (r["created"], r["id"]))
            if not terminal:
                raise Problem("يوجد20فحص جودة نشطًا؛ أكمل أحدها أولًا", 409)
            store.db.execute("DELETE FROM settings WHERE key=?", (PREFIX + terminal[0]["id"],))
        now = time.time()
        manifest = _manifest(cases)
        run = {"schema": "was.quality-run/1", "id": uid(), "created": now, "updated": now,
               "version": __version__, "suite_sha256": suite, "engine_sha256": _engine(),
               "manifest": manifest, "manifest_sha256": _digest(manifest), "status": "pending", "passed": False,
               "counts": {"total": len(cases), "completed": 0, "passed": 0, "failed": 0},
               "results": [], "in_flight": None, "notice": NOTICE}
        _save(store, run, "quality.started")
        return _public(run)


def status(store, run_id):
    with store.lock:
        return _public(_load(store, run_id))


def history(store):
    with store.lock:
        rows = store.rows("SELECT key FROM settings WHERE key LIKE ? LIMIT 21", (PREFIX + "%",))
        if len(rows) > LIMITS["runs"]:
            _invalid()
        runs = [_load(store, r["key"][len(PREFIX):]) for r in rows]
        return {"runs": [{k: run[k] for k in ("id", "created", "updated", "version", "status", "passed", "counts", "suite_sha256", "engine_sha256")} for run in sorted(runs, key=lambda r: (r["created"], r["id"]), reverse=True)]}


def _execute(case, manifest):
    result = dict(manifest)
    start_time = time.monotonic()
    code = None
    try:
        actual = worker.analyze(case["tool"], _input(case), timeout=LIMITS["worker_seconds"])
        digest = _digest(actual)
        if "reject" in case:
            code = "expected_rejection_missing"
        elif not _matches(actual, case["expected"]):
            code = "expectation_mismatch"
    except ValueError as exc:
        actual = {"error_type": type(exc).__name__, "message": str(exc)}
        digest = _digest(actual)
        if not ("reject" in case and type(exc) is ValueError and str(exc) == case["error_message"]):
            code = "worker_error"
    except (OSError, RuntimeError, TypeError, KeyError, OverflowError):
        digest = _digest({"error": "worker_error"})
        code = "worker_error"
    result.update(status="failed" if code else "passed", elapsed_ms=min(3600000, max(0, int((time.monotonic() - start_time) * 1000))), result_sha256=digest)
    if code:
        result["error_code"] = code
    return result


def advance(store, run_id):
    if not _LOCK.acquire(blocking=False):
        raise Problem("فحص جودة آخر يعمل الآن", 409)
    try:
        with store.lock:
            _guard(store)
            run = _load(store, run_id)
            if run["status"] in ("completed", "failed"):
                return _public(run)
            cases, suite = _suite()
            error = ("interrupted_case" if run["in_flight"] is not None else
                     "suite_changed" if suite != run["suite_sha256"] or _manifest(cases) != run["manifest"] else
                     "engine_changed" if _engine() != run["engine_sha256"] else None)
            if error:
                run.update(status="failed", passed=False, in_flight=None, error_code=error)
                _save(store, run, "quality.failed")
                return _public(run)
            deadline = time.monotonic() + LIMITS["batch_seconds"]
            checked = 0
            while run["counts"]["completed"] < len(cases) and checked < LIMITS["batch_cases"] and time.monotonic() < deadline:
                current_cases, current_suite = _suite()
                changed = "suite_changed" if current_suite != suite or current_cases != cases else "engine_changed" if _engine() != run["engine_sha256"] else None
                if changed:
                    run.update(status="failed", passed=False, in_flight=None, error_code=changed)
                    _save(store, run, "quality.failed")
                    break
                i = run["counts"]["completed"]
                run.update(status="running", in_flight=cases[i]["id"])
                _save(store, run, "quality.case_started")
                result = _execute(cases[i], run["manifest"][i])
                current_cases, current_suite = _suite()
                changed = "suite_changed" if current_suite != suite or current_cases != cases else "engine_changed" if _engine() != run["engine_sha256"] else None
                if changed:
                    run.update(status="failed", passed=False, in_flight=None, error_code=changed)
                    _save(store, run, "quality.failed")
                    break
                run["results"].append(result)
                run["counts"]["completed"] += 1
                run["counts"][result["status"]] += 1
                run["in_flight"] = None
                checked += 1
                if run["counts"]["completed"] == len(cases):
                    run["status"] = "completed"
                    run["passed"] = run["counts"]["failed"] == 0
                _save(store, run, "quality.case_finished")
            return _public(run)
    finally:
        _LOCK.release()


def compare(store, left_id, right_id):
    with store.lock:
        left, right = _load(store, left_id), _load(store, right_id)
        if left["status"] != "completed" or right["status"] != "completed":
            raise Problem("المقارنة تتطلب فحصين مكتملين", 409)
        if left["suite_sha256"] != right["suite_sha256"] or left["manifest"] != right["manifest"]:
            raise Problem("لا تقارن مجموعتي حالات مختلفتين", 409)
        output = {"left_id": left_id, "right_id": right_id, "suite_sha256": left["suite_sha256"],
                  "engine_changed": left["engine_sha256"] != right["engine_sha256"],
                  "regressions": [], "improvements": [], "unchanged": [], "transitions": [], "notice": NOTICE}
        for a, b in zip(left["results"], right["results"]):
            label = "unchanged" if a["status"] == b["status"] else "regressions" if b["status"] == "failed" else "improvements"
            output[label].append(a["case_id"])
            output["transitions"].append({"case_id": a["case_id"], "tool": a["tool"], "left": a["status"], "right": b["status"]})
        return output
