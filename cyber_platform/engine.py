"""Allowlisted evidence workflows with explicit, persisted acceptance outcomes."""
import hashlib
import json
import time
from pathlib import Path
from . import __version__, tools, worker
from .store import Problem, encode, uid


def accepts(result, expected):
    checks = []
    for path, expected_value in expected.items():
        current = result
        try:
            for part in path.split("."):
                current = current[int(part)] if isinstance(current, list) else current[part]
            passed = type(current) is type(expected_value) and current == expected_value
        except (KeyError, IndexError, ValueError, TypeError):
            passed = False
        checks.append({"path": path, "expected": expected_value, "passed": passed})
    return checks


def fingerprint():
    root = Path(__file__).parent
    return hashlib.sha256(b"".join((root / name).read_bytes() for name in
                                 ("engine.py", "tools.py", "worker.py", "event_adapters.py") + tools.ANALYZER_FILES)).hexdigest()


def resume_prefix(store, project_id, job_id, steps, current_fingerprint):
    rows = store.rows("SELECT * FROM jobs WHERE id=? AND project_id=?", (job_id, project_id))
    if not rows:
        raise Problem("المهمة الأصلية غير موجودة في المشروع", 404)
    original = rows[0]
    if original["status"] not in ("failed", "interrupted"):
        raise Problem("الاستكمال لمهمة فاشلة أو متوقفة فقط", 409)
    try:
        spec, results = json.loads(original["spec"]), json.loads(original["results"])
        if spec["engine_sha256"] != current_fingerprint or spec["version"] != __version__:
            raise Problem("تغير المحرك؛ أعد التشغيل الكامل بدل استكمال نتائج إصدار آخر", 409)
        if hashlib.sha256(encode(spec["steps"]).encode()).hexdigest() != spec["sha256"]:
            raise Problem("فشل تحقق خطة المهمة الأصلية", 409)
        reused = []
        for i, item in enumerate(results):
            if item["status"] != "succeeded":
                break
            if i >= len(steps) or item["step"] != i or encode(steps[i]) != encode(spec["steps"][i]):
                raise Problem("لا يمكن تعديل أو حذف خطوة منجزة عند الاستكمال", 409)
            output_id = item["evidence_id"]
            record = store.evidence(project_id, output_id)
            output = json.loads(store.read_evidence(project_id, output_id))
            input_id = steps[i].get("evidence_id") or reused[steps[i]["from_step"]]["evidence_id"]
            input_hash = hashlib.sha256(store.read_evidence(project_id, input_id)).hexdigest()
            checks = accepts(output["result"], steps[i].get("expect", {}))
            acceptance = "passed" if checks else "not_evaluated"
            valid = (record["kind"] == "result" and record["parent_id"] == input_id and
                     output["tool"] == steps[i]["tool"] and output["engine_sha256"] == current_fingerprint and
                     output["input_evidence"] == input_id and output["input_sha256"] == input_hash and
                     output["checks"] == checks and all(c["passed"] for c in checks) and
                     output["acceptance"] == acceptance and encode(item["output"]) == encode(output))
            if not valid:
                raise Problem("فشل تحقق النتيجة المنجزة أو مصدرها؛ أُوقف الاستكمال", 409)
            reused.append({**item, "reused": True})
        if len(reused) >= len(steps):
            raise Problem("لا خطوات متبقية للاستكمال", 409)
        return reused
    except (KeyError, TypeError, ValueError, IndexError):
        raise Problem("بيانات المهمة الأصلية غير صالحة للاستكمال", 409) from None


def run(store, project_id, steps, name="تحليل محلي", resume_id=None):
    store.project(project_id)
    if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
        raise Problem("سير العمل يحتاج 1–20 خطوة")
    if not isinstance(name, str) or not 1 <= len(name) <= 120:
        raise Problem("اسم سير العمل غير صالح")
    for i, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) - {"tool", "evidence_id", "from_step", "expect"} or step.get("tool") not in tools.REGISTRY:
            raise Problem("خطوة أو أداة غير مسموحة")
        if ("evidence_id" in step) == ("from_step" in step):
            raise Problem("حدد دليلًا أو نتيجة خطوة سابقة")
        if "from_step" in step and (type(step["from_step"]) is not int or not 0 <= step["from_step"] < i):
            raise Problem("الخطوة تعتمد على نتيجة سابقة فقط")
        if "evidence_id" in step:
            store.evidence(project_id, step["evidence_id"])
        expected = step.get("expect", {})
        if not isinstance(expected, dict) or len(expected) > 30 or any(not isinstance(k, str) or len(k) > 200 for k in expected):
            raise Problem("معايير القبول غير صالحة")
    engine_hash = fingerprint()
    if resume_id is not None and (not isinstance(resume_id, str) or not resume_id):
        raise Problem("معرف المهمة الأصلية غير صالح")
    results = resume_prefix(store, project_id, resume_id, steps, engine_hash) if resume_id is not None else []
    reused_count = len(results)
    job_id, created = uid(), time.time()
    spec = {"version": __version__, "engine_sha256": engine_hash, "steps": steps, "sha256": hashlib.sha256(encode(steps).encode()).hexdigest(), "resumed_from": resume_id}
    with store.lock, store.db:
        store.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)", (job_id, project_id, name, "running", encode(spec), encode(results), created))
        store.audit("job.started", {"id": job_id, "project": project_id, "resumed_from": resume_id, "reused": reused_count})
    status = "succeeded"
    for i, step in enumerate(steps[reused_count:], start=reused_count):
        started = time.monotonic()
        eid = step.get("evidence_id") or results[step["from_step"]]["evidence_id"]
        try:
            data = store.read_evidence(project_id, eid)
            result = worker.analyze(step["tool"], data)
            if fingerprint() != engine_hash:
                raise Problem("تغير محرك التحليل أثناء التنفيذ؛ لم تحفظ نتيجة", 409)
            checks = accepts(result, step.get("expect", {}))
            accepted = all(c["passed"] for c in checks)
            output = {"tool": step["tool"], "engine_version": __version__, "engine_sha256": engine_hash, "input_evidence": eid,
                      "input_sha256": hashlib.sha256(data).hexdigest(), "result": result,
                      "acceptance": "passed" if checks and accepted else "failed" if not accepted else "not_evaluated", "checks": checks}
            evidence = store.add_evidence(project_id, f"{step['tool']}-{job_id[:8]}-{i + 1}.json", encode(output).encode(), "result", eid)
            store.link(project_id, eid, evidence["id"], "اشتُق من تحليل الدليل")
            item = {"step": i, "tool": step["tool"], "status": "succeeded" if accepted else "failed",
                    "evidence_id": evidence["id"], "output": output}
            if not accepted:
                status = "failed"
        except (Problem, ValueError, TypeError, KeyError, IndexError, OverflowError) as exc:
            status = "failed"
            item = {"step": i, "tool": step["tool"], "status": "failed", "error": str(exc)[:300]}
        item["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        results.append(item)
        with store.lock, store.db:
            store.db.execute("UPDATE jobs SET results=? WHERE id=?", (encode(results), job_id))
        if status == "failed":
            break
    with store.lock, store.db:
        store.db.execute("UPDATE jobs SET status=?,results=? WHERE id=?", (status, encode(results), job_id))
        store.audit("job.finished", {"id": job_id, "status": status, "executed": len(results) - reused_count, "reused": reused_count, "planned": len(steps)})
    return {"id": job_id, "status": status, "results": results, "planned": len(steps), "executed": len(results) - reused_count, "reused": reused_count, "completed": len(results)}
