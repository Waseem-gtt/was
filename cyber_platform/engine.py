"""Allowlisted evidence workflows with explicit, persisted acceptance outcomes."""
import hashlib
import json
import time
from pathlib import Path
from . import __version__, tools
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


def run(store, project_id, steps, name="تحليل محلي"):
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
    job_id, created, results = uid(), time.time(), []
    fingerprint = hashlib.sha256(Path(__file__).read_bytes() + Path(tools.__file__).read_bytes()).hexdigest()
    spec = {"version": __version__, "engine_sha256": fingerprint, "steps": steps, "sha256": hashlib.sha256(encode(steps).encode()).hexdigest()}
    with store.lock, store.db:
        store.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)", (job_id, project_id, name, "running", encode(spec), "[]", created))
        store.audit("job.started", {"id": job_id, "project": project_id})
    status = "succeeded"
    for i, step in enumerate(steps):
        started = time.monotonic()
        eid = step.get("evidence_id") or results[step["from_step"]]["evidence_id"]
        try:
            data = store.read_evidence(project_id, eid)
            result = tools.analyze(step["tool"], data)
            checks = accepts(result, step.get("expect", {}))
            accepted = all(c["passed"] for c in checks)
            output = {"tool": step["tool"], "engine_version": __version__, "engine_sha256": fingerprint, "input_evidence": eid,
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
        store.audit("job.finished", {"id": job_id, "status": status, "executed": len(results), "planned": len(steps)})
    return {"id": job_id, "status": status, "results": results, "planned": len(steps), "executed": len(results)}
