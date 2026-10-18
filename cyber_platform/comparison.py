"""Bounded semantic differences between verified analysis-result artifacts."""
import json
from .store import Problem, encode


def differences(left, right, max_changes=100, max_nodes=10000):
    changes, visited, truncated = [], 0, False

    def preview(value):
        if isinstance(value, dict):
            return {"type": "object", "keys": len(value)}
        if isinstance(value, list):
            return {"type": "array", "items": len(value)}
        return value[:500] + "…" if isinstance(value, str) and len(value) > 500 else value

    def walk(a, b, path, depth):
        nonlocal visited, truncated
        if visited >= max_nodes or len(changes) >= max_changes or depth > 64:
            truncated = True
            return False
        visited += 1
        if type(a) is not type(b):
            changes.append({"path": path or "/", "kind": "type_changed", "before": preview(a), "after": preview(b)})
        elif isinstance(a, dict):
            for key in a:
                pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
                if key not in b:
                    if len(changes) >= max_changes:
                        truncated = True
                        return False
                    changes.append({"path": pointer, "kind": "removed", "before": preview(a[key])})
                elif not walk(a[key], b[key], pointer, depth + 1):
                    return False
            for key in b:
                if key not in a:
                    if len(changes) >= max_changes:
                        truncated = True
                        return False
                    changes.append({"path": path + "/" + key.replace("~", "~0").replace("/", "~1"), "kind": "added", "after": preview(b[key])})
        elif isinstance(a, list):
            for i in range(max(len(a), len(b))):
                if len(changes) >= max_changes or visited >= max_nodes:
                    truncated = True
                    return False
                if i >= len(a):
                    changes.append({"path": path + "/" + str(i), "kind": "added", "after": preview(b[i])})
                elif i >= len(b):
                    changes.append({"path": path + "/" + str(i), "kind": "removed", "before": preview(a[i])})
                elif not walk(a[i], b[i], path + "/" + str(i), depth + 1):
                    return False
        elif a != b:
            changes.append({"path": path or "/", "kind": "changed", "before": preview(a), "after": preview(b)})
        return True

    walk(left, right, "", 0)
    return {"changes": changes, "changes_shown": len(changes), "visited_nodes": visited, "truncated": truncated,
            "equal": not changes and not truncated, "limits": {"max_changes": max_changes, "max_nodes": max_nodes, "max_depth": 64}}


def compare(store, project_id, left_id, right_id):
    store.project(project_id)
    records, outputs = [], []
    for eid in (left_id, right_id):
        record = store.evidence(project_id, eid)
        if record["kind"] != "result":
            raise Problem("اختر نتيجتي تحليل مسجلتين، لا ملفات أصلية", 400)
        try:
            output = json.loads(store.read_evidence(project_id, eid))
            if not isinstance(output, dict) or not {"result", "tool", "input_sha256", "engine_sha256"} <= set(output):
                raise ValueError("Invalid analysis result")
        except (ValueError, TypeError):
            raise Problem("صيغة نتيجة التحليل غير صالحة للمقارنة", 409) from None
        records.append(record)
        outputs.append(output)
    if outputs[0].get("tool") != outputs[1].get("tool"):
        raise Problem("المقارنة تتطلب الأداة نفسها حتى يكون الفرق قابلًا للتفسير", 400)
    result = differences(outputs[0]["result"], outputs[1]["result"])
    result.update({"schema": "was.comparison/1", "tool": outputs[0]["tool"],
                   "sources": [{"id": r["id"], "sha256": r["sha256"]} for r in records],
                   "same_input": outputs[0].get("input_sha256") == outputs[1].get("input_sha256"),
                   "same_engine": outputs[0].get("engine_sha256") == outputs[1].get("engine_sha256"),
                   "limitation": "فرق بنيوي في النتائج؛ لا يثبت أي إصدار أكثر أمنًا أو صحة دون معيار قبول مستقل"})
    evidence = store.add_evidence(project_id, "analysis-comparison.json", encode(result).encode(), "comparison")
    for eid in (left_id, right_id):
        store.link(project_id, eid, evidence["id"], "دخل في مقارنة نتائج")
    with store.lock, store.db:
        store.audit("results.compared", {"project": project_id, "evidence": evidence["id"], "changes_shown": result["changes_shown"], "truncated": result["truncated"]})
    return {"result": result, "evidence": evidence}
