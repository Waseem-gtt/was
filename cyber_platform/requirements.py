"""Read-only source provenance and reviewed requirements, behind owner auth."""
import hashlib
import json
from pathlib import Path
from .store import Problem

DATA = json.loads((Path(__file__).parent / "requirements.json").read_text())
LABELS = {"available": "مكتمل", "partial": "منفذ جزئيًا", "not_implemented": "غير منفذ",
          "blocked": "متطلب تشغيل غير متحقق", "superseded": "ألغي أو عُدّل", "reference": "مرجع", "historical": "سجل تاريخي"}


def source_bytes():
    raw = "".join(b["text"] for b in DATA["blocks"]).encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != DATA["source"]["sha256"] or len(raw) != DATA["source"]["bytes"]:
        raise Problem("فشل تحقق الملف المرجعي", 409)
    return raw


def view(query="", status="", page=1, mode="requirements"):
    if len(query) > 200 or status not in ("", *LABELS) or mode not in ("requirements", "source"):
        raise Problem("مرشح سجل المتطلبات غير صالح")
    if type(page) is not int or not 1 <= page <= 10000:
        raise Problem("رقم الصفحة غير صالح")
    q = query.casefold()
    items = DATA["requirements"] if mode == "requirements" else DATA["blocks"]
    if mode == "requirements":
        filtered = [r for r in items if (not status or r["status"] == status) and q in " ".join((r["id"], r["title"], r["scope"])).casefold()]
    else:
        filtered = [b for b in items if (not status or b["kind"] == status) and q in (b["heading"] + b["text"]).casefold()]
    size = 25
    return {"source": DATA["source"], "items": filtered[(page - 1) * size:page * size], "matches": len(filtered),
            "page": page, "page_size": size, "mode": mode, "labels": LABELS, "overrides": DATA["overrides"],
            "notice": DATA["notice"], "completion_policy": DATA.get("completion_policy", {}), "owner_added_sections": DATA.get("owner_added_sections", []), "counts": {"source_blocks": len(DATA["blocks"]), "requirements": len(DATA["requirements"]),
            "references": len(DATA["references"]), "mentioned_files": len(DATA["mentioned_files"])}}


def block(block_id):
    result = next((b for b in DATA["blocks"] if b["id"] == block_id), None)
    if result is None:
        raise Problem("المقطع غير موجود", 404)
    return {"block": result, "source": DATA["source"], "notice": DATA["notice"]}


def import_source(store, project_id):
    store.project(project_id)
    raw = source_bytes()
    existing = store.rows("SELECT * FROM evidence WHERE project_id=? AND kind='reference' AND sha256=? ORDER BY created LIMIT 1",
                          (project_id, DATA["source"]["sha256"]))
    if existing:
        store.read_evidence(project_id, existing[0]["id"])
        return {"evidence": existing[0], "reused": True, "notice": DATA["notice"]}
    evidence = store.add_evidence(project_id, DATA["source"]["filename"], raw, "reference")
    return {"evidence": evidence, "reused": False, "notice": DATA["notice"]}
