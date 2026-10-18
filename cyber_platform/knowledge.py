"""Public global knowledge, private snapshots. No project data leaves the host."""
import hashlib
import json
import time
import urllib.request
from .store import Problem, encode

SOURCES = [{"id": "cisa-kev", "name": "CISA Known Exploited Vulnerabilities", "publisher": "CISA",
            "url": "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
            "reference": "https://github.com/cisagov/kev-data", "kind": "public-vulnerability-catalog"}]


def setting(store, key, value):
    with store.lock, store.db:
        store.db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, encode(value)))


def download(source):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None
    request = urllib.request.Request(source["url"], headers={"Accept": "application/json", "User-Agent": "WAS-Knowledge/0.2"})
    # Keep inherited proxy and TLS trust. No cookies, credentials, queries or
    # project fields are added. The source is fixed in code, never owner input.
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=20) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("Source exceeds 4 MiB")
    return data


def validate(data):
    value = json.loads(data)
    rows = value.get("vulnerabilities")
    if not isinstance(rows, list) or len(rows) > 20000 or not all(isinstance(r, dict) and isinstance(r.get("cveID"), str) for r in rows):
        raise ValueError("Invalid CISA catalog structure")
    if not isinstance(value.get("catalogVersion"), str) or len(value["catalogVersion"]) > 100:
        raise ValueError("Invalid catalog version")
    if value.get("count") != len(rows):
        raise ValueError("Catalog count mismatch")
    return value


def refresh(store, project_id, source_id="cisa-kev", loader=None):
    store.project(project_id)
    source = next((s for s in SOURCES if s["id"] == source_id), None)
    if not source:
        raise Problem("المصدر غير مسجل", 404)
    key = f"knowledge:{project_id}:{source_id}"
    previous = store.setting(key, {})
    checked = time.time()
    try:
        data = (loader or download)(source)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("Source exceeds limit")
        value = validate(data)
        digest = hashlib.sha256(data).hexdigest()
        changed = digest != previous.get("sha256")
        if not changed:
            store.read_evidence(project_id, previous["evidence_id"])
        else:
            evidence = store.add_evidence(project_id, f"{source_id}-{value['catalogVersion'].replace('/', '-')[:60]}.json", data, "knowledge")
        state = {"source_id": source_id, "source_url": source["url"], "publisher": source["publisher"], "project_id": project_id, "checked_at": checked, "success_at": checked,
                 "changed_at": checked if changed else previous["changed_at"], "changed": changed, "stale": False,
                 "evidence_id": evidence["id"] if changed else previous["evidence_id"], "sha256": digest,
                 "version": value["catalogVersion"], "published": value.get("dateReleased"), "count": len(value["vulnerabilities"])}
        setting(store, key, state)
        with store.lock, store.db:
            store.audit("knowledge.checked", {"project": project_id, "source": source_id, "changed": changed, "sha256": digest})
        return state
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, Problem):
        state = {**previous, "source_id": source_id, "project_id": project_id, "checked_at": checked, "changed": False,
                 "stale": True, "error": "تعذر جلب المصدر أو التحقق منه؛ بقيت اللقطة السابقة دون تغيير"}
        setting(store, key, state)
        with store.lock, store.db:
            store.audit("knowledge.failed", {"project": project_id, "source": source_id})
        raise Problem(state["error"], 503) from None


def status(store, project_id):
    store.project(project_id)
    return {"sources": SOURCES, "states": [store.setting(f"knowledge:{project_id}:{s['id']}", {"source_id": s["id"], "stale": True}) for s in SOURCES],
            "schedule": store.setting("knowledge_schedule", {"enabled": False, "interval_seconds": 60}),
            "privacy": "طلبات GET عامة إلى مصادر مسجلة فقط؛ لا أسئلة أو أدلة أو أسماء مشاريع في الطلب",
            "limitation": "فهرس CISA لا يحصر جميع الثغرات، وروابط التقنيات لا تعني تنزيل أدواتها أو تحديثها"}


def search(store, project_id, query):
    store.project(project_id)
    if not isinstance(query, str) or len(query) > 120:
        raise Problem("حد البحث 120 حرفًا")
    state = store.setting(f"knowledge:{project_id}:cisa-kev", {})
    if not state.get("evidence_id"):
        return {"items": [], "total_matches": 0, "state": state}
    value = validate(store.read_evidence(project_id, state["evidence_id"]))
    q = query.casefold()
    matches = [r for r in value["vulnerabilities"] if q in " ".join(str(r.get(k, "")) for k in ("cveID", "vendorProject", "product", "vulnerabilityName")).casefold()]
    return {"items": matches[:50], "total_matches": len(matches), "state": state, "limit": 50}


def configure(store, project_id, enabled, interval):
    store.project(project_id)
    if type(enabled) is not bool or type(interval) is not int or not 60 <= interval <= 86400:
        raise Problem("الفاصل من60إلى86400ثانية، وحالة التشغيل قيمة منطقية")
    value = {"project_id": project_id, "enabled": enabled, "interval_seconds": interval, "next_at": time.time()}
    setting(store, "knowledge_schedule", value)
    with store.lock, store.db:
        store.audit("knowledge.schedule", {"project": project_id, "enabled": enabled, "interval": interval})
    return value


def scheduled_tick(store, now=None, loader=None):
    config = store.setting("knowledge_schedule", {})
    now = time.time() if now is None else now
    if not config.get("enabled") or config.get("next_at", 0) > now:
        return False
    # One catch-up request after downtime, never a burst of missed intervals.
    config["next_at"] = now + config["interval_seconds"]
    setting(store, "knowledge_schedule", config)
    try:
        refresh(store, config["project_id"], loader=loader)
    except Problem:
        pass  # Failure state and previous snapshot are already persisted.
    return True
