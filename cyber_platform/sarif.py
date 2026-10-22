"""Bounded offline SARIF 2.1.0 findings and complete normalized comparisons."""
from collections import Counter
import hashlib
from .event_adapters import strict_json
from .store import encode

LIMITS = {"input_bytes": 4 * 1024 * 1024, "runs": 10, "rules": 1000,
          "findings": 2000, "locations_per_finding": 20, "json_depth": 32,
          "json_nodes": 100000, "output_bytes": 3 * 1024 * 1024}
LEVELS = ("error", "warning", "note", "none")
KINDS = {"fail", "pass", "open", "informational", "notApplicable", "review"}
NOTICE = ("توحيد مجموعة موثقة من نتائج SARIF المقدمة، وليس تشغيل فحص كود أو إثبات ثغرة. "
          "المستويات والرسائل والمواقع تصريحات المصدر. لا تصدير snippets أو fixes أو codeFlows أو Markdown، ولا قراءة ملفات أو جلب موارد.")


def _bad(message="Invalid or unsupported SARIF structure"):
    raise ValueError(message)


def _json(data):
    if not isinstance(data, bytes) or len(data) > LIMITS["input_bytes"]:
        _bad("SARIF input exceeds 4 MiB")
    try:
        value = strict_json(data.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid SARIF JSON") from exc
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); nodes += 1
        if nodes > LIMITS["json_nodes"] or depth > LIMITS["json_depth"]:
            _bad("SARIF JSON structure exceeds limits")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    if not isinstance(value, dict):
        _bad("SARIF must be an object")
    return value


def _text(value, maximum=1024, optional=False):
    if optional and value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 and c not in "\n\t\r" for c in value):
        _bad()
    try:
        value.encode("utf-8")
    except UnicodeError:
        _bad()
    return value


def _number(value):
    if type(value) is not int or not 1 <= value <= 2 ** 31 - 1:
        _bad("Invalid SARIF line or column")
    return value


def _location(value, artifacts):
    if not isinstance(value, dict) or "physicalLocation" not in value or not isinstance(value["physicalLocation"], dict):
        _bad("Only SARIF physical locations are supported")
    physical = value["physicalLocation"]
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict) or "uriBaseId" in artifact:
        _bad("SARIF URI base references are unsupported")
    uri = artifact.get("uri")
    if "index" in artifact:
        index = artifact["index"]
        if type(index) is not int or not 0 <= index < len(artifacts):
            _bad("Invalid SARIF artifact index")
        item = artifacts[index]
        if not isinstance(item, dict) or not isinstance(item.get("location"), dict) or "uriBaseId" in item["location"]:
            _bad("Unsupported SARIF artifact location")
        indexed_uri = _text(item["location"].get("uri"), 2048)
        if uri is not None and uri != indexed_uri:
            _bad("Conflicting SARIF artifact URI")
        uri = indexed_uri
    uri = _text(uri, 2048)
    if any(ord(c) < 32 or ord(c) == 127 for c in uri):
        _bad("Invalid SARIF artifact URI")
    region = physical.get("region", {})
    if not isinstance(region, dict) or any(k in region for k in ("byteOffset", "byteLength", "charOffset", "charLength")):
        _bad("SARIF byte or character coordinates are unsupported")
    fields = {"startLine":"start_line", "startColumn":"start_column", "endLine":"end_line", "endColumn":"end_column"}
    result = {"uri": uri, **{target: _number(region[source]) if source in region else None for source, target in fields.items()}}
    if (result["start_column"] is not None or result["end_line"] is not None or result["end_column"] is not None) and result["start_line"] is None:
        _bad("SARIF coordinates require a start line")
    if result["end_line"] is not None and result["end_line"] < result["start_line"]:
        _bad("Reversed SARIF region")
    if result["end_column"] is not None and result["start_column"] is not None and result["end_line"] in (None, result["start_line"]) and result["end_column"] < result["start_column"]:
        _bad("Reversed SARIF region")
    return result


def _finish(value):
    if len(encode(value).encode()) > LIMITS["output_bytes"]:
        _bad("Normalized SARIF output exceeds 3 MiB")
    return value


def analyze(data):
    value = _json(data)
    runs = value.get("runs")
    if value.get("version") != "2.1.0" or not isinstance(runs, list) or not 1 <= len(runs) <= LIMITS["runs"]:
        _bad("Expected SARIF 2.1.0 with 1 to 10 runs")
    findings, rule_count = [], 0
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("tool"), dict) or not isinstance(run["tool"].get("driver"), dict):
            _bad()
        driver = run["tool"]["driver"]
        automation = run.get("automationDetails", {})
        if not isinstance(automation, dict):
            _bad()
        tool = {"name": _text(driver.get("name"), 200), "version": _text(driver.get("version"), 200, True),
                "semantic_version": _text(driver.get("semanticVersion"), 200, True),
                "organization": _text(driver.get("organization"), 200, True),
                "automation_id": _text(automation.get("id"), 500, True),
                "automation_guid": _text(automation.get("guid"), 200, True)}
        rules, results, artifacts = driver.get("rules", []), run.get("results", []), run.get("artifacts", [])
        if not isinstance(rules, list) or not isinstance(results, list) or not isinstance(artifacts, list) or len(artifacts) > LIMITS["findings"]:
            _bad()
        rule_count += len(rules)
        if rule_count > LIMITS["rules"] or len(findings) + len(results) > LIMITS["findings"]:
            _bad("SARIF rules or findings exceed limits")
        indexed = {}
        for rule in rules:
            if not isinstance(rule, dict):
                _bad()
            identifier = _text(rule.get("id"), 500)
            if identifier in indexed:
                _bad("Duplicate SARIF rule identifier")
            configuration = rule.get("defaultConfiguration", {})
            if not isinstance(configuration, dict) or configuration.get("level", "warning") not in LEVELS:
                _bad("Invalid SARIF default level")
            indexed[identifier] = configuration.get("level", "warning")
        for result in results:
            if not isinstance(result, dict) or "rule" in result:
                _bad("SARIF rule object references are unsupported")
            rid = result.get("ruleId")
            if "ruleIndex" in result:
                index = result["ruleIndex"]
                if type(index) is not int or not 0 <= index < len(rules):
                    _bad("Invalid SARIF rule index")
                indexed_id = rules[index]["id"]
                if rid is not None and rid != indexed_id:
                    _bad("Conflicting SARIF rule identity")
                rid = indexed_id
            rid = _text(rid, 500)
            if indexed and rid not in indexed:
                _bad("Unknown SARIF rule identifier")
            level = result.get("level", indexed.get(rid, "warning"))
            kind = result.get("kind", "fail")
            if not isinstance(level, str) or level not in LEVELS or not isinstance(kind, str) or kind not in KINDS:
                _bad("Invalid SARIF level or kind")
            message = result.get("message")
            if not isinstance(message, dict) or "text" not in message or "arguments" in message:
                _bad("SARIF plain message text is required")
            message = _text(message["text"], 4096)
            locations = result.get("locations", [])
            if not isinstance(locations, list) or len(locations) > LIMITS["locations_per_finding"]:
                _bad("SARIF locations exceed limits")
            locations = [_location(location, artifacts) for location in locations]
            identity = {"tool":tool, "rule_id":rid, "kind":kind, "message":message, "locations":locations}
            fingerprint = hashlib.sha256(encode(identity).encode()).hexdigest()
            findings.append({"fingerprint":fingerprint, **identity, "level":level})
    findings.sort(key=lambda f: (f["fingerprint"], LEVELS.index(f["level"])))
    return _finish({"schema":"was.sarif-analysis/1", "run_count":len(runs), "finding_count":len(findings),
                    "findings":findings, "summary":{level:sum(f["level"] == level for f in findings) for level in LEVELS},
                    "source_sha256":hashlib.sha256(data).hexdigest(), "network":False, "snippets_exported":False,
                    "limits":dict(LIMITS), "limitations":NOTICE})


def analyze_diff(data):
    bundle = _json(data)
    if set(bundle) != {"left", "right"} or any(not isinstance(bundle[k], dict) for k in bundle):
        _bad("SARIF comparison requires exactly left and right objects")
    left, right = [analyze(encode(bundle[k]).encode()) for k in ("left", "right")]
    a, b = [Counter((f["fingerprint"], f["level"]) for f in report["findings"]) for report in (left, right)]
    representatives = {f["fingerprint"]:f for report in (left, right) for f in report["findings"]}
    added, resolved, unchanged, changed = [], [], [], []
    for identity in sorted(set(f[0] for f in a) | set(f[0] for f in b)):
        old = {level:a[identity,level] for level in LEVELS}; new = {level:b[identity,level] for level in LEVELS}
        representative = representatives[identity]
        for level in LEVELS:
            common = min(old[level], new[level]); old[level] -= common; new[level] -= common
            if common:
                unchanged.append({"finding":{**representative,"level":level}, "count":common})
        for old_level in LEVELS:
            for new_level in LEVELS:
                count = min(old[old_level], new[new_level])
                if count:
                    old[old_level] -= count; new[new_level] -= count
                    changed.append({"finding":{**representative,"level":new_level}, "from_level":old_level, "to_level":new_level, "count":count})
        for level in LEVELS:
            if old[level]:
                resolved.append({"finding":{**representative,"level":level}, "count":old[level]})
            if new[level]:
                added.append({"finding":{**representative,"level":level}, "count":new[level]})
    groups = {"added":added, "resolved":resolved, "unchanged":unchanged, "severity_changed":changed}
    counts = {key:sum(row["count"] for row in rows) for key, rows in groups.items()}
    return _finish({"schema":"was.sarif-diff/1", "complete":True, **groups, "counts":counts,
                    "normalized_findings_equal":not (added or resolved or changed),
                    "left_sha256":left["source_sha256"], "right_sha256":right["source_sha256"],
                    "source_bundle_sha256":hashlib.sha256(data).hexdigest(), "embedded_document_encoding":"canonical_json",
                    "network":False, "notice":"مقارنة كاملة للحقول الموحدة المدعومة مع احتساب التكرار؛ resolved تعني غياب ادعاء عن المصدر التالي، لا إثبات إصلاح. ليست مساواة كل حقول المصدر أو بايتاته."})


def sample():
    return {"version":"2.1.0", "runs":[{"tool":{"driver":{"name":"synthetic-scanner", "version":"1.0.0",
            "rules":[{"id":"SYN001", "defaultConfiguration":{"level":"warning"}}]}},
            "results":[{"ruleId":"SYN001", "message":{"text":"Synthetic missing validation"},
                        "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/example.py"}, "region":{"startLine":12}}}]}]}]}


def diff_sample():
    left, right = sample(), sample()
    right["runs"][0]["results"][0]["level"] = "error"
    return {"left":left, "right":right}
