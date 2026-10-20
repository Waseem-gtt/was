"""Bounded offline SPDX/CycloneDX metadata analysis; never install components."""
import hashlib
import re

from .event_adapters import strict_json
from .store import encode

LIMITS = {"input_bytes": 4 * 1024 * 1024, "components": 1000, "dependencies": 5000,
          "vulnerabilities": 1000, "json_nodes": 100000, "json_depth": 32}
LIMITATIONS = ("تحليل جزئي لبيانات SPDX2.3 وCycloneDX1.5/1.6 المرفوعة؛ "
               "التراخيص والبصمات والثغرات تصريحات المصدر وليست تحقق ناشر أو حقوق قانونية. "
               "لا تنزيل أو تثبيت أو بحث حي عن CVE؛ غياب تصريح ثغرة لا يثبت خلو المكونات منها.")
_HASH_LENGTH = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96,
                "SHA-512": 128, "SHA3-256": 64, "SHA3-384": 96, "SHA3-512": 128,
                "BLAKE2b-256": 64, "BLAKE2b-384": 96, "BLAKE2b-512": 128, "BLAKE3": 64}
_SPDX_HASH = {"MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384",
              "SHA512": "SHA-512", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512"}


def _bad(message):
    raise ValueError(message)


def _text(value, label, maximum=2048, optional=False):
    if optional and value in (None, ""):
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _bad("Invalid " + label)
    try:
        value.encode("utf-8")
    except UnicodeError:
        _bad("Invalid UTF-8 " + label)
    return value


def _array(value, label, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        _bad("Invalid or oversized " + label)
    return value


def _bounded_json(data):
    if not isinstance(data, bytes) or len(data) > LIMITS["input_bytes"]:
        _bad("SBOM input exceeds 4 MiB")
    try:
        value = strict_json(data.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid SBOM JSON") from exc
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > LIMITS["json_depth"] or count > LIMITS["json_nodes"]:
            _bad("SBOM JSON structure exceeds limits")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    if not isinstance(value, dict):
        _bad("SBOM must be a JSON object")
    return value


def _purl(value):
    value = _text(value, "package URL", optional=True)
    if value is not None and (not re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/\S+", value) or any(c.isspace() for c in value)):
        _bad("Invalid package URL; this analyzer does not resolve package URLs")
    return value


def _hashes(items, spdx=False):
    result = {}
    for item in _array(items, "checksums", 20):
        if not isinstance(item, dict):
            _bad("Invalid checksum")
        algorithm = _text(item.get("algorithm" if spdx else "alg"), "checksum algorithm", 40)
        algorithm = _SPDX_HASH.get(algorithm) if spdx else algorithm
        value = _text(item.get("checksumValue" if spdx else "content"), "checksum value", 128)
        if algorithm not in _HASH_LENGTH or not re.fullmatch("[a-fA-F0-9]{" + str(_HASH_LENGTH[algorithm]) + "}", value):
            _bad("Unsupported checksum algorithm or invalid checksum length")
        if algorithm in result:
            _bad("Duplicate checksum algorithm")
        result[algorithm] = value.lower()
    return dict(sorted(result.items()))


def _cdx_licenses(items):
    result = []
    for item in _array(items, "licenses", 20):
        if not isinstance(item, dict) or set(item) - {"license", "expression", "bom-ref"}:
            _bad("Unsupported CycloneDX license choice")
        if ("license" in item) == ("expression" in item):
            _bad("License choice must contain license or expression")
        if "expression" in item:
            result.append(_text(item["expression"], "license expression", 500))
        else:
            license_value = item["license"]
            if not isinstance(license_value, dict) or ("id" in license_value) == ("name" in license_value):
                _bad("License requires exactly one identifier or name")
            result.append(_text(license_value.get("id", license_value.get("name")), "license", 500))
    return sorted(set(result))


def _spdx_licenses(item):
    result = []
    for key in ("licenseConcluded", "licenseDeclared"):
        value = _text(item.get(key), key, 500, optional=True)
        if value and value not in ("NOASSERTION", "NONE"):
            result.append(value)
    return sorted(set(result))


def _cdx(value):
    if value.get("specVersion") not in ("1.5", "1.6"):
        _bad("Only CycloneDX 1.5 and 1.6 JSON subsets are supported")
    components, pending = [], list(reversed(_array(value.get("components", []), "components", LIMITS["components"])))
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        _bad("Invalid CycloneDX metadata")
    if "component" in metadata:
        pending.append(metadata["component"])
    while pending:
        item = pending.pop()
        if not isinstance(item, dict):
            _bad("Invalid CycloneDX component")
        components.append({"id": _text(item.get("bom-ref"), "component bom-ref", 256),
                           "name": _text(item.get("name"), "component name", 300),
                           "version": _text(item.get("version"), "component version", 300, optional=True),
                           "licenses": _cdx_licenses(item.get("licenses", [])),
                           "purl": _purl(item.get("purl")), "hashes": _hashes(item.get("hashes", []))})
        nested = _array(item.get("components", []), "nested components", LIMITS["components"])
        pending.extend(reversed(nested))
        if len(components) + len(pending) > LIMITS["components"]:
            _bad("SBOM exceeds component limit")
    edges = []
    component_ids = {c["id"] for c in components}
    for group in _array(value.get("dependencies", []), "dependency groups", LIMITS["dependencies"]):
        if not isinstance(group, dict) or set(group) - {"ref", "dependsOn"}:
            _bad("Unsupported CycloneDX dependency fields")
        source = _text(group.get("ref"), "dependency source", 256)
        for target in _array(group.get("dependsOn", []), "dependency targets", LIMITS["dependencies"]):
            edges.append((source, _text(target, "dependency target", 256)))
            if len(edges) > LIMITS["dependencies"]:
                _bad("SBOM exceeds dependency limit")
        # Empty dependency declarations still identify a real component.
        if not group.get("dependsOn", []) and source not in component_ids:
            _bad("Unknown dependency source")
    return components, edges, "CycloneDX-" + value["specVersion"], 0


def _spdx(value):
    if value.get("spdxVersion") != "SPDX-2.3":
        _bad("Only SPDX 2.3 JSON subsets are supported")
    components = []
    for item in _array(value.get("packages", []), "packages", LIMITS["components"]):
        if not isinstance(item, dict):
            _bad("Invalid SPDX package")
        purls = []
        for reference in _array(item.get("externalRefs", []), "external references", 50):
            if not isinstance(reference, dict):
                _bad("Invalid SPDX external reference")
            if reference.get("referenceType") == "purl":
                locator = _text(reference.get("referenceLocator"), "package URL reference")
                purls.append(_purl(locator))
        if len(purls) > 1:
            _bad("Duplicate package URL reference")
        identifier = _text(item.get("SPDXID"), "SPDX package identifier", 256)
        if not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", identifier):
            _bad("Invalid SPDX package identifier")
        components.append({"id": identifier,
                           "name": _text(item.get("name"), "package name", 300),
                           "version": _text(item.get("versionInfo"), "package version", 300, optional=True),
                           "licenses": _spdx_licenses(item), "purl": purls[0] if purls else None,
                           "hashes": _hashes(item.get("checksums", []), True)})
    edges, ignored = [], 0
    for relationship in _array(value.get("relationships", []), "relationships", LIMITS["dependencies"]):
        if not isinstance(relationship, dict):
            _bad("Invalid SPDX relationship")
        relation = _text(relationship.get("relationshipType"), "relationship type", 80)
        source = _text(relationship.get("spdxElementId"), "relationship source", 256)
        target = _text(relationship.get("relatedSpdxElement"), "relationship target", 256)
        if relation == "DEPENDS_ON":
            edges.append((source, target))
        elif relation == "DEPENDENCY_OF":
            edges.append((target, source))
        else:
            ignored += 1
    return components, edges, "SPDX-2.3", ignored


def _cycle_nodes(nodes, edges):
    forward, reverse = {n: [] for n in nodes}, {n: [] for n in nodes}
    for source, target in edges:
        forward[source].append(target)
        reverse[target].append(source)
    visited, order = set(), []
    for node in sorted(nodes):
        if node in visited:
            continue
        visited.add(node)
        pending = [(node, iter(forward[node]))]
        while pending:
            current, neighbors = pending[-1]
            target = next(neighbors, None)
            if target is None:
                order.append(current)
                pending.pop()
            elif target not in visited:
                visited.add(target)
                pending.append((target, iter(forward[target])))
    seen, cyclic = set(), []
    for node in reversed(order):
        if node in seen:
            continue
        component, pending = [], [node]
        seen.add(node)
        while pending:
            current = pending.pop()
            component.append(current)
            for neighbor in reverse[current]:
                if neighbor not in seen:
                    seen.add(neighbor)
                    pending.append(neighbor)
        if len(component) > 1:
            cyclic.extend(component)
    return sorted(cyclic)


def _vulnerabilities(value, known):
    result, identifiers = [], set()
    for item in _array(value.get("vulnerabilities", []), "declared vulnerabilities", LIMITS["vulnerabilities"]):
        if not isinstance(item, dict):
            _bad("Invalid vulnerability declaration")
        identifier = _text(item.get("id"), "vulnerability identifier", 256)
        if identifier in identifiers:
            _bad("Duplicate vulnerability identifier")
        identifiers.add(identifier)
        affected = []
        for entry in _array(item.get("affects", []), "affected components", LIMITS["components"]):
            if not isinstance(entry, dict):
                _bad("Invalid vulnerability affected component")
            ref = _text(entry.get("ref"), "affected component reference", 256)
            if ref not in known:
                _bad("Unknown vulnerability component reference")
            affected.append(ref)
        severities, ratings = [], []
        for rating in _array(item.get("ratings", []), "vulnerability ratings", 20):
            if not isinstance(rating, dict):
                _bad("Invalid vulnerability rating")
            if "severity" in rating:
                severities.append(_text(rating["severity"], "declared severity", 40))
            if "score" in rating and (type(rating["score"]) not in (int, float) or not 0 <= rating["score"] <= 10):
                _bad("Invalid declared vulnerability score")
            ratings.append({"severity": rating.get("severity"), "score": rating.get("score"),
                            "method": _text(rating.get("method"), "rating method", 80, optional=True)})
        result.append({"id": identifier, "affects": sorted(set(affected)),
                       "declared_severities": sorted(set(severities)),
                       "declared_ratings": sorted(ratings, key=encode), "verification": "source_claim_only"})
    return sorted(result, key=lambda v: (v["id"], v["affects"]))


def analyze(data):
    value = _bounded_json(data)
    if value.get("bomFormat") == "CycloneDX" and "spdxVersion" not in value:
        components, edges, format_name, ignored = _cdx(value)
    elif "spdxVersion" in value and "bomFormat" not in value:
        components, edges, format_name, ignored = _spdx(value)
    else:
        _bad("Expected an unambiguous SPDX 2.3 or CycloneDX 1.5/1.6 JSON document")
    known = {component["id"] for component in components}
    if len(known) != len(components):
        _bad("Duplicate component identifier")
    for source, target in edges:
        if source not in known or target not in known:
            _bad("Unknown dependency reference; external document dependencies are unsupported")
        if source == target:
            _bad("Self dependency is invalid")
    edges = sorted(set(edges))
    issues = []

    def issue(code, identifier, message):
        issues.append({"code": code, "component_id": identifier, "message": message})

    for component in components:
        for field, code in (("version", "missing_version"), ("licenses", "missing_license"), ("hashes", "missing_hash")):
            if not component[field]:
                issue(code, component["id"], "Source omits component " + field)
    cyclic = _cycle_nodes(known, edges)
    for identifier in cyclic:
        issue("dependency_cycle", identifier, "Component participates in a dependency cycle")
    identities = {}
    for component in components:
        if component["purl"]:
            identities.setdefault((component["purl"], component["version"]), []).append(component)
    for group in identities.values():
        conflict = set()
        by_algorithm = {}
        for component in group:
            for algorithm, digest in component["hashes"].items():
                by_algorithm.setdefault(algorithm, {}).setdefault(digest, []).append(component["id"])
        for digests in by_algorithm.values():
            if len(digests) > 1:
                conflict.update(identifier for ids in digests.values() for identifier in ids)
        for identifier in sorted(conflict):
            issue("conflicting_hash", identifier, "Same package URL and version declare different hashes")
    vulnerabilities = _vulnerabilities(value, known) if format_name.startswith("CycloneDX") else []
    dependencies = [{"source": source, "target": target} for source, target in edges]
    summary = {"components": len(components), "dependencies": len(dependencies),
               "missing_versions": sum(not c["version"] for c in components),
               "missing_licenses": sum(not c["licenses"] for c in components),
               "missing_hashes": sum(not c["hashes"] for c in components),
               "declared_vulnerabilities": len(vulnerabilities), "ignored_relationships": ignored}
    return {"schema": "was.supply-chain/1", "format": format_name, "component_count": len(components),
            "components": sorted(components, key=lambda c: c["id"]), "dependencies": dependencies,
            "graph": {"nodes": sorted(known), "edges": dependencies, "cycles": cyclic},
            "issues": sorted(issues, key=lambda i: (i["component_id"], i["code"])), "summary": summary,
            "vulnerabilities": vulnerabilities, "vulnerability_assessment": "source_claims_only_not_live_audit",
            "source_sha256": hashlib.sha256(data).hexdigest(), "network": False,
            "limits": dict(LIMITS), "limitations": LIMITATIONS}


def diff(left, right):
    """Compare complete normalized inventories; changed IDs are added/removed."""
    before, after = analyze(left), analyze(right)
    a = {c["id"]: c for c in before["components"]}
    b = {c["id"]: c for c in after["components"]}
    added, removed = sorted(b.keys() - a.keys()), sorted(a.keys() - b.keys())
    changed = [{"id": identifier, "fields": [key for key in a[identifier] if a[identifier][key] != b[identifier][key]]}
               for identifier in sorted(a.keys() & b.keys()) if a[identifier] != b[identifier]]
    old_edges = {(e["source"], e["target"]) for e in before["dependencies"]}
    new_edges = {(e["source"], e["target"]) for e in after["dependencies"]}
    edge_added = [{"source": s, "target": t} for s, t in sorted(new_edges - old_edges)]
    edge_removed = [{"source": s, "target": t} for s, t in sorted(old_edges - new_edges)]
    normalized_equal = not (added or removed or changed or edge_added or edge_removed) and before["vulnerabilities"] == after["vulnerabilities"]
    return {"schema": "was.supply-chain-diff/1", "complete": True,
            "left_format": before["format"], "right_format": after["format"],
            "left_sha256": before["source_sha256"], "right_sha256": after["source_sha256"],
            "added_components": added, "removed_components": removed, "changed_components": changed,
            "added_dependencies": edge_added, "removed_dependencies": edge_removed,
            "vulnerability_claims_changed": before["vulnerabilities"] != after["vulnerabilities"],
            "normalized_inventory_equal": normalized_equal,
            "notice": "المقارنة تشمل حقول الجرد الموثقة والاعتماديات وتصريحات الثغرات فقط؛ ليست مساواة جميع حقول المصدر أو فحصًا حيًا."}


def analyze_diff(data):
    """Analyze a bounded data-only pair; hashes identify canonical embedded JSON."""
    bundle = _bounded_json(data)
    if set(bundle) != {"left", "right"} or not all(isinstance(bundle[k], dict) for k in ("left", "right")):
        _bad("Comparison requires exactly left and right SBOM JSON objects")
    try:
        left, right = (encode(bundle[k]).encode("utf-8") for k in ("left", "right"))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid embedded SBOM encoding") from exc
    result = diff(left, right)
    result["embedded_document_encoding"] = "canonical_json"
    result["source_bundle_sha256"] = hashlib.sha256(data).hexdigest()
    return result


def sample():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"bom-ref": "app", "name": "synthetic-app", "version": "1.0.0",
                            "licenses": [{"license": {"id": "MIT"}}], "purl": "pkg:generic/synthetic-app@1.0.0",
                            "hashes": [{"alg": "SHA-256", "content": "a" * 64}]},
                           {"bom-ref": "library", "name": "synthetic-library", "version": "2.0.0",
                            "licenses": [{"license": {"id": "Apache-2.0"}}],
                            "hashes": [{"alg": "SHA-256", "content": "b" * 64}]}],
            "dependencies": [{"ref": "app", "dependsOn": ["library"]}]}


def diff_sample():
    left, right = sample(), sample()
    right["components"][1]["version"] = "2.1.0"
    return {"left": left, "right": right}
