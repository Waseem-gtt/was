"""Bounded, deterministic offline analyzers. No shell, network or sample execution."""
import collections
import base64
import csv
import hashlib
import io
import ipaddress
import json
import math
import re
import struct
from datetime import datetime
from . import certificates, event_adapters, pcap, supply_chain

# Every persisted engine fingerprint must include these implementation files,
# rather than only this registry, when deciding whether old results can be reused.
ANALYZER_FILES = ("pcap.py", "certificates.py", "supply_chain.py")


def text(data):
    return data.decode("utf-8-sig", errors="replace")


def obj(data):
    return json.loads(text(data))


def indicators(data):
    value = text(data)
    ips = set()
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
        try:
            ips.add(str(ipaddress.ip_address(match)))
        except ValueError:
            pass
    return {"ipv4": sorted(ips), "urls": sorted(set(re.findall(r"https?://[^\s<>\"']+", value)))[:200],
            "sha256": sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", value))), "source_bytes": len(data)}


def http_review(data):
    request = obj(data)
    headers = {k.lower(): str(v) for k, v in request.get("headers", {}).items()}
    missing = [h for h in ("content-security-policy", "x-content-type-options", "referrer-policy") if h not in headers]
    return {"missing_headers": missing, "status": request.get("status"),
            "limitations": "مراجعة رؤوس من ملف JSON؛ لا فحص لشبكة أو إثبات ثغرة."}


def events(data):
    items = obj(data)
    if isinstance(items, dict):
        envelope = event_adapters.strict_json(data.decode("utf-8-sig"))
        if not {"adapter", "content"} & set(envelope):
            raise ValueError("Expected at most 20000 events")
        if set(envelope) != {"adapter", "content"}:
            raise ValueError("Event adapter envelope requires only adapter and content")
        return event_adapters.normalize(envelope["adapter"], envelope["content"])
    if not isinstance(items, list) or len(items) > 20000:
        raise ValueError("Expected at most 20000 events")
    normalized = []
    for e in items:
        normalized.append({"time": e.get("time", "unknown"), "actor": e.get("user", e.get("actor", "unknown")),
                           "action": e.get("action", "unknown"), "outcome": e.get("outcome", "unknown"), "original": e})
    return {"schema": "was.event/1", "events": normalized, "count": len(normalized),
            "failed": sum(e["outcome"] == "failure" for e in normalized), "limitations": "ليس محول OCSF كاملًا"}


def hashes(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "sha512": hashlib.sha512(data).hexdigest(), "bytes": len(data)}


def executable(data):
    kind = "unknown"
    result = {}
    if data.startswith(b"\x7fELF"):
        if len(data) < 20:
            raise ValueError("Truncated ELF")
        kind = "ELF"
        endian = "<" if data[5] == 1 else ">"
        result = {"bits": {1: 32, 2: 64}.get(data[4]), "machine": struct.unpack_from(endian + "H", data, 18)[0]}
    elif data.startswith(b"MZ"):
        if len(data) < 64:
            raise ValueError("Truncated DOS header")
        offset = struct.unpack_from("<I", data, 60)[0]
        if offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
            raise ValueError("Invalid PE signature")
        kind = "PE"
        result = {"machine": struct.unpack_from("<H", data, offset + 4)[0],
                  "sections": struct.unpack_from("<H", data, offset + 6)[0]}
    strings = re.findall(rb"[\x20-\x7e]{6,120}", data)[:100]
    return {"format": kind, **result, "strings": [x.decode("ascii") for x in strings], "executed": False}


def network(data):
    rows = list(csv.DictReader(io.StringIO(text(data))))
    if len(rows) > 20000:
        raise ValueError("Too many flow records")
    total = sum(max(0, int(r.get("bytes", 0))) for r in rows)
    return {"flows": len(rows), "bytes": total, "protocols": dict(collections.Counter(r.get("protocol", "unknown") for r in rows)),
            "destinations": dict(collections.Counter(r.get("destination", "unknown") for r in rows).most_common(100))}


def permissions(data):
    records = obj(data)
    return {"review": [{"name": r.get("name"), "admin": bool(r.get("admin")),
                         "stale": not r.get("active", True), "mfa_missing": not r.get("mfa", False)} for r in records],
            "limitations": "تقييم بيانات حسابات مقدمة؛ لا اتصال بخادم هوية"}


def container_review(data):
    value = obj(data)
    findings = []
    if value.get("privileged"):
        findings.append("privileged")
    if value.get("user", "root") in ("root", "0", 0):
        findings.append("root_user")
    if value.get("network_mode") == "host":
        findings.append("host_network")
    if not value.get("read_only", False):
        findings.append("writable_root")
    return {"findings": findings, "count": len(findings), "limitations": "مراجعة وصف JSON وليست فحص حاوية حية"}


def sbom(data):
    value = obj(data)
    if value.get("bomFormat") == "CycloneDX":
        components = value.get("components", [])
        fmt = "CycloneDX"
    elif "spdxVersion" in value:
        components = value.get("packages", [])
        fmt = "SPDX"
    else:
        raise ValueError("Expected CycloneDX or SPDX JSON")
    return {"format": fmt, "components": [{"name": c.get("name"), "version": c.get("version", c.get("versionInfo")),
                                            "purl": c.get("purl"), "licenses": c.get("licenses", c.get("licenseConcluded"))} for c in components[:10000]],
            "count": len(components), "limitations": "جرد فقط؛ غياب تنبيه ليس إثبات أمان"}


def binary_records(data):
    offset, records = 0, []
    while offset < len(data):
        if len(records) >= 10000 or offset + 2 > len(data):
            raise ValueError("Truncated or excessive TLV records")
        kind, length = data[offset:offset + 2]
        offset += 2
        if offset + length > len(data):
            raise ValueError("TLV length exceeds input")
        records.append({"type": kind, "length": length, "hex": data[offset:offset + length].hex()})
        offset += length
    return {"records": records, "count": len(records)}


def crypto_inventory(data):
    value = text(data)
    found = sorted(set(re.findall(r"\b(?:RSA|ECDSA|Ed25519|AES|SHA-?256|ML-KEM|ML-DSA|TLSv1\.[0-3])\b", value, re.I)))
    return {"algorithms": found, "private_key_markers": value.count("PRIVATE KEY"),
            "limitations": "جرد نصي؛ لا اختبار توافق تشفير أو تقدير قوة مفاتيح"}


def firmware(data):
    counts = collections.Counter(data)
    entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values()) if data else 0
    magics = {"ELF": b"\x7fELF", "gzip": b"\x1f\x8b", "SquashFS-le": b"hsqs", "ZIP": b"PK\x03\x04"}
    return {"bytes": len(data), "entropy_bits_per_byte": round(entropy, 5),
            "signatures": {name: data.find(magic) for name, magic in magics.items() if magic in data},
            "limitations": "لا استخراج أو تشغيل للبرامج الثابتة؛ التواقيع قرائن أولية"}


def twin(data):
    value = obj(data)
    n = int(value.get("steps", 60))
    if not 1 <= n <= 1000:
        raise ValueError("steps must be 1..1000")
    temp, ambient, target = float(value.get("initial", 20)), float(value.get("ambient", 20)), float(value.get("target", 35))
    if not all(math.isfinite(x) and abs(x) <= 1000 for x in (temp, ambient, target)):
        raise ValueError("Invalid temperature")
    trace = []
    for step in range(n):
        power = max(0, min(1, (target - temp) * .2))
        temp += power * .8 - (temp - ambient) * .025
        trace.append({"step": step, "temperature": round(temp, 3), "power": round(power, 3)})
    return {"trace": trace, "final": round(temp, 3), "limitations": "توأم حراري حسابي مبسط، دون جهاز صناعي"}


def spectrum(data):
    values = obj(data)
    if not isinstance(values, list) or not 4 <= len(values) <= 256:
        raise ValueError("Expected 4..256 real samples")
    values = [float(v) for v in values]
    if not all(math.isfinite(v) and abs(v) < 1e9 for v in values):
        raise ValueError("Invalid sample")
    n = len(values)
    powers = [abs(sum(v * complex(math.cos(-2 * math.pi * k * t / n), math.sin(-2 * math.pi * k * t / n)) for t, v in enumerate(values))) ** 2 / n for k in range(n // 2 + 1)]
    peak = max(range(len(powers)), key=powers.__getitem__)
    return {"power": [round(p, 6) for p in powers], "peak_bin": peak, "normalized_frequency": peak / n,
            "limitations": "DFT لعينات حقيقية قصيرة؛ لا استقبال رادار أو SDR حي"}


def telemetry(data):
    rows = list(csv.DictReader(io.StringIO(text(data))))
    gaps, previous = [], None
    for i, row in enumerate(rows):
        seq = int(row["sequence"])
        if not 0 <= seq <= 255:
            raise ValueError("Sequence must be 0..255")
        if previous is not None and seq != (previous + 1) % 256:
            gaps.append({"row": i + 1, "previous": previous, "current": seq})
        previous = seq
    return {"records": len(rows), "gaps": gaps, "limitations": "تحليل تسلسل CSV مصدّر؛ ليس محلل MAVLink كاملًا"}


def can(data):
    frames, invalid = [], []
    for i, line in enumerate(text(data).splitlines()):
        if not line.strip():
            continue
        m = re.search(r"\b([A-Fa-f0-9]{3,8})#([A-Fa-f0-9]{0,16})\s*$", line)
        if not m or len(m[2]) % 2:
            invalid.append(i + 1)
        else:
            frames.append({"id": int(m[1], 16), "data": m[2].upper(), "length": len(m[2]) // 2})
    return {"frames": frames, "invalid_lines": invalid, "count": len(frames), "limitations": "CAN كلاسيكي من candump؛ لا تحكم بمركبة"}


def space(data):
    offset, packets = 0, []
    while offset < len(data):
        if offset + 6 > len(data):
            raise ValueError("Truncated CCSDS header")
        a, b, c = struct.unpack_from(">HHH", data, offset)
        size = c + 7
        if offset + size > len(data):
            raise ValueError("Truncated CCSDS packet")
        packets.append({"version": a >> 13, "apid": a & 2047, "sequence": b & 16383, "bytes": size})
        offset += size
        if len(packets) > 10000:
            raise ValueError("Too many packets")
    return {"packets": packets, "count": len(packets), "limitations": "رأس CCSDS الأساسي فقط؛ لا اتصال فضائي"}


def ai_audit(data):
    value = obj(data)
    excerpts = value.get("excerpts", {})
    results = []
    for claim in value.get("claims", []):
        source, quote = claim.get("source"), claim.get("quote", "")
        results.append({"claim": claim.get("text"), "source": source,
                        "quote_present": bool(quote) and quote in excerpts.get(source, "")})
    return {"claims": results, "unsupported": sum(not r["quote_present"] for r in results),
            "limitations": "وجود المقتطف لا يثبت صحة استنتاج النموذج"}


def privacy(data):
    value = text(data)
    patterns = {"email": r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "bearer": r"(?i)Bearer\s+[A-Za-z0-9._~+/-]{8,}",
                "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"}
    counts = {}
    for name, pattern in patterns.items():
        value, counts[name] = re.subn(pattern, "[REDACTED:" + name + "]", value)
    return {"redacted": value, "matches": counts, "limitations": "تنقيح نسخة فقط؛ لا ضمان اكتشاف جميع الأسرار"}


def manifest(data):
    value = obj(data)
    required = ("id", "version", "license", "source", "permissions")
    missing = [k for k in required if k not in value]
    return {"missing": missing, "valid_structure": not missing,
            "permissions": value.get("permissions", []), "activated": False,
            "limitations": "تحقق بيان فقط؛ لا تثبيت أو تنفيذ كود إضافة"}


def detection_rules(data):
    """Test exact-match AND selections on provided events. No regex/eval/YAML."""
    value = obj(data)
    events, rules = value.get("events"), value.get("rules")
    if not isinstance(events, list) or len(events) > 10000 or not all(isinstance(e, dict) for e in events):
        raise ValueError("Expected at most 10000 event objects")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 50:
        raise ValueError("Expected 1..50 rules")
    ids, outputs = set(), []
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Rule must be an object")
        rid, selection = rule.get("id"), rule.get("selection")
        if not isinstance(rid, str) or not 1 <= len(rid) <= 100 or rid in ids:
            raise ValueError("Rule IDs must be unique nonempty strings")
        ids.add(rid)
        if not isinstance(selection, dict) or not 1 <= len(selection) <= 20:
            raise ValueError("Each rule needs 1..20 exact-match fields")
        if any(not isinstance(k, str) or not 1 <= len(k) <= 100 or not isinstance(v, (str, int, float, bool, type(None))) for k, v in selection.items()):
            raise ValueError("Selection values must be JSON scalars")
        matches = [i for i, event in enumerate(events) if all(k in event and type(event[k]) is type(v) and event[k] == v for k, v in selection.items())]
        expected = rule.get("expected_event_indexes")
        metrics = None
        if expected is not None:
            if not isinstance(expected, list) or any(type(i) is not int or not 0 <= i < len(events) for i in expected):
                raise ValueError("Expected indexes must refer to supplied events")
            actual, truth = set(matches), set(expected)
            metrics = {"true_positive": len(actual & truth), "false_positive": len(actual - truth),
                       "false_negative": len(truth - actual), "true_negative": len(events) - len(actual | truth),
                       "passed": actual == truth}
        outputs.append({"id": rid, "matched_event_indexes": matches, "metrics": metrics,
                        "source": rule.get("source"), "version": rule.get("version"), "license": rule.get("license")})
    return {"schema": "was.rules/1", "rules": outputs, "event_count": len(events),
            "evaluated_rules": sum(r["metrics"] is not None for r in outputs),
            "limitations": "قواعد مطابقة حقول على بيانات مقدمة؛ ليست محرك Sigma كاملًا أو مراقبة حية أو إثبات حماية شاملة"}


SPECS = [
    ("ioc", "استخراج المؤشرات", indicators, "نص يحوي عناوين IP وروابط", "Host 192.0.2.1 contacted https://example.test/path"),
    ("http", "مراجعة رؤوس HTTP", http_review, "JSON لرؤوس استجابة", {"status": 200, "headers": {"X-Content-Type-Options": "nosniff"}}),
    ("events", "توحيد أحداث تجريبية", events, "JSON مصفوفة أحداث", [{"time": "2026-10-17T00:00:00Z", "user": "lab", "action": "login", "outcome": "failure"}]),
    ("hashes", "بصمات الأدلة", hashes, "أي ملف", "Evidence integrity sample"),
    ("executable", "فحص رؤوس ELF وPE", executable, "ملف تنفيذي للتحليل الساكن", "Static analysis sample, never executed"),
    ("flows", "إحصاء تدفقات الشبكة", network, "CSV: protocol,destination,bytes", "protocol,destination,bytes\nTLS,192.0.2.1,512\nDNS,192.0.2.2,64\n"),
    ("identity", "مراجعة حسابات وصلاحيات", permissions, "JSON مصفوفة حسابات", [{"name": "lab-admin", "admin": True, "active": True, "mfa": False}]),
    ("container", "مراجعة وصف حاوية", container_review, "JSON إعدادات محلية", {"privileged": True, "user": "root", "network_mode": "host"}),
    ("sbom", "جرد CycloneDX وSPDX", sbom, "SBOM بصيغة JSON", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "example", "version": "1.0", "licenses": [{"license": {"id": "MIT"}}]}]}),
    ("tlv", "تحليل سجلات TLV", binary_records, "ثنائي: type:uint8, length:uint8, value", None),
    ("crypto", "جرد خوارزميات نصي", crypto_inventory, "وصف تشفير نصي", "TLSv1.3 AES Ed25519 ML-KEM"),
    ("firmware", "جرد تواقيع Firmware", firmware, "ملف ثنائي", "Firmware reference hsqs"),
    ("twin", "توأم حراري مبسط", twin, "JSON: steps,initial,ambient,target", {"steps": 60, "target": 35}),
    ("spectrum", "طيف عينات قصيرة", spectrum, "JSON مصفوفة 4–256 عينة", [0, 1, 0, -1, 0, 1, 0, -1]),
    ("telemetry", "جودة تسلسل قياسات", telemetry, "CSV: sequence,value", "sequence,value\n1,20\n2,21\n4,23\n"),
    ("can", "قراءة CAN كلاسيكي", can, "نص candump", "(1.000) vcan0 123#01020304\n(1.010) vcan0 124#AABB\n"),
    ("ccsds", "رؤوس حزم CCSDS", space, "ملف حزم ثنائي", None),
    ("ai-audit", "تدقيق مقتطفات AI", ai_audit, "JSON: claims,excerpts", {"excerpts": {"e1": "Reference result: 42"}, "claims": [{"text": "Result is 42", "source": "e1", "quote": "result: 42"}]}),
    ("privacy", "تنقيح نسخة نصية", privacy, "نص للتنقيح", "Contact owner@example.test; Bearer SAMPLE_TOKEN_12345"),
    ("manifest", "تحقق بيان إضافة", manifest, "JSON بيان إضافة", {"id": "plugin.example", "version": "1.0", "license": "MIT", "source": "https://example.test", "permissions": ["selected_evidence.read"]}),
    ("rules", "اختبار قواعد كشف دفاعية", detection_rules, "JSON: events,rules مع selection ومعايير متوقعة", {"events": [{"action": "login", "outcome": "failure"}, {"action": "login", "outcome": "success"}], "rules": [{"id": "failed-login", "version": "1", "license": "CC0-1.0", "source": "owner-authored synthetic example", "selection": {"action": "login", "outcome": "failure"}, "expected_event_indexes": [0]}]}),
]
SPECS.extend([
    ("pcap", "تحليل تسجيل PCAP", pcap.analyze, "classic PCAP أو JSON: pcap_base64", {"pcap_base64": base64.b64encode(pcap.sample()).decode()}),
    ("certificate", "فحص شهادات X.509", certificates.analyze, "شهادة PEM أو DER أو JSON: certificates_pem,validation_time اختياري", certificates.sample()),
    ("supply-chain", "تحليل مكونات واعتماديات البرمجيات", supply_chain.analyze, "CycloneDX1.5/1.6 أو SPDX2.3 JSON", supply_chain.sample()),
    ("supply-chain-diff", "مقارنة قوائم مكونات البرمجيات", supply_chain.analyze_diff, "JSON: left,right وثيقتا SBOM كاملتان", supply_chain.diff_sample()),
])
REGISTRY = {s[0]: s[2] for s in SPECS}


def describe():
    return [{"id": s[0], "name": s[1], "section": {"pcap":"06", "certificate":"11", "supply-chain":"09", "supply-chain-diff":"09"}.get(s[0], f"{i + 1:02}"), "input": s[3], "state": "available",
             "sample": s[4] if isinstance(s[4], str) else json.dumps(s[4], ensure_ascii=False) if s[4] is not None else None,
             "max_bytes": 256 * 1024 if s[0] == "certificate" else 4 * 1024 * 1024, "network": False} for i, s in enumerate(SPECS)]


def analyze(tool, data):
    if tool not in REGISTRY:
        raise ValueError("Unknown tool")
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("Analyzer limit is 4 MiB")
    try:
        result = REGISTRY[tool](data)
    except (AttributeError, TypeError, KeyError, IndexError, struct.error, RecursionError) as exc:
        raise ValueError("Input does not match the documented tool format") from exc
    # Disallow NaN/Infinity in persisted JSON results.
    if len(json.dumps(result, allow_nan=False).encode()) > 8 * 1024 * 1024:
        raise ValueError("Analysis result exceeds 8 MiB")
    return result
