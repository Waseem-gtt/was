"""Bounded, privacy-preserving offline HAR observations and comparisons."""
import hashlib
import ipaddress
import math
import re
from urllib.parse import urlsplit
from .event_adapters import strict_json
from .store import encode

LIMITS = {"input_bytes": 4 * 1024 * 1024, "entries": 1000, "headers": 200,
          "cookies": 200, "json_depth": 32, "json_nodes": 100000,
          "output_bytes": 3 * 1024 * 1024}
LIMITATIONS = ("مراجعة بيانات جلسة HAR مسجلة فقط؛ الملاحظات ليست اختبارًا حيًا أو إثبات ثغرة. "
               "لا تصدير لمسارات واستعلامات وروابط الدخول أو الرؤوس والكوكيز والأجسام؛ "
               "أسماء المضيفين تبقى بيانات وصفية خاصة، ولا يثبت غياب ملاحظة سلامة التطبيق.")
_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
_PROTOCOLS = {"HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3", "HTTP/3.0", "h2", "h3", ""}
_HEADER_FIELDS = {"content_security_policy":"content-security-policy", "hsts":"strict-transport-security",
                  "x_content_type_options":"x-content-type-options", "referrer_policy":"referrer-policy"}
_MESSAGES = {
    "insecure_transport":"اتصالHTTPمسجل دونTLS؛ لا يثبت اعتراضًا فعليًا.",
    "credentials_over_http":"وجود حقل اعتماد مسجل معHTTPيحتاج مراجعة؛ لم يُصدر محتواه.",
    "missing_csp":"الاستجابة المسجلة لا تتضمنContent-Security-Policy.",
    "missing_hsts":"استجابةHTTPSالمسجلة لا تتضمنStrict-Transport-Security.",
    "missing_nosniff":"الاستجابة المسجلة لا تتضمنX-Content-Type-Options:nosniff.",
    "cors_wildcard_credentials":"تجمع الاستجابة المعلنةCORSبين النجمة والاعتمادات؛ تحتاج مراجعة السياق.",
    "cookie_without_secure":"كوكي استجابة مسجلة لا تتضمنSecure.",
    "cookie_without_http_only":"كوكي استجابة مسجلة لا تتضمنHttpOnly.",
    "cookie_without_same_site":"كوكي استجابة مسجلة دونSameSiteموثق.",
    "same_site_none_without_secure":"كوكيSameSite=Noneمسجلة دونSecure.",
}


def _bad(message="Invalid HAR structure"):
    raise ValueError(message)


def _bounded_json(data):
    if not isinstance(data, bytes) or len(data) > LIMITS["input_bytes"]:
        _bad("HAR input exceeds 4 MiB")
    try:
        value = strict_json(data.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid HAR JSON") from exc
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop(); count += 1
        if depth > LIMITS["json_depth"] or count > LIMITS["json_nodes"]:
            _bad("HAR JSON structure exceeds limits")
        if isinstance(item, dict):
            for key in item:
                if not isinstance(key, str):
                    _bad("Invalid HAR JSON key")
                try:
                    key.encode("utf-8")
                except UnicodeError:
                    _bad("Invalid HAR text")
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeError:
                _bad("Invalid HAR text")
        elif type(item) is int and abs(item) > 2 ** 63 - 1:
            _bad("HAR integer exceeds limits")
    if not isinstance(value, dict):
        _bad()
    return value


def _string(value, maximum=8192):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _bad()
    return value


def _origin(value):
    _string(value)
    try:
        url = urlsplit(value)
        if url.scheme not in {"http", "https"} or not url.hostname:
            _bad("HAR URL must use HTTP or HTTPS")
        host = url.hostname
        try:
            parsed = ipaddress.ip_address(host)
            host = "[" + str(parsed) + "]" if parsed.version == 6 else str(parsed)
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.rstrip(".").split(".")):
                _bad("Invalid HAR origin")
        port = url.port
        if port is not None and not 1 <= port <= 65535:
            _bad("Invalid HAR origin")
        suffix = "" if port in (None, 80 if url.scheme == "http" else 443) else ":" + str(port)
        return url.scheme + "://" + host + suffix, url.scheme
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid HAR origin") from exc


def _headers(value):
    if not isinstance(value, list) or len(value) > LIMITS["headers"]:
        _bad("HAR header list exceeds limits or has invalid type")
    result = {}
    for item in value:
        if not isinstance(item, dict) or not {"name", "value"} <= set(item):
            _bad()
        name = _string(item["name"], 256)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            _bad("Invalid HAR header name")
        val = _string(item["value"], 16384)
        result.setdefault(name.lower(), []).append(val)
    return result


def _cookies(value):
    if not isinstance(value, list) or len(value) > LIMITS["cookies"]:
        _bad("HAR cookie list exceeds limits or has invalid type")
    for cookie in value:
        if not isinstance(cookie, dict):
            _bad()
        _string(cookie.get("name"), 1024); _string(cookie.get("value"), 16384)
        for key in ("secure", "httpOnly"):
            if key in cookie and type(cookie[key]) is not bool:
                _bad("Invalid HAR cookie flag")
        if "sameSite" in cookie and (not isinstance(cookie["sameSite"], str) or cookie["sameSite"].lower() not in {"strict", "lax", "none"}):
            _bad("Invalid HAR SameSite")
    return value


def _cookie_attributes(cookies, headers):
    result = []
    for cookie in cookies:
        result.append({"secure":cookie.get("secure", False), "http_only":cookie.get("httpOnly", False),
                       "same_site":cookie.get("sameSite", "unknown").lower()})
    # The cookie array and Set-Cookie headers can be two representations of the
    # same cookies. Prefer the structured array to avoid double counting.
    if not cookies:
        for value in headers.get("set-cookie", []):
            parts = value.split(";")
            if "=" not in parts[0]:
                _bad("Invalid HAR Set-Cookie")
            flags, same_site = set(), "unknown"
            for part in parts[1:]:
                key, _, val = part.strip().partition("=")
                key = key.lower(); flags.add(key)
                if key == "samesite":
                    same_site = val.lower() if val.lower() in {"lax", "strict", "none"} else "unknown"
            result.append({"secure":"secure" in flags, "http_only":"httponly" in flags, "same_site":same_site})
    return result


def analyze(data):
    value = _bounded_json(data)
    log = value.get("log")
    if not isinstance(log, dict) or log.get("version") != "1.2" or not isinstance(log.get("entries"), list) or len(log["entries"]) > LIMITS["entries"]:
        _bad("Expected HAR 1.2 with bounded entries")
    entries, findings, origins = [], [], {}
    for index, entry in enumerate(log["entries"]):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict) or not isinstance(entry.get("response"), dict):
            _bad()
        request, response = entry["request"], entry["response"]
        method = request.get("method"); protocol = response.get("httpVersion", "")
        if not isinstance(method, str) or method not in _METHODS or not isinstance(protocol, str) or protocol not in _PROTOCOLS:
            _bad("Unsupported HAR method or protocol")
        status = response.get("status")
        if type(status) is not int or status != 0 and not 100 <= status <= 599:
            _bad("Invalid HAR response status")
        duration = entry.get("time", -1)
        if type(duration) not in (int, float) or not math.isfinite(duration) or not -1 <= duration <= 86400000:
            _bad("Invalid HAR entry time")
        origin, scheme = _origin(request.get("url"))
        req_headers, res_headers = _headers(request.get("headers", [])), _headers(response.get("headers", []))
        req_cookies, res_cookies = _cookies(request.get("cookies", [])), _cookies(response.get("cookies", []))
        attributes = _cookie_attributes(res_cookies, res_headers)
        security = {key:header in res_headers for key, header in _HEADER_FIELDS.items()}
        codes = []
        if scheme == "http":
            codes.append("insecure_transport")
            if req_cookies or "cookie" in req_headers or "authorization" in req_headers:
                codes.append("credentials_over_http")
        if status:
            if not security["content_security_policy"]: codes.append("missing_csp")
            if scheme == "https" and not security["hsts"]: codes.append("missing_hsts")
            if not any(v.lower().strip() == "nosniff" for v in res_headers.get("x-content-type-options", [])): codes.append("missing_nosniff")
            if "*" in res_headers.get("access-control-allow-origin", []) and any(v.lower().strip() == "true" for v in res_headers.get("access-control-allow-credentials", [])):
                codes.append("cors_wildcard_credentials")
            for cookie in attributes:
                if not cookie["secure"]: codes.append("cookie_without_secure")
                if not cookie["http_only"]: codes.append("cookie_without_http_only")
                if cookie["same_site"] == "unknown": codes.append("cookie_without_same_site")
                if cookie["same_site"] == "none" and not cookie["secure"]: codes.append("same_site_none_without_secure")
        codes = sorted(set(codes))
        findings.extend({"entry":index, "code":code, "message":_MESSAGES[code]} for code in codes)
        entries.append({"index":index, "origin":origin, "method":method, "status":status, "protocol":protocol,
                        "duration_ms":duration, "request_header_count":len(request.get("headers", [])),
                        "response_header_count":len(response.get("headers", [])), "request_cookie_count":len(req_cookies),
                        "response_cookie_count":len(attributes), "security_headers":security,
                        "response_cookie_attributes":attributes, "response_recorded":bool(status), "findings":codes})
        origins[origin] = origins.get(origin, 0) + 1
    result = {"schema":"was.har-analysis/1", "entry_count":len(entries), "entries":entries,
              "origins":[{"origin":o, "entries":n} for o, n in sorted(origins.items())], "findings":findings,
              "summary":{"origins":len(origins), "entries":len(entries), "findings":len(findings),
                         "insecure_entries":sum(e["origin"].startswith("http:") for e in entries),
                         "failed_http_responses":sum(e["status"] >= 400 for e in entries)},
              "source_sha256":hashlib.sha256(data).hexdigest(), "network":False, "content_exported":False,
              "limits":dict(LIMITS), "limitations":LIMITATIONS}
    if len(encode(result).encode()) > LIMITS["output_bytes"]:
        _bad("HAR output exceeds limits")
    return result


def analyze_diff(data):
    value = _bounded_json(data)
    if set(value) != {"left", "right"} or any(not isinstance(value[k], dict) for k in value):
        _bad("HAR comparison requires exactly left and right documents")
    before, after = [analyze(encode(value[k]).encode()) for k in ("left", "right")]
    left, right = before["entries"], after["entries"]
    shared = min(len(left), len(right))
    changed = [{"index":i, "fields":sorted(k for k in left[i] if left[i][k] != right[i][k])}
               for i in range(shared) if left[i] != right[i]]
    added, removed = list(range(shared, len(right))), list(range(shared, len(left)))
    return {"schema":"was.har-diff/1", "complete":True, "normalized_metadata_equal":not(changed or added or removed),
            "changed_entries":changed, "added_entry_indexes":added, "removed_entry_indexes":removed,
            "left_entry_count":len(left), "right_entry_count":len(right),
            "left_summary":before["summary"], "right_summary":after["summary"],
            "left_sha256":before["source_sha256"], "right_sha256":after["source_sha256"],
            "source_bundle_sha256":hashlib.sha256(data).hexdigest(), "embedded_document_encoding":"canonical_json",
            "network":False, "content_exported":False,
            "notice":"المقارنة كاملة للبيانات الوصفية الآمنة بترتيبها وتكرارها؛ ليست مساواة المسارات والقيم والأجسام المحجوبة أو جميع بايتات المصدر."}


def sample():
    return {"log":{"version":"1.2", "entries":[{"time":12, "request":{"method":"GET", "url":"https://example.test/", "headers":[], "cookies":[]},
        "response":{"status":200, "httpVersion":"HTTP/2", "headers":[{"name":"X-Content-Type-Options", "value":"nosniff"},
            {"name":"Strict-Transport-Security", "value":"max-age=31536000"}], "cookies":[]}}]}}


def diff_sample():
    left, right = sample(), sample()
    right["log"]["entries"][0]["response"]["status"] = 503
    return {"left":left, "right":right}
