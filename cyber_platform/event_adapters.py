"""Strict, bounded offline event adapters; input is data, never a command."""
import csv
import hashlib
import io
import ipaddress
import json
import math
import re
from datetime import datetime

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 1000
MAX_RECORD_BYTES = 8192
LIMITATIONS = "تطبيع جزئي إلى was.event/1؛ ليس OCSF كاملًا ولا إثبات هجوم أو نجاح حماية."


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def strict_json(content):
    def invalid(_):
        raise ValueError("Non-finite JSON number")
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Non-finite JSON number")
        return result
    try:
        return json.loads(content, object_pairs_hook=_pairs, parse_constant=invalid, parse_float=number)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("Invalid JSON structure") from exc


def _string(value, name, empty=False):
    if not isinstance(value, str) or (not empty and not value) or len(value.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("Invalid " + name)
    return value


def _time(value):
    _string(value, "timestamp")
    if value == "unknown":
        return value
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise ValueError("Timestamp requires RFC3339 date, time and explicit offset")
    offset = value[-6:]
    if offset[0] in "+-" and (int(offset[1:3]) > 23 or int(offset[4:]) > 59):
        raise ValueError("Invalid timestamp offset")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def _base(original, time="unknown", actor="unknown", action="unknown", outcome="unknown"):
    if outcome not in {"unknown", "success", "failure"}:
        raise ValueError("Outcome must be unknown, success or failure")
    return {"time": _time(time), "actor": _string(actor, "actor"),
            "action": _string(action, "action"), "outcome": outcome, "original": original}


def _windows(record):
    if not isinstance(record, dict):
        raise ValueError("Windows record must be an object")
    if "System" in record:
        if set(record) - {"System", "EventData"}:
            raise ValueError("Unknown Windows record field")
        system, data = record["System"], record.get("EventData", {})
        if not isinstance(system, dict) or set(system) - {"EventID", "TimeCreated", "Computer", "Channel", "Provider"}:
            raise ValueError("Unsupported Windows System shape")
        if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            raise ValueError("EventData must map names to strings")
        created = system.get("TimeCreated")
        if not isinstance(created, dict) or set(created) != {"SystemTime"}:
            raise ValueError("TimeCreated requires only SystemTime")
        event_id = system.get("EventID")
        for field in ("Computer", "Channel", "Provider"):
            if field in system:
                _string(system[field], field)
        result = _base(record, created["SystemTime"], data.get("TargetUserName", "unknown"))
        if "Computer" in system:
            result["host"] = system["Computer"]
    else:
        allowed = {"time", "event_id", "actor", "action", "outcome", "host"}
        if set(record) - allowed or not {"time", "event_id"} <= set(record):
            raise ValueError("Flat Windows record requires time/event_id and supported fields only")
        event_id = record["event_id"]
        result = _base(record, record["time"], record.get("actor", "unknown"), record.get("action", "unknown"), record.get("outcome", "unknown"))
        if "host" in record:
            result["host"] = _string(record["host"], "host")
    if type(event_id) is not int or not 0 <= event_id <= 65535:
        raise ValueError("EventID must be integer 0..65535")
    result["event_id"] = event_id
    return result


def _structured(value):
    """Scan RFC5424 structured data, returning its end; no backtracking parser."""
    if value.startswith("-"):
        return 1
    pos, ids = 0, set()
    def name(index):
        start = index
        while index < len(value) and value[index] not in ' =]"':
            if not 33 <= ord(value[index]) <= 126:
                raise ValueError("Invalid structured-data name")
            index += 1
        if not 1 <= index - start <= 32:
            raise ValueError("Structured-data name must be 1..32 ASCII bytes")
        return value[start:index], index
    while pos < len(value) and value[pos] == "[":
        ident, pos = name(pos + 1)
        if ident in ids:
            raise ValueError("Duplicate structured-data ID")
        ids.add(ident)
        params = set()
        while pos < len(value) and value[pos] == " ":
            key, pos = name(pos + 1)
            if key in params or value[pos:pos + 2] != '="':
                raise ValueError("Invalid or duplicate structured-data parameter")
            params.add(key)
            pos += 2
            while pos < len(value) and value[pos] != '"':
                char = value[pos]
                if char == "\\":
                    pos += 1
                    if pos >= len(value) or value[pos] not in '\\"]':
                        raise ValueError("Invalid structured-data escape")
                elif char == "]" or ord(char) < 32:
                    raise ValueError("Invalid structured-data value")
                pos += 1
            if pos >= len(value):
                raise ValueError("Unclosed structured-data value")
            pos += 1
        if pos >= len(value) or value[pos] != "]":
            raise ValueError("Unclosed structured data")
        pos += 1
    if not ids:
        raise ValueError("Expected structured data or NILVALUE")
    return pos


def _syslog(line):
    parts = line.split(" ", 6)
    if len(parts) != 7:
        raise ValueError("RFC5424 requires six header fields and structured data")
    pri_version, timestamp, host, app, proc, msgid, tail = parts
    match = re.fullmatch(r"<([0-9]{1,3})>1", pri_version)
    if not match or (len(match[1]) > 1 and match[1].startswith("0")) or int(match[1]) > 191:
        raise ValueError("Invalid RFC5424 priority/version")
    for field, limit in ((host, 255), (app, 48), (proc, 128), (msgid, 32)):
        if not 1 <= len(field) <= limit or any(not 33 <= ord(char) <= 126 for char in field):
            raise ValueError("Invalid RFC5424 header field")
    if timestamp == "unknown":
        raise ValueError("RFC5424 unknown timestamp must use NILVALUE")
    end = _structured(tail)
    if end != len(tail) and tail[end] != " ":
        raise ValueError("Unexpected bytes after structured data")
    result = _base(line, "unknown" if timestamp == "-" else timestamp)
    priority = int(match[1])
    result.update({"host": "unknown" if host == "-" else host, "application": app,
                   "process_id": proc, "message_id": msgid, "facility": priority // 8,
                   "severity": priority % 8, "structured_data": tail[:end],
                   "message": tail[end + 1:] if end < len(tail) else ""})
    return result


def _flow(row):
    result = _base(row, row["time"], action=row.get("action", "unknown"), outcome=row.get("outcome", "unknown"))
    for name in ("source", "destination"):
        result[name] = str(ipaddress.ip_address(row[name]))
    protocol = row["protocol"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", protocol):
        raise ValueError("Invalid protocol")
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", row["bytes"]) or int(row["bytes"]) > 2**64 - 1:
        raise ValueError("bytes must be an unsigned 64-bit integer")
    result.update({"protocol": protocol, "bytes": int(row["bytes"])})
    return result


def normalize(adapter, content):
    """Normalize the complete batch or fail with the offending record index."""
    _string(adapter, "adapter")
    if not isinstance(content, str):
        raise ValueError("Content must be a UTF-8 string")
    try:
        raw = content.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Invalid Unicode content") from exc
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("Content must be 1..1048576 UTF-8 bytes")
    lines = content.split("\n")
    if lines[-1] == "":
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    if adapter != "windows-json" and any(len(line.encode("utf-8")) > MAX_RECORD_BYTES for line in lines):
        raise ValueError("Input line exceeds 8192 bytes")
    if adapter == "windows-json":
        records, convert = strict_json(content), _windows
        if not isinstance(records, list):
            raise ValueError("Windows JSON must be an array")
    elif adapter == "syslog-rfc5424":
        records, convert = lines, _syslog
    elif adapter == "flows-csv":
        try:
            rows = list(csv.reader(io.StringIO(content, newline=""), strict=True))
        except csv.Error as exc:
            raise ValueError("Malformed flow CSV") from exc
        headers = rows[0] if rows else []
        required = {"time", "source", "destination", "protocol", "bytes"}
        if len(headers) != len(set(headers)) or not required <= set(headers) or set(headers) - required - {"action", "outcome"}:
            raise ValueError("Invalid flow CSV headers")
        records = []
        for index, row in enumerate(rows[1:], 1):
            if len(row) != len(headers):
                raise ValueError(f"Record {index}: CSV field count differs from headers")
            records.append(dict(zip(headers, row)))
        convert = _flow
    else:
        raise ValueError("Unknown event adapter")
    if not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("Expected 1..1000 records")
    result = []
    for index, record in enumerate(records, 1):
        try:
            encoded = record if isinstance(record, str) else json.dumps(record, ensure_ascii=False)
            if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
                raise ValueError("Record exceeds 8192 bytes")
            result.append(convert(record))
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ValueError(f"Record {index}: {exc}") from None
    return {"schema": "was.event/1", "adapter": adapter, "events": result,
            "count": len(result), "failed": sum(e["outcome"] == "failure" for e in result),
            "limitations": LIMITATIONS, "input_sha256": hashlib.sha256(raw).hexdigest()}


def catalog():
    return [
        {"id": "windows-json", "title": "Windows JSON", "description": "سجلات JSON مصدرة ضمن الشكل الموثق؛ دون XML أو اتصال Windows.",
         "example_content": '[{"time":"2026-01-01T00:00:00Z","event_id":4625,"actor":"demo","outcome":"failure"}]'},
        {"id": "syslog-rfc5424", "title": "Syslog RFC5424", "description": "ملف نصي؛ سجل RFC5424 إصدار 1 في كل سطر، دون مستمع شبكة.",
         "example_content": '<34>1 2026-01-01T00:00:00Z host app 123 ID47 [example@32473 key="value"] example message'},
        {"id": "flows-csv", "title": "Network flows CSV", "description": "تدفقات مصدرة بعناوين IP وعدد بايتات؛ دون التقاط شبكة.",
         "example_content": 'time,source,destination,protocol,bytes\n2026-01-01T00:00:00Z,192.0.2.1,198.51.100.2,TCP,128\n'},
    ]
