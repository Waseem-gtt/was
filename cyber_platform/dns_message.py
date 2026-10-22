"""Bounded offline DNS wire parsing; never issues DNS queries or exports TXT."""
import base64
import binascii
import hashlib
import ipaddress
import struct
from .event_adapters import strict_json

LIMITS = {"input_bytes":4 * 1024 * 1024, "message_bytes":65535, "questions_and_records":1000,
          "name_steps":128, "label_bytes":63, "expanded_name_bytes":255}
_TYPES = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",28:"AAAA",33:"SRV",41:"OPT",255:"ANY"}
_CLASSES = {1:"IN",3:"CH",4:"HS",254:"NONE",255:"ANY"}
NOTICE = ("تحليل رسالة DNS مسجلة فقط دون استعلام أو إعادة تجميع نقل؛ أعلام المصادقة تصريحات المصدر، "
          "ولا تحقق DNSSEC أو أصالة الرد. لا يُصدّر نص TXT أو محتوى RDATA غير المدعوم.")


def _bad(message="Malformed or unsupported DNS message"):
    raise ValueError(message)


def _input(data):
    if not isinstance(data, bytes) or len(data) > LIMITS["input_bytes"]:
        _bad("DNS input exceeds 4 MiB")
    # DNS headers include zero bytes for bounded counts. A JSON envelope does not.
    if data.lstrip().startswith(b'{') and b'\x00' not in data[:12]:
        try:
            value = strict_json(data.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {"dns_base64"} or not isinstance(value["dns_base64"], str):
                _bad("DNS envelope requires exactly dns_base64")
            message = base64.b64decode(value["dns_base64"], validate=True)
        except (UnicodeError, ValueError, RecursionError, binascii.Error) as exc:
            raise ValueError("Invalid DNS base64 envelope") from exc
        encoding = "base64-json"
    else:
        message, encoding = data, "wire"
    if not 12 <= len(message) <= LIMITS["message_bytes"]:
        _bad("DNS message must contain 12 to 65535 bytes")
    return message, encoding


def analyze(data):
    message, encoding = _input(data)
    identifier, flags, nq, na, ns, nx = struct.unpack('!6H', message[:12])
    if nq + na + ns + nx > LIMITS["questions_and_records"]:
        _bad("DNS question and record count exceeds 1000")
    if flags & 0x0040:
        _bad("DNS reserved header bit is set")
    label_offsets = set()

    def name(offset, limit=None):
        bound = len(message) if limit is None else limit
        cursor, consumed, jumped, labels, seen, expanded = offset, offset, False, [], set(), 1
        for _ in range(LIMITS["name_steps"]):
            if cursor in seen or cursor >= len(message) or (not jumped and cursor >= bound):
                _bad("Invalid DNS name or compression loop")
            seen.add(cursor)
            length = message[cursor]
            if length & 0xc0 == 0xc0:
                if cursor + 2 > len(message) or (not jumped and cursor + 2 > bound):
                    _bad("Truncated DNS name pointer")
                target = ((length & 0x3f) << 8) | message[cursor + 1]
                if target < 12 or target >= cursor or target not in label_offsets:
                    _bad("DNS pointer must reference an earlier label")
                label_offsets.add(cursor)
                if not jumped:
                    consumed = cursor + 2
                cursor, jumped = target, True
                continue
            if length & 0xc0:
                _bad("Unsupported DNS label encoding")
            label_offsets.add(cursor)
            cursor += 1
            if length == 0:
                if not jumped:
                    consumed = cursor
                return '.'.join(labels) or '.', consumed
            if length > LIMITS["label_bytes"] or cursor + length > len(message) or (not jumped and cursor + length > bound):
                _bad("Truncated DNS label")
            raw = message[cursor:cursor + length]
            if any(c < 33 or c > 126 or c in (46, 92) for c in raw):
                _bad("DNS label is outside the supported printable ASCII subset")
            expanded += length + 1
            if expanded > LIMITS["expanded_name_bytes"]:
                _bad("Expanded DNS name exceeds 255 bytes")
            labels.append(raw.decode('ascii').lower())
            cursor += length
            if not jumped:
                consumed = cursor
        _bad("DNS name traversal exceeds limit")

    offset, questions, records = 12, [], []
    for _ in range(nq):
        domain, offset = name(offset)
        if offset + 4 > len(message):
            _bad("Truncated DNS question")
        kind, klass = struct.unpack('!HH', message[offset:offset + 4]); offset += 4
        questions.append({"name":domain, "type":_TYPES.get(kind, str(kind)), "type_id":kind,
                          "class":_CLASSES.get(klass, str(klass)), "class_id":klass})
    for section, count in (("answer", na), ("authority", ns), ("additional", nx)):
        for _ in range(count):
            domain, offset = name(offset)
            if offset + 10 > len(message):
                _bad("Truncated DNS record header")
            kind, klass, ttl, length = struct.unpack('!HHIH', message[offset:offset + 10]); offset += 10
            end = offset + length
            if end > len(message):
                _bad("Truncated DNS record data")
            raw = message[offset:end]
            if kind == 1:
                if length != 4:
                    _bad("Invalid DNS A record length")
                result = {"address":str(ipaddress.IPv4Address(raw))}
            elif kind == 28:
                if length != 16:
                    _bad("Invalid DNS AAAA record length")
                result = {"address":str(ipaddress.IPv6Address(raw))}
            elif kind in (2, 5, 12):
                target, consumed = name(offset, end)
                if consumed != end:
                    _bad("Trailing data in DNS name record")
                result = {"name":target}
            elif kind in (15, 33):
                prefix = 2 if kind == 15 else 6
                if length < prefix + 1:
                    _bad("Truncated DNS MX or SRV record")
                target, consumed = name(offset + prefix, end)
                if consumed != end:
                    _bad("Trailing data in DNS service record")
                if kind == 15:
                    result = {"preference":struct.unpack('!H',raw[:2])[0], "exchange":target}
                else:
                    priority, weight, port = struct.unpack('!HHH', raw[:6])
                    result = {"priority":priority, "weight":weight, "port":port, "target":target}
            elif kind == 6:
                primary, cursor = name(offset, end); responsible, cursor = name(cursor, end)
                if cursor + 20 != end:
                    _bad("Invalid DNS SOA record length")
                numbers = struct.unpack('!5I', message[cursor:end])
                result = {"primary":primary, "responsible":responsible,
                          **dict(zip(("serial","refresh","retry","expire","minimum"), numbers))}
            elif kind == 16:
                cursor, lengths = 0, []
                if length == 0:
                    _bad("DNS TXT record needs a character string")
                while cursor < len(raw):
                    size = raw[cursor]; cursor += 1
                    if cursor + size > len(raw):
                        _bad("Truncated DNS TXT character string")
                    lengths.append(size); cursor += size
                result = {"string_count":len(lengths), "lengths":lengths}
            else:
                result = {"bytes":length}
            records.append({"section":section, "name":domain, "type":_TYPES.get(kind,str(kind)), "type_id":kind,
                            "class":_CLASSES.get(klass,str(klass)), "class_id":klass, "ttl":ttl, "data":result})
            offset = end
    if offset != len(message):
        _bad("Trailing bytes after DNS message")
    return {"schema":"was.dns-analysis/1", "id":identifier,
            "flags":{"response":bool(flags & 0x8000), "opcode":(flags >> 11) & 15,
                     "authoritative_claim":bool(flags & 0x0400), "truncated_claim":bool(flags & 0x0200),
                     "recursion_desired":bool(flags & 0x0100), "recursion_available_claim":bool(flags & 0x0080),
                     "authenticated_data_claim":bool(flags & 0x0020), "checking_disabled":bool(flags & 0x0010), "rcode":flags & 15},
            "question_count":len(questions), "record_count":len(records), "questions":questions, "records":records,
            "source_sha256":hashlib.sha256(data).hexdigest(), "message_sha256":hashlib.sha256(message).hexdigest(),
            "input_encoding":encoding, "network":False, "dnssec_verified":False,
            "limits":dict(LIMITS), "limitations":NOTICE}


def sample():
    question = b'\x07example\x04test\x00' + struct.pack('!HH',1,1)
    answer = b'\xc0\x0c' + struct.pack('!HHIH',1,1,300,4) + bytes((192,0,2,1))
    message = struct.pack('!6H',1234,0x8180,1,1,0,0) + question + answer
    return {"dns_base64":base64.b64encode(message).decode()}
