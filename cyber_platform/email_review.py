"""Offline MIME metadata review; no message bodies, addresses or filenames exported."""
import base64
import binascii
import hashlib
import re
from email import policy
from email.errors import MessageError
from email.parser import BytesParser
from email.utils import getaddresses
from .store import encode

LIMITS = {"input_bytes":4 * 1024 * 1024, "parts":100, "depth":10,
          "headers_per_part":200, "header_bytes":65536, "line_bytes":16384,
          "lines":100000, "addresses":100, "filename_characters":1024,
          "output_bytes":1024 * 1024}
LIMITATIONS = ("قراءة بنية رسالةEMLمسجلة فقط؛ لا اتصال أو استخراج أو عرض أجسام ومرفقات. "
               "النطاقات والبصمات بيانات وصفية خاصة، وأحكامSPF/DKIM/DMARCتصريحات من المصدر لا تحققًا تشفيريًا أو ثقة به. "
               "اختلاف نطاقReply-Toملاحظة تحتاج سياقًا وليس إثبات تصيد.")
_AUTH = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"}
_EXTENSIONS = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "json", "xml", "zip", "tar", "gz", "exe", "js", "html", "htm", "png", "jpg", "jpeg", "gif", "eml"}
_CONTENT_TYPES = {"text/plain", "text/html", "text/csv", "application/pdf", "application/json", "application/xml",
                  "application/octet-stream", "application/zip", "image/png", "image/jpeg", "image/gif"}


def _bad(message="Invalid or unsupported EML structure"):
    raise ValueError(message)


def _domain(address):
    if not isinstance(address, str) or address.count("@") != 1:
        _bad("Invalid EML address")
    host = address.rsplit("@", 1)[1]
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        _bad("Invalid EML address domain")
    if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.rstrip(".").split(".")):
        _bad("Invalid EML address domain")
    return host


def _domains(message, fields):
    values = []
    for field in fields:
        values.extend(str(v) for v in message.get_all(field, []))
    try:
        addresses = getaddresses(values)
    except (ValueError, TypeError, IndexError, RecursionError):
        _bad("Invalid EML address header")
    if len(addresses) > LIMITS["addresses"]:
        _bad("EML address count exceeds limits")
    if values and not any(address for _, address in addresses):
        _bad("Invalid or unsupported EML address header")
    return sorted({_domain(address) for _, address in addresses if address})


def _headers(part):
    headers = list(part.raw_items())
    if len(headers) > LIMITS["headers_per_part"]:
        _bad("EML header count exceeds limits")
    total = 0
    for name, value in headers:
        if not re.fullmatch(r"[!-9;-~]+", name):
            _bad("Invalid EML header name")
        if any(ord(c) < 32 and c not in "\r\n\t" for c in value):
            _bad("Invalid EML header text")
        try:
            total += len(name.encode()) + len(value.encode("utf-8"))
        except UnicodeError:
            _bad("Invalid EML header encoding")
        try:
            parsed = part[name]
        except (ValueError, TypeError, UnicodeError, RecursionError, IndexError, MessageError):
            _bad("Malformed EML header")
        if getattr(parsed, "defects", ()):
            _bad("Malformed EML header")
    if total > LIMITS["header_bytes"]:
        _bad("EML header bytes exceed limits")
    for name in ("content-type", "content-transfer-encoding", "content-disposition", "from", "reply-to"):
        if len(part.get_all(name, [])) > 1:
            _bad("Duplicate structural EML header")
    if part.defects:
        _bad("Malformed EML parser input")


def _decoded(part):
    payload = part.get_payload()
    if not isinstance(payload, str):
        _bad("Unsupported EML payload structure")
    transfer = str(part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
    if transfer in {"7bit", "8bit", "binary"}:
        raw = part.get_payload(decode=True)
        if not isinstance(raw, bytes):
            _bad("Unsupported EML body encoding")
        if transfer == "7bit" and any(byte >= 128 for byte in raw):
            _bad("Invalid EML 7bit payload")
        return raw
    try:
        raw = payload.encode("ascii", errors="surrogateescape")
    except UnicodeError:
        _bad("Unsupported EML body encoding")
    if transfer == "base64":
        try:
            return base64.b64decode(b"".join(raw.split()), validate=True)
        except (ValueError, binascii.Error):
            _bad("Invalid EML base64 attachment")
    if transfer == "quoted-printable":
        # Strictly validate escapes before the standard decoder; it otherwise
        # tolerates malformed escapes and can obscure the recorded byte identity.
        if re.search(rb"=(?![0-9A-Fa-f]{2}|\r?\n)", raw):
            _bad("Invalid EML quoted-printable payload")
        result = part.get_payload(decode=True)
        if not isinstance(result, bytes):
            _bad("Invalid EML quoted-printable payload")
        return result
    _bad("Unsupported EML transfer encoding")


def analyze(data):
    if not isinstance(data, bytes) or not data or len(data) > LIMITS["input_bytes"]:
        _bad("EML input must be nonempty and at most 4 MiB")
    lines = data.splitlines()
    if len(lines) > LIMITS["lines"] or any(len(line) > LIMITS["line_bytes"] for line in lines):
        _bad("EML line limits exceeded")
    if b"\x00" in data:
        _bad("NUL bytes are unsupported in EML")
    # Preflight MIME boundary markers limits large part allocations before the
    # parser creates its object graph. The post-parse counter remains authoritative.
    if sum(line.startswith(b"--") for line in lines) > LIMITS["parts"] * 2:
        _bad("EML boundary count exceeds limits")
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except (ValueError, TypeError, RecursionError, IndexError, MessageError) as exc:
        raise ValueError("Invalid EML parser structure") from exc
    if not list(message.raw_items()):
        _bad("EML requires message headers")
    stack, part_count, attachments = [(message, 0)], 0, []
    while stack:
        part, depth = stack.pop(); part_count += 1
        if part_count > LIMITS["parts"] or depth > LIMITS["depth"]:
            _bad("EML MIME structure exceeds limits")
        _headers(part)
        content_type = part.get_content_type().lower()
        if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", content_type) or len(content_type) > 100:
            _bad("Invalid EML content type")
        if content_type.startswith("message/"):
            _bad("Encapsulated EML messages are unsupported")
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if disposition not in {None, "inline", "attachment"}:
            _bad("Unsupported EML disposition")
        if part.is_multipart():
            if filename is not None or disposition == "attachment":
                _bad("Multipart EML attachment containers are unsupported")
            children = part.get_payload()
            if not isinstance(children, list):
                _bad("Invalid EML multipart payload")
            stack.extend((child, depth + 1) for child in reversed(children))
            continue
        decoded = _decoded(part)
        if disposition == "attachment" or filename is not None:
            if filename is None:
                filename = ""
            if not isinstance(filename, str) or len(filename) > LIMITS["filename_characters"] or any(ord(c) < 32 or ord(c) == 127 for c in filename):
                _bad("Invalid EML attachment filename")
            try:
                name_bytes = filename.encode("utf-8")
            except UnicodeError:
                _bad("Invalid EML attachment filename")
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown"
            attachments.append({"filename_sha256":hashlib.sha256(name_bytes).hexdigest(),
                                "extension":extension if extension in _EXTENSIONS else "unknown",
                                "content_type":content_type if content_type in _CONTENT_TYPES else "other", "decoded_bytes":len(decoded),
                                "sha256":hashlib.sha256(decoded).hexdigest()})
    domains = {"from":_domains(message, ["From"]), "to":_domains(message, ["To", "Cc"]), "reply_to":_domains(message, ["Reply-To"])}
    auth_claims = []
    for header in message.get_all("Authentication-Results", []):
        for mechanism, status in re.findall(r"(?:^|[;\s])(spf|dkim|dmarc)\s*=\s*([a-z]+)(?=[;\s(]|$)", str(header).lower()):
            if status in _AUTH:
                auth_claims.append({"mechanism":mechanism, "result":status, "verification":"source_claim_only"})
    findings = []
    if domains["from"] and domains["reply_to"] and domains["from"] != domains["reply_to"]:
        findings.append({"code":"reply_domain_differs", "message":"نطاقReply-Toالمعلن مختلف عنFrom؛ يحتاج سياقًا ولا يثبت تصيدًا."})
    if any(a["result"] in {"fail", "softfail", "permerror"} for a in auth_claims):
        findings.append({"code":"reported_auth_failure", "message":"تتضمن رؤوس المصدر تصريح فشل مصادقة؛ لم يتحقق التطبيق من صدقه."})
    result = {"schema":"was.email-analysis/1", "part_count":part_count, "attachment_count":len(attachments),
              "domains":domains, "attachments":attachments, "auth_claims":auth_claims,
              "auth_verification":"source_claims_only", "findings":findings,
              "source_sha256":hashlib.sha256(data).hexdigest(), "network":False, "content_exported":False,
              "extracted":False, "limits":dict(LIMITS), "limitations":LIMITATIONS}
    if len(encode(result).encode()) > LIMITS["output_bytes"]:
        _bad("EML metadata output exceeds limits")
    return result


def sample():
    return ('From: Synthetic <sender@example.test>\r\nTo: recipient@example.net\r\nReply-To: reply@example.test\r\n'
            'Authentication-Results: synthetic.example.test; spf=pass; dkim=pass; dmarc=pass\r\n'
            'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="synthetic-boundary"\r\n\r\n'
            '--synthetic-boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSynthetic private body.\r\n'
            '--synthetic-boundary\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename="example.txt"\r\n'
            'Content-Transfer-Encoding: base64\r\n\r\nU3ludGhldGljIGF0dGFjaG1lbnQ=\r\n'
            '--synthetic-boundary--\r\n')
