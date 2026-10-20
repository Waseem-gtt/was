"""Bounded offline X.509 inspection; provided signatures never establish trust."""
import hashlib
import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa

from .event_adapters import strict_json

MAX_BYTES = 256 * 1024
MAX_CERTIFICATES = 10
MAX_NAMES = 100
MAX_EXTENSIONS = 50
NOTICE = ("فحص ملفات شهادات وروابط توقيع مباشرة فقط؛ وجود شهادة جذر ضمن الملف لا يجعلها موثوقة. "
          "لا تحقق PKIX كاملًا أو اسم مضيف أو إلغاء OCSP/CRL أو مخزن ثقة أو اتصال شبكة.")
_PEM = re.compile(br"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")
# Public certificate only. The temporary synthetic signing key was discarded.
_SAMPLE = """-----BEGIN CERTIFICATE-----
MIIBazCCARGgAwIBAgICMskwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwWc3ludGhl
dGljLmV4YW1wbGUudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBa
MCExHzAdBgNVBAMMFnN5bnRoZXRpYy5leGFtcGxlLnRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT2M+hfRJ1weYCHnJg+rwxCNwg/j+cIXpUTeZGUuedrk1fu
5S4nO282UoqRMZ0mJJo7kMIcTJZf8/M+vIcNJPcnozkwNzASBgNVHRMBAf8ECDAG
AQH/AgEAMCEGA1UdEQQaMBiCFnN5bnRoZXRpYy5leGFtcGxlLnRlc3QwCgYIKoZI
zj0EAwIDSAAwRQIhAKswBOvOaeyiNEq44FrAVZGXVoFFoFMjVgDfLqNyiEKrAiBD
NaqAfrNQ9TQmz8+b5Lk+7Roypi2Jn51EcPSjQQ6NkQ==
-----END CERTIFICATE-----
"""


def sample():
    return {"certificates_pem": _SAMPLE, "validation_time": "2026-10-20T00:00:00Z"}


def _text(value, maximum=4096):
    if not isinstance(value, str) or len(value.encode()) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Certificate text exceeds the documented limit or has control characters")
    return value


def _time(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise ValueError("validation_time requires RFC3339 with an explicit offset")
    if value[-6:-5] in {"+", "-"} and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise ValueError("Invalid validation_time offset")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _inputs(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise ValueError("Certificate input must be 1..256 KiB")
    at = None
    content = data
    if data.lstrip().startswith(b"{"):
        value = strict_json(data)
        if not isinstance(value, dict) or not {"certificates_pem"} <= set(value) or set(value) - {"certificates_pem", "validation_time"} or not isinstance(value["certificates_pem"], str):
            raise ValueError("Expected certificates_pem and optional validation_time only")
        content = value["certificates_pem"].encode()
        if "validation_time" in value:
            at = _time(value["validation_time"])
    if not content or len(content) > MAX_BYTES:
        raise ValueError("Empty or oversized certificate bundle")
    try:
        if content.lstrip().startswith(b"-----"):
            chunks = list(_PEM.finditer(content))
            if not 1 <= len(chunks) <= MAX_CERTIFICATES:
                raise ValueError("Expected 1..10 CERTIFICATE blocks")
            cursor = 0
            for match in chunks:
                if content[cursor:match.start()].strip():
                    raise ValueError("Only certificate PEM blocks and whitespace are accepted")
                cursor = match.end()
            if content[cursor:].strip():
                raise ValueError("Trailing data or private keys are not certificate input")
            certificates = [x509.load_pem_x509_certificate(match.group()) for match in chunks]
        else:
            certificate = x509.load_der_x509_certificate(content)
            if certificate.public_bytes(serialization.Encoding.DER) != content:
                raise ValueError("Expected exactly one canonical DER certificate without trailing data")
            certificates = [certificate]
        fingerprints = [cert.fingerprint(hashes.SHA256()).hex() for cert in certificates]
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError("Duplicate certificate in bundle")
        return certificates, at
    except (TypeError, UnicodeError, UnsupportedAlgorithm, OverflowError) as exc:
        raise ValueError("Invalid or unsupported X.509 certificate") from exc


def _extension(cert, extension_type):
    try:
        return cert.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def _verify(cert, issuer):
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            parameters = cert.signature_algorithm_parameters
            if not isinstance(parameters, (padding.PKCS1v15, padding.PSS)):
                return "unsupported"
            key.verify(cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            parameters = cert.signature_algorithm_parameters
            if not isinstance(parameters, ec.ECDSA):
                return "unsupported"
            key.verify(cert.signature, cert.tbs_certificate_bytes, parameters)
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return "unsupported"
        return "valid"
    except InvalidSignature:
        return "invalid"
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "unsupported"


def _key(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": public_key.key_size}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "bits": public_key.key_size, "curve": public_key.curve.name}
    if isinstance(public_key, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": public_key.key_size}
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "bits": 256}
    if isinstance(public_key, ed448.Ed448PublicKey):
        return {"type": "Ed448", "bits": 456}
    return {"type": "unsupported", "bits": None}


def _san(cert):
    extension = _extension(cert, x509.SubjectAlternativeName)
    if extension is None:
        return []
    if len(extension) > MAX_NAMES:
        raise ValueError("Certificate SAN count exceeds 100")
    names = []
    for name in extension:
        if isinstance(name, x509.OtherName):
            if len(name.value) > 512:
                raise ValueError("Certificate OtherName exceeds 512 bytes")
            names.append({"type": "OtherName", "oid": name.type_id.dotted_string, "value_hex": name.value.hex()})
        elif isinstance(name, x509.DirectoryName):
            names.append({"type": "DirectoryName", "value": _text(name.value.rfc4514_string())})
        elif isinstance(name, x509.RegisteredID):
            names.append({"type": "RegisteredID", "value": name.value.dotted_string})
        else:
            names.append({"type": type(name).__name__, "value": _text(str(name.value))})
    return names


def _inspect(cert, at):
    if len(cert.extensions) > MAX_EXTENSIONS:
        raise ValueError("Certificate extension count exceeds 50")
    subject, issuer = _text(cert.subject.rfc4514_string()), _text(cert.issuer.rfc4514_string())
    key = _key(cert.public_key())
    try:
        signature_hash = cert.signature_hash_algorithm
        hash_name = signature_hash.name if signature_hash else None
    except UnsupportedAlgorithm:
        hash_name = "unsupported"
    constraints = _extension(cert, x509.BasicConstraints)
    usage = _extension(cert, x509.KeyUsage)
    eku = _extension(cert, x509.ExtendedKeyUsage)
    if eku is not None and len(eku) > MAX_NAMES:
        raise ValueError("Certificate EKU count exceeds 100")
    key_usage = None
    if usage is not None:
        key_usage = {name: getattr(usage, name) for name in (
            "digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
            "key_agreement", "key_cert_sign", "crl_sign")}
        key_usage["encipher_only"] = usage.encipher_only if usage.key_agreement else None
        key_usage["decipher_only"] = usage.decipher_only if usage.key_agreement else None
    warnings = []
    if key["type"] in {"RSA", "DSA"} and key["bits"] < 2048 or key["type"] == "EC" and key["bits"] < 224:
        warnings.append("weak_public_key_size")
    if hash_name in {"md5", "sha1"}:
        warnings.append("weak_signature_hash")
    if hash_name == "unsupported":
        warnings.append("unsupported_signature_algorithm")
    unknown_critical = [extension.oid.dotted_string for extension in cert.extensions
                        if extension.critical and isinstance(extension.value, x509.UnrecognizedExtension)]
    if unknown_critical:
        warnings.append("unrecognized_critical_extensions")
    not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
    time_status = "not_evaluated" if at is None else "not_yet_valid" if at < not_before else "expired" if at > not_after else "within_validity_period"
    return {"sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "spki_sha256": hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
            "subject": subject, "issuer": issuer, "serial": str(cert.serial_number),
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(), "time_status": time_status,
            "key": key, "signature": {"oid": cert.signature_algorithm_oid.dotted_string, "hash": hash_name},
            "subject_alt_names": _san(cert),
            "basic_constraints": {"ca": constraints.ca, "path_length": constraints.path_length} if constraints else None,
            "key_usage": key_usage, "extended_key_usage": [oid.dotted_string for oid in eku] if eku else [],
            "unrecognized_critical_extensions": unknown_critical,
            "self_issued": cert.subject == cert.issuer,
            "self_signature": _verify(cert, cert) if cert.subject == cert.issuer else "not_evaluated",
            "warnings": warnings}


def analyze(data):
    """Inspect public certificate files without network or implicit trust anchors."""
    certificates, at = _inputs(data)
    try:
        inspected = [_inspect(cert, at) for cert in certificates]
        links = []
        for child_index, child in enumerate(certificates):
            for issuer_index, issuer in enumerate(certificates):
                if child_index == issuer_index or child.issuer != issuer.subject:
                    continue
                constraints = _extension(issuer, x509.BasicConstraints)
                usage = _extension(issuer, x509.KeyUsage)
                links.append({"certificate": child_index, "issuer": issuer_index,
                              "signature": _verify(child, issuer),
                              "issuer_is_ca": constraints.ca if constraints else None,
                              "issuer_key_cert_sign": usage.key_cert_sign if usage else None,
                              "trusted": False})
        return {"schema": "was.certificate-analysis/1", "certificate_count": len(certificates),
                "certificates": inspected, "chain_links": links,
                "validation_time": at.isoformat() if at else None,
                "trust": "not_evaluated", "network": False, "limitations": NOTICE,
                "limits": {"input_bytes": MAX_BYTES, "certificates": MAX_CERTIFICATES,
                           "subject_alt_names": MAX_NAMES, "extensions": MAX_EXTENSIONS}}
    except (ValueError, TypeError, UnsupportedAlgorithm, x509.DuplicateExtension, OverflowError, UnicodeError) as exc:
        raise ValueError("Invalid or unsupported certificate fields: " + str(exc)[:200]) from exc
