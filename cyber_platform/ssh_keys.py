"""Offline OpenSSH public key metadata; never authenticates or executes options."""
import base64
import hashlib
import re
import struct
import unicodedata
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

LIMITS = {'input_bytes':4 * 1024 * 1024, 'keys':1000, 'lines':2000, 'line_bytes':8192,
          'options_per_key':32, 'rsa_bits':16384}
_ALGORITHMS = {'ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521'}
_FLAGS = {'restrict','cert-authority','no-agent-forwarding','no-port-forwarding','no-pty','no-user-rc',
          'no-x11-forwarding','no-touch-required','verify-required','touch-required'}
_VALUES = {'command','environment','from','principals','expiry-time','permitopen','permitlisten','tunnel'}
LIMITATIONS = ('مراجعة بيانات مفاتيحOpenSSHالعامة وصيغةauthorized_keysالموثقة؛ لا اتصال أو مصادقةSSH '
               'أو تحقق هوية صاحب المفتاح أو تفعيل صلاحياته. لا تُصدّر التعليقات أو قيم خيارات الأوامر والبيئة؛ '
               'لا تدعم المفاتيح الخاصة أو known_hosts أو شهاداتSSH. الملاحظات ليست شهادة سلامة.')


def _bad(message='Invalid or unsupported OpenSSH public key input'):
    raise ValueError(message)


def _token(line, pos):
    """One whitespace-separated token, respecting double-quoted option values."""
    begin, quoted, escaped = pos, False, False
    while pos < len(line):
        c = line[pos]
        if escaped:
            escaped = False
        elif c == '\\':
            escaped = True
        elif c == '"':
            quoted = not quoted
        elif c.isspace() and not quoted:
            break
        pos += 1
    if quoted or escaped:
        _bad('Unterminated authorized_keys quoted option')
    return line[begin:pos], pos


def _options(value):
    pieces, start, quoted, escaped = [], 0, False, False
    for i, c in enumerate(value):
        if escaped:
            escaped = False
        elif c == '\\':
            escaped = True
        elif c == '"':
            quoted = not quoted
        elif c == ',' and not quoted:
            pieces.append(value[start:i]); start = i + 1
    if quoted or escaped:
        _bad()
    pieces.append(value[start:])
    if len(pieces) > LIMITS['options_per_key']:
        _bad('Authorized key option count exceeds limit')
    names = []
    for piece in pieces:
        name, sep, content = piece.partition('=')
        name = name.lower()
        if not re.fullmatch(r'[a-z][a-z0-9-]*', name) or name in names:
            _bad('Invalid or duplicate authorized key option')
        if name in _FLAGS:
            if sep:
                _bad('Flag option cannot have a value')
        elif name in _VALUES:
            if not sep or not content:
                _bad('Authorized key option requires a value')
            if content.startswith('"'):
                if not content.endswith('"') or len(content) < 3:
                    _bad()
                inner, escaping = content[1:-1], False
                for c in inner:
                    if escaping:
                        escaping = False
                    elif c == '\\':
                        escaping = True
                    elif c == '"':
                        _bad()
                if escaping:
                    _bad()
            elif any(c in content for c in ('"','\\')):
                _bad()
        else:
            _bad('Unknown authorized key option; known_hosts is unsupported')
        names.append(name)
    return sorted(names)


def analyze(data):
    if not isinstance(data, bytes) or len(data) > LIMITS['input_bytes']:
        _bad('SSH public key input exceeds 4 MiB')
    try:
        text = data.decode('utf-8')
    except UnicodeError as exc:
        raise ValueError('SSH public key input must be UTF-8') from exc
    if any(unicodedata.category(c).startswith('C') for c in text if c not in '\n\r\t'):
        _bad('SSH public key input contains control characters')
    lines = text.splitlines()
    if len(lines) > LIMITS['lines']:
        _bad('SSH line count exceeds limit')
    keys, findings, known = [], [], set()
    for raw in lines:
        if len(raw.encode()) > LIMITS['line_bytes']:
            _bad('SSH line exceeds 8192 bytes')
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if len(keys) >= LIMITS['keys']:
            _bad('SSH key count exceeds limit')
        first, pos = _token(line, 0)
        names = []
        if first in _ALGORITHMS:
            algorithm = first
        else:
            names = _options(first)
            pos = len(line) - len(line[pos:].lstrip())
            algorithm, pos = _token(line, pos)
            if algorithm not in _ALGORITHMS:
                _bad('Unsupported SSH key algorithm')
        while pos < len(line) and line[pos].isspace():
            pos += 1
        blob, finish = _token(line, pos)
        if not blob or any(c.isspace() for c in blob):
            _bad('Missing SSH public key blob')
        try:
            binary = base64.b64decode(blob, validate=True)
            if base64.b64encode(binary).decode() != blob:
                _bad('SSH key blob is not canonical base64')
            if len(binary) < 4:
                _bad()
            size = struct.unpack_from('!I', binary)[0]
            if size > len(binary) - 4 or binary[4:4 + size].decode('ascii') != algorithm:
                _bad('SSH declared algorithm and blob disagree')
            key = serialization.load_ssh_public_key((algorithm + ' ' + blob).encode())
        except (ValueError, TypeError, UnicodeError, UnsupportedAlgorithm, struct.error) as exc:
            raise ValueError('Invalid or unsupported SSH public key blob') from exc
        if isinstance(key, rsa.RSAPublicKey):
            bits = key.key_size
            if bits > LIMITS['rsa_bits']:
                _bad('RSA public key exceeds 16384 bits')
            kind = 'RSA'
        elif isinstance(key, ed25519.Ed25519PublicKey):
            bits, kind = 256, 'Ed25519'
        elif isinstance(key, ec.EllipticCurvePublicKey):
            bits, kind = key.key_size, 'ECDSA'
        else:
            _bad('Unsupported SSH key algorithm')
        # Round-trip encoding also rejects noncanonical/trailing key blob fields.
        encoded = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[1]
        if encoded.decode() != blob:
            _bad('SSH key blob is noncanonical or contains trailing fields')
        digest = hashlib.sha256(binary).digest()
        sha = digest.hex()
        index = len(keys)
        keys.append({'index':index, 'type':kind, 'bits':bits, 'sha256':sha,
                     'fingerprint':'SHA256:' + base64.b64encode(digest).decode().rstrip('='), 'option_names':names})
        def add(code, message):
            findings.append({'key':index, 'code':code, 'message':message})
        if sha in known:
            add('duplicate_key', 'The same public key appears more than once')
        known.add(sha)
        if kind == 'RSA' and bits < 2048:
            add('weak_rsa_size', 'RSA key is smaller than the review threshold of 2048 bits')
        for option in ('command','environment','cert-authority','no-touch-required'):
            if option in names:
                add('option_' + option.replace('-', '_'), 'A privileged or execution-related authorized key option requires owner review')
    if not keys:
        _bad('No supported SSH public keys found')
    return {'schema':'was.ssh-key-review/1', 'key_count':len(keys), 'keys':keys, 'findings':findings,
            'summary':{'unique_keys':len(known), 'duplicate_keys':len(keys) - len(known),
                       'rsa_keys':sum(k['type'] == 'RSA' for k in keys), 'findings':len(findings)},
            'source_sha256':hashlib.sha256(data).hexdigest(), 'network':False, 'authenticated':False,
            'limits':dict(LIMITS), 'limitations':LIMITATIONS}


def sample():
    # Public material only. No private key is generated or persisted here.
    algorithm = b'ssh-ed25519'
    blob = struct.pack('!I', len(algorithm)) + algorithm + struct.pack('!I', 32) + bytes(range(1, 33))
    return 'restrict ssh-ed25519 ' + base64.b64encode(blob).decode() + ' synthetic public key\n'
