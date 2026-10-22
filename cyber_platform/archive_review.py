"""Bounded ZIP/TAR metadata inspection; never decompresses or extracts members."""
import base64
import hashlib
import struct
import unicodedata
from .event_adapters import strict_json

LIMITS = {'input_bytes': 4 * 1024 * 1024, 'members': 2000, 'name_bytes': 1000}
LIMITATIONS = ('فحص بيانات وصفية فقط لصيغ ZIPالكلاسيكي وTARالموثقة؛ لا استخراج أو فك ضغط أو تحقق CRC. '
               'الأحجام ونسب الضغط تصريحات الأرشيف، وليست تحققًا من المحتوى أو ضمانًا لاستخراج آمن. '
               'ZIP64 والأقراص المتعددة وPAX وGNUlong وTARالمضغوط وحقول تغيير الاسم/الرابط غير مدعومة.')
_BAD_EXTRA = {0x0001, 0x7075, 0x000d, 0x756e}


def _bad(message='Invalid or unsupported archive structure'):
    raise ValueError(message)


def _name(value):
    if not value or len(value.encode('utf-8')) > LIMITS['name_bytes'] or any(unicodedata.category(c).startswith('C') for c in value):
        _bad('Invalid archive member name')
    return value


def _extra(data):
    pos = 0
    while pos < len(data):
        if len(data) - pos < 4:
            _bad()
        kind, size = struct.unpack_from('<HH', data, pos)
        pos += 4
        if pos + size > len(data) or kind in _BAD_EXTRA:
            _bad('Unsupported archive extra field')
        pos += size


def _zip(data):
    # A small bounded backward scan locates the only EOCD ending at EOF.
    matches = []
    for pos in range(max(0, len(data) - 65557), max(0, len(data) - 21)):
        if data[pos:pos + 4] == b'PK\x05\x06' and pos + 22 <= len(data):
            values = struct.unpack_from('<4s4H2IH', data, pos)
            if pos + 22 + values[-1] == len(data):
                matches.append((pos, values))
    if len(matches) != 1:
        _bad('ZIP requires one final classic directory record')
    end, values = matches[0]
    _, disk, directory_disk, count_disk, count, size, start, _ = values
    if disk or directory_disk or count_disk != count or count == 65535 or size == 0xffffffff or start == 0xffffffff:
        _bad('ZIP64 or multiple disks are unsupported')
    if count > LIMITS['members'] or start + size != end:
        _bad('ZIP directory bounds or member count invalid')
    members, local_regions = [], []
    pos = start
    for index in range(count):
        if pos + 46 > end or data[pos:pos + 4] != b'PK\x01\x02':
            _bad('Truncated ZIP directory')
        row = struct.unpack_from('<4s6H3I5H2I', data, pos)
        _, made, needed, flags, method, _, _, crc, compressed, expanded, nlen, xlen, clen, member_disk, _, attributes, offset = row
        if needed >= 45 or member_disk or compressed == 0xffffffff or expanded == 0xffffffff or offset == 0xffffffff:
            _bad('Unsupported ZIP member version or bounds')
        if flags & ~(0x0001 | 0x0008 | 0x0800) or method not in {0, 8, 12, 14, 93, 99}:
            _bad('Unsupported ZIP member flags or compression metadata')
        if pos + 46 + nlen + xlen + clen > end or not 0 < nlen <= LIMITS['name_bytes']:
            _bad()
        name_raw = data[pos + 46:pos + 46 + nlen]
        try:
            name = _name(name_raw.decode('utf-8' if flags & 0x800 else 'cp437'))
        except UnicodeError as exc:
            raise ValueError('Invalid ZIP filename encoding') from exc
        _extra(data[pos + 46 + nlen:pos + 46 + nlen + xlen])
        if offset + 30 > start or data[offset:offset + 4] != b'PK\x03\x04':
            _bad('Invalid ZIP local header')
        local = struct.unpack_from('<4s5H3I2H', data, offset)
        _, lv, lf, lm, _, _, lc, ls, le, ln, lx = local
        body = offset + 30 + ln + lx
        if (lv, lf, lm) != (needed, flags, method) or body + compressed > start or data[offset + 30:offset + 30 + ln] != name_raw:
            _bad('ZIP local and directory metadata disagree')
        if not flags & 8 and (lc, ls, le) != (crc, compressed, expanded):
            _bad('ZIP local and directory sizes disagree')
        if flags & 8 and any(value not in (0, expected) for value, expected in ((lc, crc), (ls, compressed), (le, expanded))):
            _bad('Invalid ZIP streaming size metadata')
        _extra(data[offset + 30 + ln:body])
        finish = body + compressed
        if flags & 8:
            if data[finish:finish + 4] == b'PK\x07\x08':
                finish += 4
            if finish + 12 > start or struct.unpack_from('<III', data, finish) != (crc, compressed, expanded):
                _bad('Invalid ZIP data descriptor')
            finish += 12
        mode = (attributes >> 16) & 0xffff if made >> 8 == 3 else 0
        kind = {0o120000:'symlink',0o040000:'directory',0o010000:'fifo',0o020000:'character_device',0o060000:'block_device',0o140000:'socket'}.get(mode & 0o170000, 'directory' if name.endswith('/') else 'file')
        if method == 0 and not flags & 1 and compressed != expanded:
            _bad('Stored ZIP member sizes disagree')
        members.append({'index':index, 'name':name, 'type':kind, 'size':expanded,
                        'compressed_size':compressed, 'mode':mode, 'encrypted':bool(flags & 1), 'link_target':None})
        local_regions.append((offset, finish))
        pos += 46 + nlen + xlen + clen
    if pos != end:
        _bad('ZIP directory contains unaccounted bytes')
    previous = 0
    for begin, finish in sorted(local_regions):
        if begin != previous or finish < begin:
            _bad('ZIP member regions overlap or contain unaccounted data')
        previous = finish
    if previous != start:
        _bad('ZIP contains an unsupported prefix or overlay')
    return members


def _octal(raw):
    if raw and raw[0] & 128:
        _bad('TAR binary numeric fields are unsupported')
    text = raw.rstrip(b'\0 ').lstrip(b' ')
    if not text:
        return 0
    if any(c not in b'01234567' for c in text):
        _bad('Invalid TAR octal field')
    return int(text, 8)


def _tar_text(raw):
    value, marker, rest = raw.partition(b'\0')
    if marker and any(rest):
        _bad('Invalid TAR text padding')
    try:
        return value.decode('utf-8')
    except UnicodeError as exc:
        raise ValueError('TAR text must be UTF-8') from exc


def _tar(data):
    if len(data) % 512 or len(data) < 1024:
        _bad('TAR requires aligned headers and final zero blocks')
    members, pos = [], 0
    kinds = {b'0':'file', b'\0':'file', b'1':'hardlink', b'2':'symlink', b'3':'character_device',
             b'4':'block_device', b'5':'directory', b'6':'fifo'}
    while pos + 512 <= len(data):
        header = data[pos:pos + 512]
        if not any(header):
            if pos + 1024 > len(data) or any(data[pos:]):
                _bad('TAR requires two zero blocks and no trailing payload')
            return members
        if len(members) >= LIMITS['members']:
            _bad('Archive member count exceeds limit')
        expected = _octal(header[148:156])
        if sum(header[:148]) + 8 * 32 + sum(header[156:]) != expected:
            _bad('Invalid TAR header checksum')
        magic = header[257:263]
        if magic not in (b'\0' * 6, b'ustar\0') or magic == b'ustar\0' and header[263:265] != b'00':
            _bad('Unsupported TAR dialect')
        kind = kinds.get(header[156:157])
        if kind is None:
            _bad('PAX, GNU long names or unsupported TAR member types')
        name = _tar_text(header[:100])
        prefix = _tar_text(header[345:500]) if magic == b'ustar\0' else ''
        if prefix:
            name = prefix + '/' + name
        name = _name(name)
        size, mode = _octal(header[124:136]), _octal(header[100:108])
        link = _tar_text(header[157:257])
        if link:
            _name(link)
        if kind in {'symlink', 'hardlink'} and (not link or size) or kind not in {'symlink', 'hardlink'} and link:
            _bad('Invalid TAR link metadata')
        if kind != 'file' and size:
            _bad('Non-file TAR member has a payload')
        finish = pos + 512 + ((size + 511) // 512) * 512
        if finish > len(data) or any(data[pos + 512 + size:finish]):
            _bad('Truncated TAR member or invalid padding')
        members.append({'index':len(members), 'name':name, 'type':kind, 'size':size,
                        'compressed_size':size, 'mode':mode, 'encrypted':False, 'link_target':link or None})
        pos = finish
    _bad('TAR has no final zero blocks')


def _canonical(name):
    # Lexical only: never touch the filesystem or follow archive links.
    result = []
    for part in name.replace('\\', '/').split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            if result:
                result.pop()
        else:
            result.append(part)
    return '/'.join(result)


def _unsafe(name):
    parts = name.replace('\\', '/').split('/')
    return name.startswith(('/', '\\')) or '\\' in name or '..' in parts or len(name) >= 2 and name[1] == ':'


def analyze(data):
    if not isinstance(data, bytes) or len(data) > LIMITS['input_bytes']:
        _bad('Archive input exceeds 4 MiB')
    original = data
    encoding = 'binary'
    if data.lstrip().startswith(b'{'):
        try:
            envelope = strict_json(data.decode('utf-8'))
            if not isinstance(envelope, dict) or set(envelope) != {'archive_base64'} or not isinstance(envelope['archive_base64'], str):
                _bad('Archive JSON requires archive_base64 only')
            data = base64.b64decode(envelope['archive_base64'], validate=True)
        except (UnicodeError, TypeError, ValueError, RecursionError) as exc:
            raise ValueError('Invalid archive JSON or base64') from exc
        encoding = 'base64-json'
    if data.startswith((b'\x1f\x8b', b'BZh', b'\xfd7zXZ')):
        _bad('Compressed TAR is unsupported')
    kind = 'ZIP' if data.startswith(b'PK') else 'TAR'
    members = _zip(data) if kind == 'ZIP' else _tar(data)
    findings, known = [], {}

    def add(index, code, message):
        findings.append({'member':index, 'code':code, 'message':message})

    for member in members:
        index, name = member['index'], member['name']
        canonical = _canonical(name)
        if _unsafe(name):
            add(index, 'unsafe_path', 'Member name contains a path traversal or platform-dependent separator')
        if canonical in known:
            add(index, 'duplicate_path', 'Member aliases an earlier normalized name')
        known[canonical] = member['type']
        if member['type'] in {'symlink', 'hardlink'}:
            add(index, 'link_member', 'Archive link requires independent extraction policy')
            if member['link_target'] and _unsafe(member['link_target']):
                add(index, 'unsafe_link_target', 'Link target is not a simple confined relative path')
        elif member['type'] not in {'file', 'directory'}:
            add(index, 'special_member', 'Special filesystem member must not be extracted implicitly')
        if member['encrypted']:
            add(index, 'encrypted_member', 'Encrypted content was not decrypted or inspected')
        if member['mode'] & 0o6000:
            add(index, 'privileged_mode', 'Member declares setuid or setgid permission bits')
        if member['mode'] & 0o002:
            add(index, 'world_writable', 'Member declares world-writable permission bits')
        if member['size'] > 64 * 1024 * 1024 or member['size'] > max(1, member['compressed_size']) * 1000:
            add(index, 'declared_expansion', 'Declared expanded size or ratio exceeds the review threshold')
    # At most 2000 names: examine each one's bounded ancestors without retaining
    # every prefix, which could amplify deeply segmented names into large memory.
    for member in members:
        canonical = _canonical(member['name'])
        pos = 0
        while True:
            pos = canonical.find('/', pos)
            if pos < 0:
                break
            if canonical[:pos] in known and known[canonical[:pos]] != 'directory':
                add(member['index'], 'path_type_conflict', 'An ancestor name is also a non-directory member')
                break
            pos += 1
    return {'schema':'was.archive-review/1', 'format':kind, 'member_count':len(members),
            'members':members, 'findings':findings,
            'summary':{'declared_expanded_bytes':sum(m['size'] for m in members),
                       'stored_bytes':sum(m['compressed_size'] for m in members),
                       'encrypted_members':sum(m['encrypted'] for m in members),
                       'links':sum(m['type'] in {'symlink','hardlink'} for m in members), 'findings':len(findings)},
            'extracted':False, 'content_exported':False, 'crc_verified':False, 'network':False,
            'source_sha256':hashlib.sha256(original).hexdigest(), 'archive_sha256':hashlib.sha256(data).hexdigest(),
            'input_encoding':encoding, 'limits':dict(LIMITS), 'limitations':LIMITATIONS}


def sample():
    # Fixed STORE member. The CRC is metadata only, not checked by this analyzer.
    name, body = b'hello.txt', b'Synthetic archive metadata sample'
    import zlib
    crc = zlib.crc32(body)
    local = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, 0, 0, 0, 0, crc, len(body), len(body), len(name), 0) + name + body
    central = struct.pack('<4s6H3I5H2I', b'PK\x01\x02', (3 << 8) | 20, 20, 0, 0, 0, 0, crc, len(body), len(body), len(name), 0, 0, 0, 0, 0o100644 << 16, 0) + name
    end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 1, 1, len(central), len(local), 0)
    return {'archive_base64':base64.b64encode(local + central + end).decode()}
