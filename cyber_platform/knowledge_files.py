"""Owner-imported KEV JSON: bounded parsing, immutable receipt, no network."""
import hashlib
import json
import re
import time
from datetime import date, datetime
from pathlib import Path
from . import tools, worker
from .detection import _persist
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode

MAX_BYTES = 4 * 1024 * 1024
MAX_IMPORTS = 20
PREFIX = 'knowledge.files.'
NOTICE = 'ملف يقدمه المالك بصيغة CISA KEV؛ صحة البنية والبصمة لا تثبت هوية الناشر أو صحة ادعاءات الثغرات. لا اتصال خارجي.'


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def _text(value, maximum, required=False):
    if not isinstance(value, str) or len(value) > maximum or required and not value.strip() or any(ord(c) < 32 and c not in '\n\t\r' for c in value):
        raise ValueError('invalid field')
    value.encode('utf-8')
    return value


def parse(raw):
    """Called in the fixed resource-limited worker; return documented fields only."""
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
            raise ValueError('size')
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
        if not isinstance(value, dict):
            raise ValueError('root')
        version = _text(value.get('catalogVersion'), 100, True)
        published = _text(value.get('dateReleased'), 80, True)
        parsed_time = datetime.fromisoformat(published.replace('Z', '+00:00'))
        if parsed_time.tzinfo is None:
            raise ValueError('timezone')
        rows = value.get('vulnerabilities')
        if not isinstance(rows, list) or len(rows) > 20000 or type(value.get('count')) is not int or value['count'] != len(rows):
            raise ValueError('count')
        result, seen = [], set()
        fields = {'cveID':80, 'vendorProject':300, 'product':300, 'vulnerabilityName':1000,
                  'shortDescription':8000, 'requiredAction':8000, 'notes':8000,
                  'knownRansomwareCampaignUse':100, 'dateAdded':10, 'dueDate':10}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('row')
            current = {key:_text(row[key], limit, key in ('cveID','vendorProject','product','vulnerabilityName'))
                       for key, limit in fields.items() if key in row}
            if not {'cveID','vendorProject','product','vulnerabilityName'} <= current.keys() or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,16}', current['cveID']) or current['cveID'] in seen:
                raise ValueError('identifier')
            for field in ('dateAdded', 'dueDate'):
                if field in current and (len(current[field]) != 10 or date.fromisoformat(current[field]).isoformat() != current[field]):
                    raise ValueError('date')
            if 'cwes' in row:
                if not isinstance(row['cwes'], list) or len(row['cwes']) > 100 or any(not isinstance(c, str) or not re.fullmatch(r'CWE-[0-9]{1,8}', c) for c in row['cwes']):
                    raise ValueError('cwes')
                current['cwes'] = row['cwes']
            seen.add(current['cveID']); result.append(current)
        return {'catalogVersion':version, 'dateReleased':published, 'count':len(result), 'vulnerabilities':result}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise ValueError('ملف فهرس الثغرات غير صالح؛ راجع صيغة KEV والحقول والتكرار والحد4MiB') from None


def fingerprint():
    root = Path(__file__).parent
    return hashlib.sha256(encode({name:hashlib.sha256((root/name).read_bytes()).hexdigest()
                                  for name in ('knowledge_files.py','worker.py','tools.py') + tools.ANALYZER_FILES}).encode()).hexdigest()


def _index(store, pid):
    value = store.setting(PREFIX + pid, {'catalogs':[]})
    if not isinstance(value, dict) or set(value) != {'catalogs'} or not isinstance(value['catalogs'], list) or len(value['catalogs']) > MAX_IMPORTS or any(not isinstance(item, str) for item in value['catalogs']) or len(set(value['catalogs'])) != len(value['catalogs']):
        raise Problem('فهرس ملفات المعرفة غير سليم', 409)
    return value


def _receipt(store, pid, eid):
    record = store.evidence(pid, eid)
    if record['kind'] != 'knowledge-file' or record['size'] > 16384:
        raise Problem('سجل استيراد المعرفة غير صالح', 409)
    raw = store.read_evidence(pid, eid)
    proof = encode({'project':pid, 'id':eid, 'sha256':record['sha256']})
    if not store.rows("SELECT seq FROM audit WHERE action='knowledge-file.created' AND details=? LIMIT 1", (proof,)):
        raise Problem('إثبات إنشاء سجل المعرفة مفقود', 409)
    value = json.loads(raw)
    if value.get('schema') != 'was.knowledge-file/1' or value.get('input_evidence') != record['parent_id'] or value.get('parser_sha256') != fingerprint():
        raise Problem('تغير قارئ المعرفة أو إثبات الاستيراد؛ أعد استيراد الأصل', 409)
    source = store.evidence(pid, value['input_evidence'])
    if source['kind'] != 'original' or source['size'] > MAX_BYTES or source['sha256'] != value['input_sha256']:
        raise Problem('مصدر سجل المعرفة غير مطابق', 409)
    source_raw = store.read_evidence(pid, source['id'])
    return value, source_raw


def import_file(store, pid, evidence_id):
    store.project(pid)
    with store.lock, _directories(store):
        _guard(store)
        index = _index(store, pid)
        record = store.evidence(pid, evidence_id)
        if record['kind'] != 'original' or record['size'] > MAX_BYTES:
            raise Problem('اختر ملفًا أصليًا لفهرس KEV لا يتجاوز4MiB', 413)
        raw = store.read_evidence(pid, evidence_id)
        before = fingerprint()
    try:
        catalog = worker.analyze('knowledge-catalog', raw, timeout=3)
    except ValueError:
        raise Problem('تعذر قبول ملف KEV ضمن الصيغة والحدود؛ بقي الفهرس السابق محفوظًا', 400) from None
    with store.lock, _directories(store):
        _guard(store)
        if fingerprint() != before or store.read_evidence(pid, evidence_id) != raw:
            raise Problem('تغير المصدر أو القارئ أثناء الاستيراد', 409)
        index = _index(store, pid)
        if index['catalogs']:
            try:
                prior, _ = _receipt(store, pid, index['catalogs'][-1])
                if prior['input_sha256'] == record['sha256']:
                    return {'evidence':store.evidence(pid, index['catalogs'][-1]), 'receipt':prior, 'reused':True, 'notice':NOTICE}
            except Problem:
                pass  # A new verified import can replace an unusable current reference.
        if len(index['catalogs']) >= MAX_IMPORTS:
            raise Problem('حد ملفات المعرفة20إصدارًا لكل مشروع؛ الأصول تبقى محفوظة', 409)
        receipt = {'schema':'was.knowledge-file/1', 'input_evidence':evidence_id, 'input_sha256':record['sha256'],
                   'parser_sha256':before, 'version':catalog['catalogVersion'], 'published':catalog['dateReleased'],
                   'count':catalog['count'], 'imported_at':time.time(), 'source_authenticity':'not_verified', 'network':False}
        artifact = _persist(store, pid, receipt, 'knowledge-file', evidence_id,
                            setting=(PREFIX+pid, index, 'catalogs'))
        return {'evidence':artifact, 'receipt':receipt, 'reused':False, 'notice':NOTICE}


def status(store, pid):
    store.project(pid)
    with store.lock, _directories(store):
        _guard(store)
        ids = _index(store, pid)['catalogs']
        if not ids:
            return {'current':None, 'imports':0, 'notice':NOTICE}
        receipt, _ = _receipt(store, pid, ids[-1])
        return {'current':receipt, 'receipt_id':ids[-1], 'imports':len(ids), 'notice':NOTICE}


def search(store, pid, query):
    if not isinstance(query, str) or len(query) > 120:
        raise Problem('حد البحث120حرفًا')
    with store.lock, _directories(store):
        _guard(store)
        store.project(pid)
        ids = _index(store, pid)['catalogs']
        if not ids:
            return {'items':[], 'total_matches':0, 'current':None, 'notice':NOTICE}
        receipt, raw = _receipt(store, pid, ids[-1])
        before = fingerprint()
    try:
        catalog = worker.analyze('knowledge-catalog', raw, timeout=3)
    except ValueError:
        raise Problem('تعذر قراءة فهرس المعرفة ضمن الحدود', 409) from None
    with store.lock, _directories(store):
        _guard(store)
        if fingerprint() != before or _index(store,pid)['catalogs'][-1] != ids[-1] or store.read_evidence(pid,receipt['input_evidence']) != raw:
            raise Problem('تغير فهرس المعرفة أثناء البحث؛ أعد المحاولة', 409)
    q = query.casefold()
    matches = [row for row in catalog['vulnerabilities'] if q in ' '.join(row.get(key,'') for key in ('cveID','vendorProject','product','vulnerabilityName','shortDescription')).casefold()]
    return {'items':matches[:50], 'total_matches':len(matches), 'limit':50, 'current':receipt, 'receipt_id':ids[-1], 'notice':NOTICE}
