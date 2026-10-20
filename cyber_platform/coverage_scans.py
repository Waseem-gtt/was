"""Resumable verification of frozen static coverage, never live protection."""
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from pathlib import Path
from . import __version__, coverage, detection, integrity
from .store import Problem, encode, uid

PREFIX = 'coverage.scan.'
MAX_RUNS = 20
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_PROOFS = 3000
MAX_BYTES = 64 * 1024 * 1024
MAX_CHECKS = 3
MAX_FINAL_FILES = 100
MAX_SECONDS = 3
NOTICE = ('تقرير لقطة تغطية ثابتة يعاد التحقق منه على دفعات؛ ليس حماية حية. '
          'فحص الملفات متتابع وغير ذري؛ اكتمال التحقق لا يعني أن جميع الأصول مدعومة. '
          'حد64MiB يخص قراءات ملفات الإثبات المباشرة؛ لمحرك الكشف قراءات وإعادة تنفيذ محدودة إضافية.')
_LOCK = threading.Lock()
STATUSES = {'supported', 'gap', 'unverified', 'stale', 'conflict'}


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _id(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value) is not None


def _hash(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def _prefix(pid):
    if not _id(pid):
        raise Problem('معرف المشروع غير صالح')
    return PREFIX + pid + '.'


def _engine():
    root = Path(__file__).parent
    return _digest({'version': __version__, 'detection': detection._engine(), 'files': {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ('coverage_scans.py', 'coverage.py')}})


def _environment(store, pid):
    return {'engine': _engine(), 'bundle': detection._pack()[1],
            'rules_index': _digest(detection._index(store, pid))}


def _record(store, pid, eid):
    item = store.evidence(pid, eid)
    info = os.stat(store.blobs / eid, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != item['size'] or not 0 <= info.st_size <= 16 * 1024 * 1024:
        raise Problem('ملف إثبات غير آمن أو متغير', 409)
    return {'record': {k: item[k] for k in ('id', 'project_id', 'sha256', 'size', 'kind', 'parent_id')},
            'identity': [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]}


def _proof_read(store, pid, proof):
    eid = proof['record']['id']
    if _record(store, pid, eid) != proof:
        raise Problem('تغير ملف إثبات محفوظ', 409)
    data = store.read_evidence(pid, eid)
    if _record(store, pid, eid) != proof:
        raise Problem('تغير ملف الإثبات أثناء القراءة', 409)
    return data


def _chain(store, pid, eid):
    records, seen = {}, set()
    while eid is not None:
        if eid in seen or len(seen) >= 32:
            raise Problem('سلسلة مصدر الأدلة غير صالحة أو طويلة', 409)
        seen.add(eid)
        proof = _record(store, pid, eid)
        records[eid] = proof
        eid = proof['record']['parent_id']
    return records


def _guard(store):
    integrity._audit_guard(store)


def _save(store, run, action):
    run['updated'] = time.time()
    run['record_sha256'] = _digest({k: v for k, v in run.items() if k != 'record_sha256'})
    raw = encode(run)
    if len(raw.encode()) > MAX_STATE_BYTES:
        raise Problem('تجاوز حجم فحص التغطية المحفوظ', 413)
    with store.lock, store.db, integrity._directories(store) as (_, validate):
        _guard(store)
        store.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', (_prefix(run['project_id']) + run['id'], raw))
        store.audit(action, {'id': run['id'], 'project': run['project_id'], 'cursor': run['cursor'], 'phase': run['phase'], 'status': run['status']})
        validate()


def _bad():
    raise Problem('حالة فحص التغطية المحفوظة غير متسقة', 409)


def _load(store, pid, scan_id):
    key = _prefix(pid)
    store.project(pid)
    if not _id(scan_id):
        raise Problem('معرف فحص التغطية غير صالح')
    rows = store.rows('SELECT value FROM settings WHERE key=?', (key + scan_id,))
    if not rows:
        raise Problem('فحص التغطية غير موجود', 404)
    try:
        raw = rows[0]['value']
        if len(raw.encode()) > MAX_STATE_BYTES:
            _bad()
        run = json.loads(raw, object_pairs_hook=coverage._pairs)
        fields = {'schema', 'id', 'project_id', 'version', 'created', 'updated', 'status', 'phase', 'scope', 'scope_sha256', 'environment', 'cursor', 'cache', 'proofs', 'proof_order', 'proof_cursor', 'in_flight', 'notice', 'last_batch', 'record_sha256'}
        if not isinstance(run, dict) or not fields <= set(run) or set(run) - fields - {'error_code'} or run['schema'] != 'was.coverage-scan/1' or run['id'] != scan_id or run['project_id'] != pid:
            _bad()
        if not _hash(run['record_sha256']) or run['record_sha256'] != _digest({k: v for k, v in run.items() if k != 'record_sha256'}):
            _bad()
        if run['status'] not in {'pending', 'running', 'completed', 'failed'} or run['phase'] not in {'verify', 'finalize', 'done'}:
            _bad()
        if any(type(run[k]) not in (int, float) or not math.isfinite(run[k]) or run[k] <= 0 for k in ('created', 'updated')) or run['updated'] < run['created']:
            _bad()
        scope = run['scope']
        if not isinstance(scope, dict) or set(scope) != {'schema', 'project_id', 'assets', 'assessments'} or scope['schema'] != 'was.coverage/1' or scope['project_id'] != pid or not isinstance(scope['assets'], list) or len(scope['assets']) > 100 or not isinstance(scope['assessments'], list) or len(scope['assessments']) > 200 or run['scope_sha256'] != _digest(scope):
            _bad()
        asset_ids = set()
        for item in scope['assets']:
            if not isinstance(item, dict) or set(item) != {'id', 'name', 'kind', 'created'} or not _id(item['id']) or item['id'] in asset_ids or not coverage._title(item['name']) or item['kind'] not in coverage.KINDS or type(item['created']) not in (int, float) or not 0 < item['created'] < 1e12:
                _bad()
            asset_ids.add(item['id'])
        assessment_ids = set()
        for item in scope['assessments']:
            if not isinstance(item, dict) or set(item) != {'id', 'asset_id', 'threat', 'control', 'evidence_id', 'snapshot', 'created'} or not _id(item['id']) or item['id'] in assessment_ids or item['asset_id'] not in asset_ids or not coverage._title(item['threat']) or not coverage._title(item['control']) or not coverage._snapshot_valid(item['snapshot']) or item['evidence_id'] != item['snapshot']['evidence_id'] or type(item['created']) not in (int, float) or not 0 < item['created'] < 1e12:
                _bad()
            assessment_ids.add(item['id'])
        if not isinstance(run['environment'], dict) or set(run['environment']) != {'engine', 'bundle', 'rules_index'} or any(not _hash(v) for v in run['environment'].values()):
            _bad()
        if type(run['cursor']) is not int or not 0 <= run['cursor'] <= len(scope['assessments']) or type(run['proof_cursor']) is not int:
            _bad()
        cache, proofs, order = run['cache'], run['proofs'], run['proof_order']
        if not isinstance(cache, dict) or len(cache) > 200 or not isinstance(proofs, dict) or len(proofs) > MAX_PROOFS or not isinstance(order, list) or len(order) != len(set(order)) or set(order) != set(proofs) or not 0 <= run['proof_cursor'] <= len(order):
            _bad()
        required = {a['evidence_id'] for a in scope['assessments'][:run['cursor']]}
        if set(cache) != required:
            _bad()
        for eid, result in cache.items():
            if not _id(eid) or not isinstance(result, dict) or set(result) != {'status', 'snapshot'} or result['status'] not in {'supported', 'gap', 'unverified', 'stale'} or not coverage._snapshot_valid(result['snapshot']):
                _bad()
        for eid, proof in proofs.items():
            if not _id(eid) or not isinstance(proof, dict) or set(proof) != {'record', 'identity'} or not isinstance(proof['record'], dict) or set(proof['record']) != {'id', 'project_id', 'sha256', 'size', 'kind', 'parent_id'}:
                _bad()
            record = proof['record']
            if record['id'] != eid or record['project_id'] != pid or not _hash(record['sha256']) or type(record['size']) is not int or not 0 <= record['size'] <= 16 * 1024 * 1024 or not isinstance(record['kind'], str) or len(record['kind']) > 100 or record['parent_id'] is not None and not _id(record['parent_id']):
                _bad()
            if not isinstance(proof['identity'], list) or len(proof['identity']) != 5 or any(type(v) is not int or v < 0 for v in proof['identity']) or proof['identity'][2] != record['size']:
                _bad()
        for eid, proof in proofs.items():
            parent = proof['record']['parent_id']
            if parent is not None and parent not in proofs:
                _bad()
        for eid, result in cache.items():
            snapshot = result['snapshot']
            if eid not in proofs or proofs[eid]['record']['sha256'] != snapshot['evidence_sha256'] or proofs[eid]['record']['kind'] != snapshot['evidence_kind']:
                _bad()
            source = snapshot['input_evidence']
            if source is not None and (source not in proofs or proofs[source]['record']['sha256'] != snapshot['input_sha256'] or proofs[eid]['record']['parent_id'] != source):
                _bad()
        if not isinstance(run['version'], str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', run['version']) or not isinstance(run['notice'], str) or len(run['notice']) > 2000:
            _bad()
        batch = run['last_batch']
        if not isinstance(batch, dict) or set(batch) != {'assessments', 'proof_files', 'proof_bytes'} or any(type(v) is not int or v < 0 for v in batch.values()) or batch['assessments'] > 3 or batch['proof_files'] > MAX_PROOFS or batch['proof_bytes'] > 64 * 1024 * 1024:
            _bad()
        if run['in_flight'] is not None and (run['status'] != 'running' or run['phase'] != 'verify' or run['cursor'] >= len(scope['assessments']) or run['in_flight'] != scope['assessments'][run['cursor']]['evidence_id']):
            _bad()
        if run['phase'] in {'finalize', 'done'} and run['cursor'] != len(scope['assessments']) or run['status'] == 'completed' and (run['phase'] != 'done' or run['proof_cursor'] != len(order)):
            _bad()
        if (run['status'] == 'failed') != ('error_code' in run) or 'error_code' in run and run['error_code'] not in {'interrupted_check', 'scope_changed', 'engine_changed', 'evidence_changed', 'proof_scope_overflow', 'verification_error'}:
            _bad()
        return run
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        _bad()


def _view(run):
    scope, cache = run['scope'], run['cache']
    results = []
    for index, saved in enumerate(scope['assessments']):
        if index < run['cursor']:
            ref = cache[saved['evidence_id']]
            state = ref['status'] if ref['snapshot'] == saved['snapshot'] else 'stale'
            reason = state
        else:
            state, reason = 'unverified', 'pending_verification'
        results.append(dict(saved, status=state, reason=reason))
    grouped = {}
    for result in results:
        grouped.setdefault((result['asset_id'], result['threat'], result['control']), []).append(result)
    for group in grouped.values():
        if {r['status'] for r in group} >= {'supported', 'gap'}:
            for result in group:
                if result['status'] in {'supported', 'gap'}:
                    result.update(status='conflict', reason='contradictory_snapshot_tests')
    assets, gaps = [], []
    for original in scope['assets']:
        own = [r for r in results if r['asset_id'] == original['id']]
        state = next((s for s in ('conflict', 'stale', 'gap', 'unverified', 'supported') if any(r['status'] == s for r in own)), 'untested')
        assets.append(dict(original, status=state, assessment_count=len(own)))
        if not own:
            gaps.append({'asset_id': original['id'], 'assessment_id': None, 'status': 'untested', 'reason': 'no_assessment'})
    for result in results:
        if result['status'] != 'supported':
            gaps.append({'asset_id': result['asset_id'], 'assessment_id': result['id'], 'status': result['status'], 'reason': result['reason']})
    summary = {'assets': len(assets), 'assessments': len(results)}
    summary.update({s: sum(r['status'] == s for r in results) for s in sorted(STATUSES)})
    summary['untested'] = sum(a['status'] == 'untested' for a in assets)
    total = len(scope['assessments'])
    complete = run['status'] == 'completed'
    return {'schema': run['schema'], 'id': run['id'], 'project_id': run['project_id'], 'version': run['version'], 'created': run['created'], 'updated': run['updated'], 'status': run['status'], 'phase': run['phase'], 'complete': complete,
            'all_supported': bool(complete and results and not gaps), 'current_validity': 'snapshot_only',
            'cursor': run['cursor'], 'total': total, 'counts': {'processed': run['cursor'], 'total': total, 'remaining': total - run['cursor']},
            'proof_counts': {'checked': run['proof_cursor'], 'total': len(run['proof_order']), 'remaining': len(run['proof_order']) - run['proof_cursor']},
            'results': results, 'assets': assets, 'gaps': gaps, 'summary': summary,
            'nodes': [{'id': a['id'], 'label': a['name'], 'kind': a['kind']} for a in assets] + [{'id': r['id'], 'label': r['control'], 'kind': 'assessment'} for r in results],
            'edges': [{'source': r['asset_id'], 'target': r['id'], 'label': r['threat'], 'status': r['status']} for r in results],
            'notice': run['notice'], 'last_batch': run['last_batch'], **({'error_code': run['error_code']} if 'error_code' in run else {})}


def status(store, pid, scan_id):
    with store.lock:
        return _view(_load(store, pid, scan_id))


def history(store, pid):
    with store.lock:
        store.project(pid)
        rows = store.rows('SELECT key FROM settings WHERE key LIKE ? LIMIT 21', (_prefix(pid) + '%',))
        if len(rows) > MAX_RUNS:
            _bad()
        scans = [_load(store, pid, row['key'][len(_prefix(pid)):]) for row in rows]
        return {'scans': [{**{k: run[k] for k in ('id', 'project_id', 'status', 'phase', 'created', 'updated')},
                           'complete': run['status'] == 'completed',
                           'counts': {'processed': run['cursor'], 'total': len(run['scope']['assessments']), 'remaining': len(run['scope']['assessments']) - run['cursor']},
                           'proof_counts': {'checked': run['proof_cursor'], 'total': len(run['proof_order']), 'remaining': len(run['proof_order']) - run['proof_cursor']}}
                          for run in sorted(scans, key=lambda r: (r['created'], r['id']), reverse=True)]}


def start(store, pid):
    try:
        with store.lock, store.db, integrity._directories(store):
            _guard(store)
            scope = coverage._load(store, pid)
            previous = history(store, pid)['scans']
            if len(previous) >= MAX_RUNS:
                terminal = sorted((r for r in previous if r['status'] in {'completed', 'failed'}), key=lambda r: (r['created'], r['id']))
                if not terminal:
                    raise Problem('يوجد20فحص تغطية نشطًا؛ أكمل أحدها أولًا', 409)
                store.db.execute('DELETE FROM settings WHERE key=?', (_prefix(pid) + terminal[0]['id'],))
            now = time.time()
            proofs = {}
            for revisions in detection._index(store, pid).values():
                for eid in revisions:
                    proofs[eid] = _record(store, pid, eid)
            run = {'schema': 'was.coverage-scan/1', 'id': uid(), 'project_id': pid, 'version': __version__, 'created': now, 'updated': now,
                   'status': 'pending', 'phase': 'verify', 'scope': scope, 'scope_sha256': _digest(scope), 'environment': _environment(store, pid),
                   'cursor': 0, 'cache': {}, 'proofs': proofs, 'proof_order': sorted(proofs), 'proof_cursor': 0, 'in_flight': None,
                   'notice': NOTICE, 'last_batch': {'assessments': 0, 'proof_files': 0, 'proof_bytes': 0}}
            _save(store, run, 'coverage.scan_started')
            return _view(run)
    except OSError:
        raise Problem('التخزين تغير أو غير آمن', 409) from None


def _fail(store, run, code):
    run.update(status='failed', in_flight=None, error_code=code)
    _save(store, run, 'coverage.scan_failed')
    return _view(run)


def _unchanged(store, run):
    pid = run['project_id']
    if _digest(coverage._load(store, pid)) != run['scope_sha256']:
        return 'scope_changed'
    if _environment(store, pid) != run['environment']:
        return 'engine_changed'
    try:
        if any(_record(store, pid, eid) != proof for eid, proof in run['proofs'].items()):
            return 'evidence_changed'
    except (Problem, OSError):
        return 'evidence_changed'
    return None


def advance(store, pid, scan_id):
    if not _LOCK.acquire(blocking=False):
        raise Problem('فحص تغطية آخر قيد التنفيذ', 409)
    try:
        with store.lock, integrity._directories(store):
            _guard(store)
            run = _load(store, pid, scan_id)
            if run['status'] in {'completed', 'failed'}:
                return _view(run)
            if run['in_flight'] is not None:
                return _fail(store, run, 'interrupted_check')
            error = _unchanged(store, run)
            if error:
                return _fail(store, run, error)
            run['status'] = 'running'
            batch = {'assessments': 0, 'proof_files': 0, 'proof_bytes': 0}
            run['last_batch'] = batch
            deadline = time.monotonic() + MAX_SECONDS
            if run['phase'] == 'verify':
                while run['cursor'] < len(run['scope']['assessments']) and batch['assessments'] < MAX_CHECKS and time.monotonic() < deadline:
                    saved = run['scope']['assessments'][run['cursor']]
                    eid = saved['evidence_id']
                    if eid not in run['cache']:
                        try:
                            chain = _chain(store, pid, eid)
                            amount = sum(p['record']['size'] for p in chain.values())
                            if amount > MAX_BYTES:
                                return _fail(store, run, 'proof_scope_overflow')
                            if batch['proof_bytes'] + amount > MAX_BYTES:
                                break
                            if len(set(run['proofs']) | set(chain)) > MAX_PROOFS:
                                return _fail(store, run, 'proof_scope_overflow')
                            run['in_flight'] = eid
                            _save(store, run, 'coverage.scan_check_started')
                            for proof in chain.values():
                                _proof_read(store, pid, proof)
                                batch['proof_files'] += 1
                                batch['proof_bytes'] += proof['record']['size']
                            result = coverage._reference(store, pid, eid)
                            if any(_record(store, pid, key) != proof for key, proof in chain.items()):
                                return _fail(store, run, 'evidence_changed')
                            run['proofs'].update(chain)
                            run['proof_order'] = sorted(run['proofs'])
                            run['cache'][eid] = result
                        except (Problem, OSError, ValueError, TypeError, KeyError, RecursionError):
                            return _fail(store, run, 'verification_error')
                    run['cursor'] += 1
                    run['in_flight'] = None
                    batch['assessments'] += 1
                    error = _unchanged(store, run)
                    if error:
                        return _fail(store, run, error)
                    _save(store, run, 'coverage.scan_check_finished')
                if run['cursor'] == len(run['scope']['assessments']):
                    run['phase'] = 'finalize'
                    _save(store, run, 'coverage.scan_finalizing')
                _save(store, run, 'coverage.scan_batch')
                return _view(run)
            while run['proof_cursor'] < len(run['proof_order']) and batch['proof_files'] < MAX_FINAL_FILES and time.monotonic() < deadline:
                proof = run['proofs'][run['proof_order'][run['proof_cursor']]]
                size = proof['record']['size']
                if batch['proof_bytes'] + size > MAX_BYTES:
                    break
                try:
                    _proof_read(store, pid, proof)
                except (Problem, OSError):
                    return _fail(store, run, 'evidence_changed')
                batch['proof_bytes'] += size
                batch['proof_files'] += 1
                run['proof_cursor'] += 1
                _save(store, run, 'coverage.scan_proof_checked')
            error = _unchanged(store, run)
            if error:
                return _fail(store, run, error)
            if run['proof_cursor'] == len(run['proof_order']):
                run.update(status='completed', phase='done')
                _save(store, run, 'coverage.scan_completed')
            else:
                _save(store, run, 'coverage.scan_batch')
            return _view(run)
    except OSError:
        raise Problem('التخزين تغير أو غير آمن', 409) from None
    finally:
        _LOCK.release()
