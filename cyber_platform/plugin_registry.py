"""Offline, evidence-backed plugin metadata review. Never installs or executes code."""
import hashlib
import re
import sys
from urllib.parse import urlsplit
from . import detection
from .quality import _guard
from .store import Problem, encode

PREFIX = 'plugins.registry.'
LIMITS = {'plugins': 20, 'revisions_per_plugin': 20, 'manifest_bytes': 16384,
          'dependencies': 10, 'permissions': 20, 'proof_bytes': 8 * 1024 * 1024}
NOTICE = ('مراجعة بيانات إضافات فقط؛ الاعتماد قرار مالك للبيان وليس تثبيتًا أو تشغيلًا أو توقيع ناشر. '
          'المصدر والترخيص والصلاحيات تصريحات تحتاج مراجعة مستقلة؛ لا تنزيل مصادر أو تنفيذ شيفرة.')
_ID = re.compile(r'[a-z0-9][a-z0-9.-]{0,79}')
_VERSION = re.compile(r'(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(?:\.(0|[1-9][0-9]{0,3}))?')
_HEX = re.compile(r'[a-f0-9]{32}')
_ALLOWED = {'selected_evidence.read', 'derived_evidence.write', 'settings.read'}
_RECORD_FIELDS = {'schema', 'id', 'revision', 'previous_evidence', 'action', 'state', 'reason',
                  'manifest', 'manifest_sha256', 'source_evidence', 'source_sha256'}
_STATES = {'register': 'pending', 'approve': 'approved', 'disable': 'disabled', 'revoke': 'revoked'}


def _bad(message='بيانات سجل الإضافات غير صالحة', status=400):
    raise Problem(message, status)


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _text(value, maximum):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _bad()
    try:
        value.encode()
    except UnicodeError:
        _bad()
    return value


def _version(value):
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        _bad('رقم الإصدار يجب أن يكون رقميًا مثل1.0.0')
    return tuple(int(x) for x in value.split('.')) + (0,) * (3 - len(value.split('.')))


def _manifest(value):
    required = {'id', 'version', 'license', 'source', 'permissions'}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - {'dependencies', 'compatibility'}:
        _bad('البيان يحتاج المعرف والإصدار والترخيص والمصدر والصلاحيات فقط مع الحقول الاختيارية الموثقة')
    if not _ID.fullmatch(_text(value['id'], 80)):
        _bad('معرف الإضافة غير صالح')
    _version(value['version'])
    _text(value['license'], 100)
    source = _text(value['source'], 500)
    try:
        url = urlsplit(source)
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.port not in (None, 443):
            _bad('مصدر الإضافة رابط HTTPS دون بيانات دخول أو استعلام أو جزء لاحق')
        url.hostname.encode('idna')
    except (ValueError, UnicodeError):
        _bad('رابط مصدر الإضافة غير صالح')
    permissions = value['permissions']
    if not isinstance(permissions, list) or len(permissions) > LIMITS['permissions'] or any(not isinstance(p, str) or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,79}', p) for p in permissions) or len(set(permissions)) != len(permissions):
        _bad('قائمة الصلاحيات غير صالحة')
    dependencies = value.get('dependencies', [])
    if not isinstance(dependencies, list) or len(dependencies) > LIMITS['dependencies']:
        _bad('قائمة الاعتماديات تجاوزت الحد')
    seen = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {'id', 'version'} or not isinstance(dependency['id'], str) or not _ID.fullmatch(dependency['id']) or dependency['id'] in seen:
            _bad('اعتمادية غير صالحة أو مكررة')
        _version(dependency['version'])
        seen.add(dependency['id'])
    compatibility = value.get('compatibility', {'python_min': '3.11', 'python_max': '3.13', 'platform': 'linux'})
    if not isinstance(compatibility, dict) or set(compatibility) != {'python_min', 'python_max', 'platform'} or compatibility['platform'] != 'linux':
        _bad('التوافق يدعم Linux وحدود إصدار Python فقط')
    for key in ('python_min', 'python_max'):
        if not isinstance(compatibility[key], str) or not re.fullmatch(r'[0-9]{1,2}\.[0-9]{1,2}', compatibility[key]):
            _bad('إصدار توافق Python غير صالح')
    if _version(compatibility['python_min']) > _version(compatibility['python_max']):
        _bad('حدود توافق Python معكوسة')
    result = {**value, 'permissions': sorted(permissions), 'dependencies': sorted(dependencies, key=lambda d: d['id']), 'compatibility': compatibility}
    if len(encode(result).encode()) > LIMITS['manifest_bytes']:
        _bad('حجم بيان الإضافة يتجاوز16KiB', 413)
    return detection._json(encode(result).encode())


def _json(raw, maximum=17408):
    if len(raw) > maximum:
        _bad('حجم سجل الإضافة تجاوز الحد', 413)
    return detection._json(raw)


def _index(store, pid):
    rows = store.rows('SELECT value FROM settings WHERE key=?', (PREFIX + pid,))
    if rows and not isinstance(rows[0]['value'], str):
        _bad('فهرس الإضافات غير صالح', 409)
    index = _json(rows[0]['value'].encode(), 32768) if rows else {}
    if not isinstance(index, dict) or len(index) > LIMITS['plugins']:
        _bad('فهرس الإضافات غير صالح', 409)
    flat = []
    for identifier, revisions in index.items():
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or not isinstance(revisions, list) or not 1 <= len(revisions) <= LIMITS['revisions_per_plugin'] or any(not isinstance(eid, str) or not _HEX.fullmatch(eid) for eid in revisions):
            _bad('فهرس مراجعات الإضافات غير صالح', 409)
        flat.extend(revisions)
    records = store.rows("SELECT id FROM evidence WHERE project_id=? AND kind='plugin-registry' LIMIT 401", (pid,))
    if len(set(flat)) != len(flat) or set(flat) != {r['id'] for r in records}:
        _bad('فهرس الإضافات لا يطابق الأدلة المحفوظة', 409)
    return index


def _can_transition(state, action):
    return action in {'approve', 'disable', 'revoke'} and state != 'revoked' and _STATES[action] != state


def _items(store, pid):
    index = _index(store, pid)
    cached, budget = {}, [0]

    def read(eid):
        if not isinstance(eid, str) or not _HEX.fullmatch(eid):
            _bad('معرف دليل مراجعة الإضافة غير صالح', 409)
        if eid not in cached:
            record = store.evidence(pid, eid)
            if type(record['size']) is not int or not 0 <= record['size'] <= 17408:
                _bad('دليل الإضافة يتجاوز الحد', 409)
            budget[0] += record['size']
            if budget[0] > LIMITS['proof_bytes']:
                _bad('تجاوز سجل الإضافات ميزانية التحقق', 409)
            cached[eid] = (record, store.read_evidence(pid, eid))
        return cached[eid]

    result = []
    for identifier, revisions in sorted(index.items()):
        previous, latest, history = None, None, []
        for number, eid in enumerate(revisions, 1):
            record, raw = read(eid)
            saved = _json(raw)
            if not isinstance(saved, dict) or set(saved) != _RECORD_FIELDS or saved['schema'] != 'was.plugin-review/1' or saved['id'] != identifier or type(saved['revision']) is not int or saved['revision'] != number or saved['previous_evidence'] != previous or not isinstance(saved['action'], str) or saved['action'] not in _STATES or saved['state'] != _STATES[saved['action']]:
                _bad('تغيّر سجل مراجعات الإضافة', 409)
            manifest = _manifest(saved['manifest'])
            _text(saved['reason'], 1000)
            if manifest['id'] != identifier or _digest(manifest) != saved['manifest_sha256']:
                _bad('بصمة بيان الإضافة غير مطابقة', 409)
            source, source_bytes = read(saved['source_evidence'])
            if source['kind'] != 'original' or source['sha256'] != saved['source_sha256'] or _manifest(_json(source_bytes, LIMITS['manifest_bytes'])) != manifest:
                _bad('مصدر بيان الإضافة تغيّر أو غير مطابق', 409)
            parent = previous or source['id']
            if record['parent_id'] != parent:
                _bad('رابط تسلسل الإضافة غير مطابق', 409)
            audit_details = encode({'project': pid, 'id': eid, 'sha256': record['sha256']})
            if not store.rows('SELECT seq FROM audit WHERE action=? AND details=? LIMIT 1', ('plugin-registry.created', audit_details)):
                _bad('سجل الإضافة لا يملك واقعة إنشاء موثقة', 409)
            if saved['action'] == 'register':
                if latest and _version(manifest['version']) <= _version(latest['manifest']['version']):
                    _bad('ترتيب إصدارات الإضافة غير صالح', 409)
            elif not latest or not _can_transition(latest['state'], saved['action']) or any(saved[k] != latest[k] for k in ('manifest', 'manifest_sha256', 'source_evidence', 'source_sha256')):
                _bad('انتقال حالة الإضافة غير صالح', 409)
            history.append({'revision': number, 'action': saved['action'], 'state': saved['state'], 'reason': saved['reason'], 'evidence_id': eid})
            latest, previous = saved, eid
        result.append({k: latest[k] for k in ('id', 'manifest', 'state', 'revision', 'source_evidence', 'source_sha256', 'manifest_sha256')} | {'evidence_id': previous, 'history': history})
    return result


def _review(items):
    indexed = {i['id']: i for i in items}
    edges, issues = [], {i['id']: [] for i in items}

    def add(identifier, code, message):
        issue = {'code': code, 'message': message}
        if issue not in issues[identifier]:
            issues[identifier].append(issue)

    for item in items:
        identifier, manifest = item['id'], item['manifest']
        unsupported = sorted(set(manifest['permissions']) - _ALLOWED)
        if unsupported:
            add(identifier, 'unsupported_permissions', 'صلاحيات خارج قائمة مراجعة البيانات: ' + ', '.join(unsupported))
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+-]{0,99}', manifest['license']) or manifest['license'].lower() in {'unknown', 'none', 'unlicensed'}:
            add(identifier, 'license_review', 'معرف الترخيص يحتاج تصحيحًا؛ لا يتحقق التطبيق من الحقوق القانونية')
        compat = manifest['compatibility']
        current = sys.version_info[:2] + (0,)
        if not _version(compat['python_min']) <= current <= _version(compat['python_max']) or sys.platform != 'linux':
            add(identifier, 'incompatible_runtime', 'بيان التوافق لا يشمل إصدار Python أو النظام الحالي')
        for dep in manifest['dependencies']:
            edges.append({'source': identifier, 'target': dep['id'], 'required_version': dep['version']})
            target = indexed.get(dep['id'])
            if target is None:
                add(identifier, 'missing_dependency', 'اعتمادية غير مسجلة: ' + dep['id'])
            elif _version(target['manifest']['version']) != _version(dep['version']):
                add(identifier, 'version_conflict', 'إصدار اعتمادية غير مطابق: ' + dep['id'])
            elif target['state'] != 'approved':
                add(identifier, 'dependency_not_approved', 'اعتمادية غير معتمدة: ' + dep['id'])

    def reaches(start, target, seen):
        if start == target:
            return True
        if start in seen or start not in indexed:
            return False
        seen.add(start)
        return any(reaches(d['id'], target, seen) for d in indexed[start]['manifest']['dependencies'])

    for item in items:
        if any(reaches(d['id'], item['id'], set()) for d in item['manifest']['dependencies']):
            add(item['id'], 'dependency_cycle', 'دورة اعتماديات تمنع الاعتماد')
    # Propagate blocked dependencies to a fixed point, including transitive drift.
    for _ in range(len(items)):
        changed = False
        for item in items:
            for dep in item['manifest']['dependencies']:
                if dep['id'] in issues and issues[dep['id']] and not any(i['code'] == 'dependency_blocked' and dep['id'] in i['message'] for i in issues[item['id']]):
                    add(item['id'], 'dependency_blocked', 'اعتمادية ذات ملاحظات مانعة: ' + dep['id'])
                    changed = True
        if not changed:
            break
    return edges, issues


def view(store, project_id):
    with store.lock:
        _guard(store)
        store.project(project_id)
        items = _items(store, project_id)
        edges, issues = _review(items)
        for item in items:
            item['issues'] = issues[item['id']]
            item['effective_state'] = 'blocked' if item['state'] == 'approved' and item['issues'] else item['state']
        value = {'schema': 'was.plugin-registry/1', 'items': items,
                 'graph': {'nodes': [{'id': i['id'], 'state': i['state'], 'effective_state': i['effective_state']} for i in items],
                           'edges': edges, 'issues': [{'plugin_id': identifier, **issue} for identifier, values in issues.items() for issue in values]},
                 'limits': dict(LIMITS), 'notice': NOTICE}
        value['digest'] = _digest(value)
        return value


def _save(store, pid, index, manifest, source, action, reason, previous):
    revisions = index.get(manifest['id'], [])
    if len(revisions) >= LIMITS['revisions_per_plugin']:
        _bad('بلغت الإضافة حد المراجعات؛ لا تحذف التاريخ لتجاوزه', 409)
    saved = {'schema': 'was.plugin-review/1', 'id': manifest['id'], 'revision': len(revisions) + 1,
             'previous_evidence': previous, 'action': action, 'state': _STATES[action], 'reason': reason,
             'manifest': manifest, 'manifest_sha256': _digest(manifest),
             'source_evidence': source['id'], 'source_sha256': source['sha256']}
    # Refuse before publication if the next immutable revision would make the
    # complete retained proof set unreadable within the registry's budget.
    proof_ids, total = {source['id']}, 0
    for chain in index.values():
        for eid in chain:
            record = store.evidence(pid, eid)
            total += record['size']
            prior = _json(store.read_evidence(pid, eid))
            proof_ids.add(prior['source_evidence'])
    total += sum(store.evidence(pid, eid)['size'] for eid in proof_ids)
    if total + len(encode(saved).encode()) > LIMITS['proof_bytes']:
        _bad('المراجعة التالية تتجاوز ميزانية إثبات السجل؛ لم تحفظ', 409)
    artifact = detection._persist(store, pid, saved, 'plugin-registry', parent=previous or source['id'],
                                  setting=(PREFIX + pid, index, manifest['id']))
    return {'evidence': artifact, 'item': next(i for i in view(store, pid)['items'] if i['id'] == manifest['id'])}


def register(store, project_id, evidence_id):
    with store.lock:
        current = view(store, project_id)
        source = store.evidence(project_id, evidence_id)
        if source['kind'] != 'original' or source['size'] > LIMITS['manifest_bytes']:
            _bad('اختر بيان JSON أصليًا لا يتجاوز16KiB')
        manifest = _manifest(_json(store.read_evidence(project_id, evidence_id), LIMITS['manifest_bytes']))
        prior = next((i for i in current['items'] if i['id'] == manifest['id']), None)
        if prior is None and len(current['items']) >= LIMITS['plugins']:
            _bad('بلغ السجل حد الإضافات', 409)
        if prior and _version(manifest['version']) <= _version(prior['manifest']['version']):
            _bad('استخدم إصدارًا أعلى؛ لا يستبدل البيان أو يعاد استعمال الإصدار المحفوظ', 409)
        return _save(store, project_id, _index(store, project_id), manifest, source, 'register',
                     'تسجيل بيان للمراجعة؛ لا تثبيت أو تشغيل', prior['evidence_id'] if prior else None)


def transition(store, project_id, plugin_id, action, reason):
    if not isinstance(plugin_id, str) or not _ID.fullmatch(plugin_id) or not isinstance(action, str) or action not in {'approve', 'disable', 'revoke'}:
        _bad()
    reason = _text(reason, 1000)
    if not reason.strip():
        _bad('سبب قرار المراجعة مطلوب')
    with store.lock:
        current = view(store, project_id)
        item = next((i for i in current['items'] if i['id'] == plugin_id), None)
        if item is None:
            _bad('الإضافة غير مسجلة في المشروع', 404)
        if not _can_transition(item['state'], action):
            _bad('انتقال الحالة مكرر أو غير مسموح؛ الإصدار المسحوب يحتاج إصدارًا جديدًا', 409)
        if action == 'approve' and item['issues']:
            _bad('عالج ملاحظات الصلاحيات والتوافق والاعتماديات قبل الاعتماد', 409)
        return _save(store, project_id, _index(store, project_id), item['manifest'],
                     store.evidence(project_id, item['source_evidence']), action, reason, item['evidence_id'])
