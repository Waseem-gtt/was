"""Stable section/platform identities with audited owner presentation settings."""
import hashlib
import json
from pathlib import Path
from . import tools
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode

CATALOG = json.loads((Path(__file__).parent/'catalog.json').read_text())
COLORS = ('teal','blue','violet','amber','rose')
ICONS = ('◈','◎','⌘','◇','▦','⚙','✓','✧')
LANDINGS = ('overview','tools','map')
PREFIX = 'workspace.identity.'
FIELDS = {'id','revision','title','description','icon','color','landing'}
NOTICE = 'هوية ومساحة عمل مستقلة لكل قسم ومنصة، مع خدمات مشتركة. جاهزية مساحة العمل لا تعني اكتمال جميع تقنيات التخصص.'


def _definitions():
    result = {}
    for index, section in enumerate(CATALOG):
        result[section['id']] = {'id':section['id'],'parent_id':None,'type':'section',
            'title':section['name'],'description':section.get('description') or 'مساحة '+section['name']+'؛ '+ '، '.join(p['name'] for p in section['platforms']),
            'icon':ICONS[index%len(ICONS)],'color':COLORS[index%len(COLORS)],'landing':'overview','revision':0,
            'references':section.get('references') or section['platforms'][0].get('references',[]),
            'topics':[p['name'] for p in section['platforms']],
            'tool_ids':list(dict.fromkeys(t for p in section['platforms'] for t in p['tool_ids'])),
            'child_ids':[p['id'] for p in section['platforms']]}
        for platform in section['platforms']:
            result[platform['id']] = {'id':platform['id'],'parent_id':section['id'],'type':'platform',
                'title':platform['name'],'description':platform['description'],
                'icon':ICONS[index%len(ICONS)],'color':COLORS[index%len(COLORS)],'landing':'overview','revision':0,
                'references':platform.get('references',[]),'topics':platform.get('topics',[]),
                'tool_ids':platform['tool_ids'],'child_ids':[]}
    return result


DEFINITIONS = _definitions()


def _text(value, maximum, multiline=False):
    if not isinstance(value,str) or not 1 <= len(value.strip()) <= maximum or any(ord(c)<32 and not (multiline and c in '\r\n\t') or ord(c)==127 for c in value):
        raise Problem('عنوان أو وصف مساحة العمل غير صالح')
    try:value.encode('utf-8')
    except UnicodeError:raise Problem('نص مساحة العمل غير قابل للحفظ') from None
    return value.strip()


def _valid_id(identifier):
    if not isinstance(identifier,str) or identifier not in DEFINITIONS:
        raise Problem('مساحة العمل غير موجودة',404)
    return identifier


def _fields(body):
    if not isinstance(body,dict) or set(body) != FIELDS:
        raise Problem('إعدادات مساحة العمل تقبل حقول الهوية المعروفة فقط')
    _valid_id(body['id'])
    if type(body['revision']) is not int or not 0 <= body['revision'] <= 2**31-1:
        raise Problem('رقم مراجعة مساحة العمل غير صالح')
    for field, allowed in (('icon',ICONS),('color',COLORS),('landing',LANDINGS)):
        if not isinstance(body[field],str) or body[field] not in allowed:
            raise Problem('اختر الأيقونة واللون وصفحة البداية من الخيارات المسجلة')
    return {**body,'title':_text(body['title'],120),'description':_text(body['description'],2000,True)}


def _proof(record):
    return encode({'id':record['id'],'revision':record['revision'],
                   'sha256':hashlib.sha256(encode(record).encode()).hexdigest()})


def _identity(store, identifier):
    default = DEFINITIONS[_valid_id(identifier)]
    try:
        saved = store.setting(PREFIX+identifier)
        prefix = '{"id":' + encode(identifier) + ','
        latest = store.rows("SELECT details FROM audit WHERE action='workspace.updated' AND substr(details,1,?)=? ORDER BY seq DESC LIMIT 1", (len(prefix),prefix))
        if saved is None:
            if latest:raise ValueError('missing preference record')
            return dict(default)
        if not isinstance(saved,dict) or set(saved) != FIELDS|{'schema'} or saved['schema'] != 'was.workspace/1':
            raise ValueError('schema')
        checked = _fields({key:saved[key] for key in FIELDS})
        if checked['id'] != identifier or checked['revision'] < 1 or any(saved[key] != checked[key] for key in FIELDS):
            raise ValueError('identity')
        if not latest or latest[0]['details'] != _proof(saved):
            raise ValueError('latest proof')
        return {**default,**checked}
    except (ValueError,TypeError,KeyError,UnicodeError,Problem):
        raise Problem('إعدادات مساحة العمل أو إثباتها غير سليمة؛ لم تُستبدل بالافتراضي',409) from None


def _describe(store, identifier):
    workspace = _identity(store,identifier)
    parent = _identity(store,workspace['parent_id']) if workspace['parent_id'] else None
    workspace['parent_title'] = parent['title'] if parent else None
    registry = {tool['id']:tool for tool in tools.describe()}
    workspace['tools'] = [registry[tid] for tid in workspace.pop('tool_ids') if tid in registry]
    children = [_identity(store,cid) for cid in workspace.pop('child_ids')]
    workspace['children'] = [{key:child[key] for key in ('id','title','type','icon','color','revision')} for child in children]
    workspace['shared_services'] = ['evidence','knowledge','plans','maintenance','assistant']
    return {'workspace':workspace,'colors':list(COLORS),'icons':list(ICONS),
            'landings':list(LANDINGS),'notice':NOTICE}


def describe(store, identifier):
    _valid_id(identifier)
    with store.lock, _directories(store):
        _guard(store)
        return _describe(store,identifier)


def save(store, body):
    value = _fields(body)
    with store.lock, _directories(store) as (_, validate):
        with store.db:
            # Serialize revision checks across separate connections/processes too.
            store.db.execute('BEGIN IMMEDIATE')
            _guard(store)
            current = _identity(store,value['id'])
            if value['revision'] != current['revision']:
                raise Problem('تغيرت الإعدادات في نافذة أخرى؛ أعد تحميلها قبل الحفظ',409)
            if current['revision'] >= 2**31-1:
                raise Problem('بلغت الهوية حد المراجعات؛ لم تُغير الإعدادات',409)
            record = {**value,'schema':'was.workspace/1','revision':current['revision']+1}
            _describe(store,value['id'])
            store.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(PREFIX+value['id'],encode(record)))
            store.audit('workspace.updated',json.loads(_proof(record)))
            result = _describe(store,value['id'])
            validate()
        return result


def catalog_view(store):
    """Apply display preferences to navigation without mutating source IDs/tools."""
    with store.lock, _directories(store):
        _guard(store)
        result = []
        for section in CATALOG:
            identity = _identity(store,section['id'])
            entry = {**section, **{key:identity[key] for key in ('icon','color','landing','revision')},
                     'name':identity['title'],'description':identity['description'],'platforms':[]}
            for platform in section['platforms']:
                child = _identity(store,platform['id'])
                entry['platforms'].append({**platform, **{key:child[key] for key in ('icon','color','landing','revision')},
                                          'name':child['title'],'description':child['description']})
            result.append(entry)
        return result
