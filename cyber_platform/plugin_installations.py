"""Explicit owner-authorized, signed no-import Wasm installations and receipts.

The old manifest registry remains metadata-only. Uploading a file never executes
it: a trusted publisher plus an explicit installation operation is required.
"""
import base64
import hashlib
import json
import math
import os
import re
import sys
import time
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from . import plugin_registry, plugin_wasm, tools
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode, uid

SCHEMA = 'was.plugin-installations/1'
KIND = 'plugin-installation'
LIMITS = {'plugins':20, 'versions_per_plugin':10, 'publisher_keys':20, 'journal_records':512,
          'runs':100, 'package_bytes':2*1024*1024, 'aggregate_package_bytes':16*1024*1024,
          'module_bytes':1024*1024, 'input_bytes':65536, 'result_bytes':65536,
          'fixtures':10, 'record_bytes':98304, 'journal_bytes':4*1024*1024}
NOTICE = ('حزم WebAssembly موقعة لا تستورد أي وظائف من المضيف؛ لا ملفات أو شبكة أو أوامر. '
          'التثبيت والثقة والتفعيل أوامر صريحة للمالك، ولا يمنح رفع الملف أو اعتماد بيان قديم إذن تشغيل. '
          'نتائج الإضافة قد تعكس محتوى الملف المختار؛ لا ترسل خارجًا تلقائيًا.')
_EID = re.compile(r'[a-f0-9]{32}')
_SHA = re.compile(r'[a-f0-9]{64}')
_COMMON = {'schema','action','created','previous'}
_FIELDS = {
    'trust':{'key_id','public_key'}, 'revoke':{'key_id'},
    'install':{'plugin_id','version','package_evidence','package_sha256','publisher','manifest','fixture_count','runtime_sha256'},
    'activate':{'plugin_id','version','runtime_sha256'},
    'disable':{'plugin_id','version','runtime_sha256'},
    'rollback':{'plugin_id','version','runtime_sha256'},
    'run':{'plugin_id','version','package_evidence','package_sha256','input_evidence','input_sha256','runtime_sha256','result'},
}


def _bad(message='بيانات الحزمة التنفيذية أو إثباتها غير صالح', status=400):
    raise Problem(message, status)


def _eid(value):
    if not isinstance(value,str) or not _EID.fullmatch(value):_bad('معرف المشروع أو الدليل غير صالح')
    return value


def _sha(value):
    if not isinstance(value,str) or not _SHA.fullmatch(value):_bad('بصمة الحزمة غير صالحة')
    return value


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _b64(value, maximum, exact=None):
    if not isinstance(value,str) or len(value)>4*((maximum+2)//3):_bad('حجم البيانات المرمزة غير صالح',413)
    try:raw=base64.b64decode(value,validate=True)
    except (ValueError,UnicodeError):_bad('ترميز الحزمة أو المفتاح غير صالح')
    if len(raw)>maximum or exact is not None and len(raw)!=exact:_bad('طول البيانات المرمزة غير صالح')
    if base64.b64encode(raw).decode()!=value:_bad('الترميز يجب أن يكون قياسيًا')
    return raw


def _strict(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate')
            result[key]=value
        return result
    def constant(_):raise ValueError('nonfinite')
    try:
        result=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
        encode(result).encode('utf-8')
        return result
    except (ValueError,TypeError,UnicodeError,RecursionError,OverflowError):_bad('محتوى JSON للحزمة غير صالح')


def _result(value):
    if not isinstance(value,(dict,list)):_bad('نتيجة الإضافة تحتاج كائنًا أو قائمةJSON')
    try:raw=encode(value).encode()
    except (ValueError,TypeError,UnicodeError,RecursionError,OverflowError):_bad('نتيجة الإضافة غير صالحة')
    if len(raw)>LIMITS['result_bytes']:_bad('نتيجة الإضافة تتجاوز64كيبيبايت',413)
    return value


def _package(raw):
    if len(raw)>LIMITS['package_bytes']:_bad('حجم الحزمة يتجاوز2ميبيبايت',413)
    value=_strict(raw)
    if not isinstance(value,dict) or set(value)!={'signed','module_base64','public_key','signature'}:_bad('حقول الحزمة غير مطابقة')
    signed=value['signed']
    if not isinstance(signed,dict) or set(signed)!={'schema','manifest','module_sha256','fixtures'} or signed['schema']!='was.plugin-package/1':_bad('بيان الحزمة الموقع غير صالح')
    manifest=plugin_registry._manifest(signed['manifest'])
    if set(manifest['permissions'])-{'selected_evidence.read','derived_evidence.write'}:_bad('صلاحيات الحزمة خارج منفذ البيانات المعزول')
    if set(manifest['permissions'])!={'selected_evidence.read','derived_evidence.write'}:_bad('الحزمة تحتاج صلاحيتي قراءة المدخل وكتابة النتيجة فقط')
    if any(d['id']==manifest['id'] for d in manifest['dependencies']):_bad('الإضافة لا تعتمد على نفسها')
    module=_b64(value['module_base64'],LIMITS['module_bytes'])
    if not module or hashlib.sha256(module).hexdigest()!=_sha(signed['module_sha256']):_bad('بصمة شيفرة الحزمة غير مطابقة',409)
    fixtures=signed['fixtures']
    if not isinstance(fixtures,list) or not 1<=len(fixtures)<=LIMITS['fixtures']:_bad('الحزمة تحتاج1إلى10عينات مرجعية')
    checked=[]
    for fixture in fixtures:
        if not isinstance(fixture,dict) or set(fixture)!={'input_base64','expected'}:_bad('عينة الحزمة غير صالحة')
        checked.append((_b64(fixture['input_base64'],LIMITS['input_bytes']),_result(fixture['expected'])))
    key=_b64(value['public_key'],32,32)
    signature=_b64(value['signature'],64,64)
    try:Ed25519PublicKey.from_public_bytes(key).verify(signature,encode(signed).encode())
    except InvalidSignature:_bad('توقيع ناشر الحزمة غير صحيح',409)
    return {'manifest':manifest,'module':module,'fixtures':checked,'publisher':hashlib.sha256(key).hexdigest(),
            'public_key':value['public_key'],'module_sha256':signed['module_sha256']}


def fingerprint():
    root=Path(__file__).parent
    files=('plugin_installations.py','plugin_registry.py','tools.py')+tools.ANALYZER_FILES
    return _digest({'runtime':plugin_wasm.fingerprint(),'files':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}})


def _compatible(manifest):
    compat=manifest['compatibility'];current=sys.version_info[:2]+(0,)
    return sys.platform=='linux' and plugin_registry._version(compat['python_min'])<=current<=plugin_registry._version(compat['python_max'])


def _file(store,pid,eid,cache,maximum):
    _eid(eid);record=store.evidence(pid,eid)
    if record['kind']!='original' or type(record['size'])is not int or not 0<=record['size']<=maximum:_bad('اختر ملفًا أصليًا ضمن حد الحجم من المشروع نفسه',413)
    if eid in cache:
        if cache[eid][0]!=record:_bad('تغير وصف أصل الإضافة',409)
        return cache[eid]
    raw=store.read_evidence(pid,eid)
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:_bad('تغير أصل الإضافة',409)
    cache[eid]=(record,raw)
    return record,raw


def _issues(plugins,trust,identifier,seen=None,engine=None):
    seen=set() if seen is None else seen
    if identifier in seen:return [{'code':'dependency_cycle','message':'دورة اعتماديات'}]
    item=plugins[identifier]
    if item['state']!='active' or item['current_version'] is None:return [{'code':'disabled','message':'الإضافة غير مفعلة'}]
    version=item['versions'][item['current_version']];manifest=version['manifest'];issues=[]
    publisher=trust.get(version['publisher'])
    if not publisher or publisher['state']!='trusted':issues.append({'code':'publisher_revoked','message':'مفتاح الناشر غير موثوق حاليًا'})
    if not _compatible(manifest):issues.append({'code':'incompatible_runtime','message':'إصدارPythonأو نظام التشغيل خارج البيان'})
    if engine is not None and item['runtime_sha256']!=engine:issues.append({'code':'stale_runtime','message':'تغير المنفذ؛ أعد اختبار الإصدار وتفعيله'})
    for dependency in manifest['dependencies']:
        target=plugins.get(dependency['id'])
        if not target or target['current_version']!=dependency['version'] or target['state']!='active':
            issues.append({'code':'missing_dependency','message':'اعتمادية غير مفعلة بالإصدار المحدد: '+dependency['id']})
        elif _issues(plugins,trust,dependency['id'],seen|{identifier},engine):
            issues.append({'code':'dependency_blocked','message':'اعتمادية محجوبة: '+dependency['id']})
    return issues


def _check_dependencies(state,manifest,engine):
    temporary={key:{**item,'versions':dict(item['versions'])} for key,item in state['plugins'].items()}
    temporary[manifest['id']]={'state':'active','current_version':manifest['version'],'runtime_sha256':engine,
        'versions':{manifest['version']:{'manifest':manifest,'publisher':'candidate'}}}
    trust={**state['trust'],'candidate':{'state':'trusted'}}
    if _issues(temporary,trust,manifest['id'],engine=engine):_bad('اعتماديات الحزمة أو توافقها غير متحقق',409)


def _load(store,pid):
    _eid(pid);store.project(pid);_guard(store)
    rows=store.rows("SELECT * FROM evidence WHERE project_id=? AND kind=? LIMIT ?",(pid,KIND,LIMITS['journal_records']+1))
    if len(rows)>LIMITS['journal_records'] or sum(r['size'] for r in rows)>LIMITS['journal_bytes']:_bad('تجاوز ميزانية سجل الإضافات',409)
    audits=store.rows("SELECT seq,details FROM audit WHERE action=? AND details LIKE ? ORDER BY seq LIMIT ?",(KIND+'.created','%"project":"'+pid+'"%',LIMITS['journal_records']+1))
    if len(rows)!=len(audits):_bad('سجلات الإضافات لا تطابق وقائع الإنشاء',409)
    indexed={r['id']:r for r in rows};records=[];seen=set();total=0
    state={'plugins':{},'trust':{},'runs':[],'cache':{},'packages':{},'records':records,'previous':None}
    for audit in audits:
        proof=_strict(audit['details'])
        if not isinstance(proof,dict) or set(proof)!={'project','id','sha256'} or proof['project']!=pid or proof['id'] in seen or proof['id'] not in indexed:_bad('إثبات عضوية الإضافات غير مطابق',409)
        row=indexed[proof['id']];seen.add(row['id'])
        if row['size']>LIMITS['record_bytes'] or row['sha256']!=proof['sha256']:_bad('بصمة سجل الإضافات غير مطابقة',409)
        raw=store.read_evidence(pid,row['id']);value=_strict(raw)
        if hashlib.sha256(raw).hexdigest()!=row['sha256'] or not isinstance(value,dict) or not isinstance(value.get('action'),str) or value['action'] not in _FIELDS:_bad('سجل إضافات غير صالح',409)
        action=value['action']
        if set(value)!=_COMMON|_FIELDS[action] or value['schema']!=SCHEMA or value['previous']!=state['previous'] or type(value['created'])not in (int,float) or not math.isfinite(value['created']) or value['created']!=row['created']:_bad('تسلسل الإضافات أو حقوله غير مطابق',409)
        parent=value['previous'] or (value.get('package_evidence') if action=='install' else value.get('input_evidence'))
        if row['parent_id']!=parent:_bad('أصل سجل الإضافات غير مطابق',409)
        if action=='trust':
            key=_b64(value['public_key'],32,32)
            if hashlib.sha256(key).hexdigest()!=value['key_id'] or value['key_id'] in state['trust'] or len(state['trust'])>=LIMITS['publisher_keys']:_bad('تسلسل ثقة الناشر غير صالح',409)
            state['trust'][value['key_id']]={'key_id':value['key_id'],'public_key':value['public_key'],'state':'trusted'}
        elif action=='revoke':
            if value['key_id'] not in state['trust'] or state['trust'][value['key_id']]['state']!='trusted':_bad('سحب الثقة غير صالح',409)
            state['trust'][value['key_id']]['state']='revoked'
        elif action=='install':
            source,package_raw=_file(store,pid,value['package_evidence'],state['cache'],LIMITS['package_bytes'])
            if source['sha256']!=value['package_sha256']:_bad('تغيرت حزمة الإضافة المثبتة',409)
            if source['id'] not in state['packages']:
                total+=len(package_raw)
                if total>LIMITS['aggregate_package_bytes']:_bad('تجاوز حجم مراجعة الحزم',413)
                state['packages'][source['id']]=_package(package_raw)
            package=state['packages'][source['id']];manifest=package['manifest'];identifier=manifest['id'];version=manifest['version']
            key=state['trust'].get(package['publisher'])
            if not key or key['state']!='trusted' or key['public_key']!=package['public_key']:_bad('لم تكن الحزمة موثوقة عند تثبيتها',409)
            if any(value[k]!=v for k,v in [('manifest',manifest),('publisher',package['publisher']),('plugin_id',identifier),('version',version),('fixture_count',len(package['fixtures']))]):_bad('بيان التثبيت لا يطابق الحزمة',409)
            _sha(value['runtime_sha256'])
            item=state['plugins'].setdefault(identifier,{'id':identifier,'current_version':None,'state':'disabled','runtime_sha256':None,'versions':{},'history':[],'activated':set()})
            if len(state['plugins'])>LIMITS['plugins'] or len(item['versions'])>=LIMITS['versions_per_plugin'] or any(plugin_registry._version(version)<=plugin_registry._version(v) for v in item['versions']):_bad('تسلسل إصدارات الحزمة غير صالح',409)
            item['versions'][version]={k:value[k] for k in ('manifest','publisher','package_evidence','package_sha256','fixture_count','runtime_sha256')}|{'version':version,'installed_evidence':row['id']}
            item['history'].append({'action':action,'version':version,'evidence_id':row['id']})
        else:
            identifier=value['plugin_id'];item=state['plugins'].get(identifier);version=value['version']
            if not item or version not in item['versions']:_bad('إصدار غير مثبت في السجل',409)
            _sha(value['runtime_sha256'])
            if action=='run':
                package=item['versions'][version]
                if item['state']!='active' or item['current_version']!=version or any(value[k]!=package[k] for k in ('package_evidence','package_sha256')):_bad('التشغيل لا يطابق الإصدار المفعّل',409)
                source,_=_file(store,pid,value['input_evidence'],state['cache'],LIMITS['input_bytes'])
                if source['sha256']!=value['input_sha256']:_bad('تغير مدخل تشغيل الإضافة',409)
                _result(value['result']);state['runs'].append({'evidence_id':row['id'],**value})
                if len(state['runs'])>LIMITS['runs']:_bad('تجاوز عدد تقارير التشغيل',409)
            elif action=='disable':
                if item['state']!='active' or item['current_version']!=version:_bad('سجل إيقاف غير صالح',409)
                item['state']='disabled';item['history'].append({'action':action,'version':version,'evidence_id':row['id']})
            else:
                if action=='rollback' and (version not in item['activated'] or item['current_version'] is None or plugin_registry._version(version)>=plugin_registry._version(item['current_version'])):_bad('سجل استعادة إصدار غير صالح',409)
                if action=='activate' and item['current_version'] and plugin_registry._version(version)<plugin_registry._version(item['current_version']):_bad('الإصدار الأقدم يحتاج أمر استعادة صريحًا',409)
                item['state']='active';item['current_version']=version;item['runtime_sha256']=value['runtime_sha256'];item['activated'].add(version)
                item['history'].append({'action':action,'version':version,'evidence_id':row['id']})
        state['previous']=row['id'];records.append({'id':row['id'],'sha256':row['sha256']})
    if set(indexed)!=seen:_bad('سجل إضافة محذوف أو غير مسجل',409)
    state['digest']=_digest(records)
    return state


def _recheck(store,pid,state):
    for eid,(record,raw) in state['cache'].items():
        if store.evidence(pid,eid)!=record or store.read_evidence(pid,eid)!=raw:_bad('تغير أصل الإضافة أثناء العملية',409)


def _snapshot(store,pid):
    try:
        with store.lock,_directories(store) as (_,validate):
            state=_load(store,pid);_recheck(store,pid,state);validate();return state
    except OSError:_bad('تغير التخزين أو أصبح غير آمن',409)


def _publish(store,pid,state,record,source=None):
    eid=uid();created=False
    value={'schema':SCHEMA,'created':time.time(),'previous':state['previous'],**record}
    raw=encode(value).encode()
    if len(raw)>LIMITS['record_bytes']:_bad('تجاوز حجم سجل الإضافات',413)
    try:
        with store.lock,_directories(store) as (blobs_fd,validate):
            try:
                store.db.execute('BEGIN IMMEDIATE')
                current=_load(store,pid)
                if current['digest']!=state['digest']:_bad('تغير سجل الإضافات؛ أعد العملية',409)
                _recheck(store,pid,state)
                if len(current['records'])>=LIMITS['journal_records']:_bad('بلغ سجل الإضافات حده',409)
                total=store.db.execute('SELECT coalesce(sum(size),0) FROM evidence WHERE project_id=? AND kind=?',(pid,KIND)).fetchone()[0]
                if total+len(raw)>LIMITS['journal_bytes']:_bad('تجاوز مجموع سجلات الإضافات',413)
                resources=store.resources()
                if resources['evidence_bytes']+len(raw)>store.quota or resources['filesystem_free']<len(raw)+256*1024*1024:_bad('المساحة أو حصة الأدلة غير كافية',409)
                fd=os.open(eid,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=blobs_fd);created=True
                with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                parent=state['previous'] or (source['id'] if source else None)
                digest=hashlib.sha256(raw).hexdigest()
                store.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)',(eid,pid,'plugin-installation.json',digest,len(raw),KIND,parent,value['created']))
                if source:store.db.execute('INSERT INTO relations VALUES(?,?,?,?,?)',(uid(),pid,source['id'],eid,'plugin-installation'))
                store.audit(KIND+'.created',{'project':pid,'id':eid,'sha256':digest})
                fresh=_load(store,pid);_recheck(store,pid,fresh);_recheck(store,pid,state)
                if record['action'] in ('install','activate','rollback','run') and fingerprint()!=record['runtime_sha256']:_bad('تغير منفذ الإضافات قبل حفظ النتيجة',409)
                _guard(store);validate();store.db.commit()
            except BaseException:
                store.db.rollback()
                if created:os.unlink(eid,dir_fd=blobs_fd)
                raise
    except OSError:_bad('تغير التخزين أو أصبح غير آمن',409)
    return {'evidence':store.evidence(pid,eid),'record':value,'notice':NOTICE}


def trust(store,pid,public_key):
    key=_b64(public_key,32,32);key_id=hashlib.sha256(key).hexdigest();state=_snapshot(store,pid)
    if key_id in state['trust']:_bad('المفتاح مسجل بالفعل؛ السحب نهائي لهذا المفتاح',409)
    if len(state['trust'])>=LIMITS['publisher_keys']:_bad('بلغ عدد مفاتيح الناشرين الحد',409)
    return _publish(store,pid,state,{'action':'trust','key_id':key_id,'public_key':public_key})


def revoke(store,pid,key_id):
    _sha(key_id);state=_snapshot(store,pid)
    if key_id not in state['trust'] or state['trust'][key_id]['state']!='trusted':_bad('مفتاح الناشر غير موثوق حاليًا',409)
    return _publish(store,pid,state,{'action':'revoke','key_id':key_id})


def _tested(package):
    try:results=plugin_wasm.execute_batch(package['module'],[raw for raw,_ in package['fixtures']])
    except (ValueError,TypeError,OverflowError):_bad('فشل عزل الحزمة أو مواردها؛ لم تُثبت أو تُفعّل',409)
    if not isinstance(results,list) or len(results)!=len(package['fixtures']):_bad('نتائج اختبارات الحزمة غير كاملة',409)
    for actual,(_,expected) in zip(results,package['fixtures']):
        if encode(_result(actual))!=encode(expected):_bad('فشل اختبار الحزمة المرجعي؛ لم تُفعّل',409)


def install(store,pid,evidence_id):
    state=_snapshot(store,pid);source,raw=_file(store,pid,evidence_id,state['cache'],LIMITS['package_bytes'])
    package=_package(raw);manifest=package['manifest'];key=state['trust'].get(package['publisher'])
    if not key or key['state']!='trusted' or key['public_key']!=package['public_key']:_bad('اعتمد مفتاح الناشر صراحة قبل تثبيت الحزمة',409)
    item=state['plugins'].get(manifest['id'])
    if not item and len(state['plugins'])>=LIMITS['plugins']:_bad('بلغ عدد الإضافات الحد',409)
    if item and (len(item['versions'])>=LIMITS['versions_per_plugin'] or any(plugin_registry._version(manifest['version'])<=plugin_registry._version(v) for v in item['versions'])):_bad('التثبيت يحتاج إصدارًا أحدث لم يُثبت سابقًا',409)
    if not _compatible(manifest):_bad('الحزمة لا تتوافق معPythonأوLinuxالحالي',409)
    engine=fingerprint();_check_dependencies(state,manifest,engine);_tested(package)
    if fingerprint()!=engine:_bad('تغير منفذ الإضافات أثناء الاختبار',409)
    return _publish(store,pid,state,{'action':'install','plugin_id':manifest['id'],'version':manifest['version'],
        'package_evidence':source['id'],'package_sha256':source['sha256'],'publisher':package['publisher'],
        'manifest':manifest,'fixture_count':len(package['fixtures']),'runtime_sha256':engine},source)


def transition(store,pid,plugin_id,action,version=None):
    if not isinstance(plugin_id,str) or not plugin_registry._ID.fullmatch(plugin_id) or action not in ('activate','disable','rollback'):_bad('اختر إضافة وعملية صالحتين')
    state=_snapshot(store,pid);item=state['plugins'].get(plugin_id)
    if not item:_bad('الإضافة غير مثبتة',404)
    if action=='disable':
        if version is not None or item['state']!='active':_bad('الإيقاف يحتاج إضافة مفعلة دون تحديد إصدار',409)
        return _publish(store,pid,state,{'action':action,'plugin_id':plugin_id,'version':item['current_version'],'runtime_sha256':item['runtime_sha256']})
    if not isinstance(version,str) or version not in item['versions']:_bad('اختر إصدارًا مثبتًا',404)
    if action=='rollback' and (version not in item['activated'] or item['current_version'] is None or plugin_registry._version(version)>=plugin_registry._version(item['current_version'])):_bad('الاستعادة تحتاج إصدارًا أقدم سبق تفعيله',409)
    if action=='activate' and item['current_version'] and plugin_registry._version(version)<plugin_registry._version(item['current_version']):_bad('استخدم الاستعادة الصريحة للإصدار الأقدم',409)
    package=state['packages'][item['versions'][version]['package_evidence']]
    if state['trust'][package['publisher']]['state']!='trusted':_bad('ثقة ناشر الإصدار مسحوبة',409)
    engine=fingerprint();_check_dependencies(state,package['manifest'],engine);_tested(package)
    if fingerprint()!=engine:_bad('تغير المنفذ أثناء التفعيل',409)
    return _publish(store,pid,state,{'action':action,'plugin_id':plugin_id,'version':version,'runtime_sha256':engine})


def run(store,pid,plugin_id,evidence_id):
    if not isinstance(plugin_id,str) or not plugin_registry._ID.fullmatch(plugin_id):_bad('معرف الإضافة غير صالح')
    state=_snapshot(store,pid);item=state['plugins'].get(plugin_id)
    if not item:_bad('الإضافة غير مثبتة',404)
    engine=fingerprint()
    if _issues(state['plugins'],state['trust'],plugin_id,engine=engine):_bad('الإضافة غير مفعلة أو ثقتها أو اعتمادياتها غير صالحة',409)
    if len(state['runs'])>=LIMITS['runs']:_bad('بلغت تقارير التشغيل الحد',409)
    version=item['current_version'];installed=item['versions'][version];package=state['packages'][installed['package_evidence']]
    source,raw=_file(store,pid,evidence_id,state['cache'],LIMITS['input_bytes'])
    try:result=_result(plugin_wasm.execute(package['module'],raw))
    except (ValueError,TypeError,OverflowError):_bad('فشل تشغيل الإضافة المعزول؛ لم تُحفظ نتيجة ناجحة',409)
    if fingerprint()!=engine:_bad('تغير المنفذ أثناء التشغيل',409)
    return _publish(store,pid,state,{'action':'run','plugin_id':plugin_id,'version':version,
        'package_evidence':installed['package_evidence'],'package_sha256':installed['package_sha256'],
        'input_evidence':source['id'],'input_sha256':source['sha256'],'runtime_sha256':engine,'result':result},source)


def view(store,pid):
    state=_snapshot(store,pid);engine=fingerprint();plugins=[]
    for identifier,item in state['plugins'].items():
        issues=_issues(state['plugins'],state['trust'],identifier,engine=engine) if item['state']=='active' else []
        plugins.append({'id':identifier,'current_version':item['current_version'],'state':item['state'],
            'effective_state':'blocked' if issues else item['state'],'issues':issues,
            'versions':list(item['versions'].values()),'history':item['history']})
    runs=[{**item,'historical':True,'current_runtime':item['runtime_sha256']==engine} for item in state['runs']]
    return {'schema':SCHEMA,'plugins':plugins,'trust':list(state['trust'].values()),'runs':runs,
            'limits':dict(LIMITS),'runtime_sha256':engine,'notice':NOTICE}
