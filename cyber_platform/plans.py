"""Durable, allowlisted DAG workflows. Inputs are evidence, never executable code."""
import hashlib
import json
import math
import os
import re
import threading
import time
from pathlib import Path
from . import __version__, engine, event_adapters, tools, worker
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode, uid

PREFIX = 'plans.run.'
LIMITS = {'nodes':20, 'runs':20, 'batch_nodes':2, 'batch_seconds':3,
          'worker_seconds':10, 'input_bytes':4*1024*1024, 'output_bytes':4*1024*1024,
          'record_bytes':256*1024}
NOTICE = 'سير عمل محلي يدوي على دفعات؛ لا تنفيذ كود أو أوامر من المدخلات، ولا تشغيل متوازٍ أو خلفي. نجاح التنفيذ ليس إثبات صحة تحليل كل البيانات.'
_LOCK = threading.Lock()
_ID = re.compile(r'[a-f0-9]{32}')
_NAME = re.compile(r'[a-z][a-z0-9_-]{0,39}')
_HASH = re.compile(r'[a-f0-9]{64}')
_ERRORS = {'interrupted_node','engine_changed','source_changed','result_changed','template_changed'}


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _bad(message='خطة العمل أو حالتها غير صالحة', status=400):
    raise Problem(message, status)


def _id(value):
    return isinstance(value,str) and _ID.fullmatch(value) is not None


def _name(value):
    return isinstance(value,str) and _NAME.fullmatch(value) is not None


def _hash(value):
    return isinstance(value,str) and _HASH.fullmatch(value) is not None


def _json_safe(value):
    try:
        raw=encode(value).encode()
        # Prevent deeply nested expectation values and huge scalar comparisons.
        if len(raw)>16384:
            _bad('حجم معايير القبول يتجاوز الحد')
        def depth(item, level=0):
            if level>20:
                _bad('معايير قبول متداخلة أكثر من الحد')
            if isinstance(item,dict):
                for v in item.values():depth(v,level+1)
            elif isinstance(item,list):
                for v in item:depth(v,level+1)
        depth(value)
    except (ValueError,TypeError,UnicodeError,RecursionError):
        _bad()


def validate(plan, allow_slots=False):
    """Return canonical topological order; infer input and condition dependencies."""
    try:
        if not isinstance(plan,dict) or set(plan)!={'schema','name','nodes'} or plan['schema']!='was.plan/1':
            _bad()
        name=plan['name']
        if not isinstance(name,str) or not 1<=len(name.strip())<=120 or any(ord(c)<32 or ord(c)==127 for c in name):
            _bad('اسم الخطة غير صالح')
        nodes=plan['nodes']
        if not isinstance(nodes,list) or not 1<=len(nodes)<=LIMITS['nodes']:
            _bad('الخطة تحتاج 1–20 عقدة')
        normalized=[]; identifiers=set()
        for node in nodes:
            if not isinstance(node,dict) or not {'id','tool','input'}<=set(node) or set(node)-{'id','tool','input','depends_on','when','expect'}:
                _bad('حقول عقدة العمل غير صالحة')
            nid=node['id']; tool=node['tool']; inp=node['input']
            if not _name(nid) or nid in identifiers or not isinstance(tool,str) or tool not in tools.REGISTRY:
                _bad('معرف عقدة أو أداة غير صالحة')
            identifiers.add(nid)
            if not isinstance(inp,dict) or len(inp)!=1:
                _bad('حدد مصدر إدخال واحدًا')
            key=next(iter(inp)); value=inp[key]
            if key=='evidence_id':
                if not _id(value):_bad('معرف دليل غير صالح')
            elif key=='node_id':
                if not _name(value):_bad('معرف عقدة مصدر غير صالح')
            elif key=='slot' and allow_slots:
                if not _name(value):_bad('معرف خانة قالب غير صالح')
            else:_bad('نوع إدخال غير مسموح')
            dependencies=node.get('depends_on',[])
            if not isinstance(dependencies,list) or len(dependencies)>LIMITS['nodes'] or any(not _name(v) for v in dependencies) or len(set(dependencies))!=len(dependencies):
                _bad('اعتماديات العقدة غير صالحة')
            dependencies=list(dependencies)
            when=node.get('when')
            if when is not None:
                if not isinstance(when,dict) or set(when)!={'node_id','status'} or not _name(when['node_id']) or when['status'] not in ('succeeded','failed'):
                    _bad('شرط التفرع غير صالح')
                if when['node_id'] not in dependencies:dependencies.append(when['node_id'])
            if key=='node_id' and value not in dependencies:dependencies.append(value)
            expected=node.get('expect',{})
            if not isinstance(expected,dict) or len(expected)>30 or any(not isinstance(k,str) or not 1<=len(k)<=200 for k in expected):
                _bad('معايير القبول غير صالحة')
            _json_safe(expected)
            normalized.append({'id':nid,'tool':tool,'input':dict(inp),'depends_on':sorted(dependencies),'when':when,'expect':expected})
        if any(d not in identifiers or d==n['id'] for n in normalized for d in n['depends_on']):
            _bad('اعتماد مفقود أو ذاتي')
        ordered=[]; done=set()
        while len(ordered)<len(normalized):
            candidates=[n for n in normalized if n['id'] not in done and set(n['depends_on'])<=done]
            if not candidates:_bad('الخطة تحتوي دورة اعتماد')
            for n in candidates:ordered.append(n);done.add(n['id'])
        result={'schema':'was.plan/1','name':name.strip(),'nodes':ordered}
        _json_safe({'name':result['name']})
        if len(encode(result).encode())>65536:_bad('حجم الخطة يتجاوز الحد')
        return json.loads(encode(result))
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        _bad()


def fingerprint():
    root=Path(__file__).parent
    return _digest({'version':__version__,'files':{n:hashlib.sha256((root/n).read_bytes()).hexdigest()
                    for n in ('__init__.py','plans.py','engine.py','tools.py','worker.py','event_adapters.py','plan_templates.py','detection.py') + tools.ANALYZER_FILES}})


def _key(pid,run_id):
    if not _id(pid) or not _id(run_id):_bad('معرف مشروع أو تشغيل غير صالح')
    return PREFIX+pid+'.'+run_id


def _counts(run):
    return {'total':len(run['plan']['nodes']),'completed':len(run['results']),
            **{status:sum(r['status']==status for r in run['results']) for status in ('succeeded','failed','skipped')}}


def _passed(run):
    c=_counts(run)
    return run['status']=='completed' and c['completed']==c['total'] and c['failed']==0 and c['succeeded']>0


def _public(run):
    return {k:v for k,v in run.items() if k not in ('record_sha256','in_flight')}


def _load(store,pid,run_id):
    try:
        run=store.setting(_key(pid,run_id))
        if run is None:_bad('تشغيل الخطة غير موجود في المشروع',404)
        fields={'schema','id','project_id','version','created','updated','plan','plan_sha256','engine_sha256','sources','status','passed','counts','results','in_flight','notice','record_sha256','template_origin'}
        if not isinstance(run,dict) or not fields<=set(run) or set(run)-fields-{'error_code'} or run['schema']!='was.plan-run/1' or run['id']!=run_id or run['project_id']!=pid:
            _bad(status=409)
        if run['record_sha256']!=_digest({k:v for k,v in run.items() if k!='record_sha256'}) or run['plan']!=validate(run['plan']) or run['plan_sha256']!=_digest(run['plan']) or not _hash(run['engine_sha256']):
            _bad(status=409)
        if not isinstance(run['version'],str) or not re.fullmatch(r'\d+\.\d+\.\d+',run['version']) or any(type(run[k]) not in (int,float) or not math.isfinite(run[k]) or run[k]<=0 for k in ('created','updated')) or run['updated']<run['created']:
            _bad(status=409)
        origin=run['template_origin']
        if origin is not None:
            if not isinstance(origin,dict) or set(origin)!={'evidence_id','sha256','template_id','template_sha256','revision','bundle_sha256'} or not _id(origin['evidence_id']) or not _hash(origin['sha256']) or not _hash(origin['template_sha256']) or not _hash(origin['bundle_sha256']) or not isinstance(origin['template_id'],str) or not 1<=len(origin['template_id'])<=100 or type(origin['revision']) is not int or not 1<=origin['revision']<=100:
                _bad(status=409)
        sources=run['sources']; expected_sources={n['input']['evidence_id'] for n in run['plan']['nodes'] if 'evidence_id' in n['input']}
        if not isinstance(sources,dict) or set(sources)!=expected_sources or any(not _hash(h) for h in sources.values()):_bad(status=409)
        results=run['results']; nodes=run['plan']['nodes']
        if not isinstance(results,list) or len(results)>len(nodes) or run['status'] not in ('pending','running','paused','completed','failed') or type(run['passed']) is not bool:
            _bad(status=409)
        for i,r in enumerate(results):
            common={'node_id','status','elapsed_ms'}
            if not isinstance(r,dict) or not common<=set(r) or r['node_id']!=nodes[i]['id'] or r['status'] not in ('succeeded','failed','skipped') or type(r['elapsed_ms']) is not int or not 0<=r['elapsed_ms']<=3600000:
                _bad(status=409)
            if r['status']=='skipped':
                if set(r)!=common|{'reason'} or r['reason'] not in ('condition_not_met','dependency_not_succeeded') or _skip_reason(nodes[i],results[:i])!=r['reason']:_bad(status=409)
            else:
                needed=common|{'evidence_id','input_evidence','input_sha256','output_sha256','checks'}
                if not needed<=set(r) or set(r)-needed-{'error_code'} or not _id(r['evidence_id']) or not _id(r['input_evidence']) or not _hash(r['input_sha256']) or not _hash(r['output_sha256']) or not isinstance(r['checks'],list) or len(r['checks'])>30:
                    _bad(status=409)
                if _skip_reason(nodes[i],results[:i]) is not None or (r['status']=='failed')!=('error_code' in r) or r.get('error_code') not in (None,'worker_error','acceptance_failed'):_bad(status=409)
        if run['counts']!=_counts(run) or any(type(v) is not int for v in run['counts'].values()) or run['passed']!=_passed(run):_bad(status=409)
        if run['status'] in ('running','paused') and len(results)==len(nodes):_bad(status=409)
        if run['status']=='completed' and len(results)!=len(nodes) or run['status']=='pending' and results or run['status'] in ('pending','paused','completed','failed') and run['in_flight'] is not None:
            _bad(status=409)
        if run['in_flight'] is not None and (len(results)>=len(nodes) or run['in_flight']!=nodes[len(results)]['id']):_bad(status=409)
        if (run['status']=='failed')!=('error_code' in run) or run.get('error_code') not in _ERRORS|{None}:_bad(status=409)
        return run
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError):
        _bad(status=409)


def _stamp(run):
    run['updated']=time.time();run['counts']=_counts(run);run['passed']=_passed(run)
    run['record_sha256']=_digest({k:v for k,v in run.items() if k!='record_sha256'})
    if len(encode(run).encode())>LIMITS['record_bytes']:_bad('تقرير الخطة أكبر من الحد',413)


def _save(store,run,action):
    _stamp(run)
    try:
        with store.lock,store.db,_directories(store) as (_,check):
            _guard(store)
            store.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(_key(run['project_id'],run['id']),encode(run)))
            store.audit(action,{'project':run['project_id'],'id':run['id'],'completed':run['counts']['completed'],'status':run['status']})
            check()
    except OSError:
        _bad('التخزين تغير أو غير آمن',409)


def _skip_reason(node,results):
    previous={r['node_id']:r for r in results}
    when=node['when']
    if when and (when['node_id'] not in previous or previous[when['node_id']]['status']!=when['status']):return 'condition_not_met'
    for dep in node['depends_on']:
        if when and dep==when['node_id'] and when['status']=='failed':continue
        if dep not in previous or previous[dep]['status']!='succeeded':return 'dependency_not_succeeded'
    return None


def _input_id(node,results):
    if 'evidence_id' in node['input']:return node['input']['evidence_id']
    prior=next((r for r in results if r['node_id']==node['input'].get('node_id')),None)
    if prior is None or 'evidence_id' not in prior:_bad('نتيجة العقدة المصدر غير متاحة',409)
    return prior['evidence_id']


def _provenance(store,run):
    if run['engine_sha256']!=fingerprint() or run['version']!=__version__:return 'engine_changed'
    if run['template_origin'] is not None:
        try:
            from . import plan_templates
            proof=plan_templates.verify_instantiation(store,run['project_id'],run['template_origin']['evidence_id'],run['plan'])
            if proof!=run['template_origin']:return 'template_changed'
        except (Problem,ValueError,TypeError,KeyError):return 'template_changed'
    try:
        for eid,digest in run['sources'].items():
            raw=store.read_evidence(run['project_id'],eid)
            if len(raw)>LIMITS['input_bytes'] or hashlib.sha256(raw).hexdigest()!=digest:return 'source_changed'
    except Problem:return 'source_changed'
    try:
        for i,item in enumerate(run['results']):
            if item['status']=='skipped':continue
            node=run['plan']['nodes'][i];eid=item['evidence_id']
            record=store.evidence(run['project_id'],eid)
            if record['size']>LIMITS['output_bytes']:_bad(status=409)
            report=event_adapters.strict_json(store.read_evidence(run['project_id'],eid).decode('utf-8'))
            fields={'schema','node_id','tool','plan_sha256','engine_sha256','input_evidence','input_sha256','result','checks','acceptance','error_code'}
            source=_input_id(node,run['results'][:i]);raw=store.read_evidence(run['project_id'],source)
            if record['kind']!='plan-result' or record['parent_id']!=source or not isinstance(report,dict) or set(report)!=fields or report['schema']!='was.plan-result/1' or report['node_id']!=node['id'] or report['tool']!=node['tool'] or report['plan_sha256']!=run['plan_sha256'] or report['engine_sha256']!=run['engine_sha256'] or report['input_evidence']!=source or report['input_sha256']!=hashlib.sha256(raw).hexdigest() or item['input_evidence']!=source or item['input_sha256']!=report['input_sha256'] or item['output_sha256']!=record['sha256'] or report['checks']!=item['checks']:
                return 'result_changed'
            code=item.get('error_code')
            if code=='worker_error':
                if report['error_code']!=code or report['result'] is not None or report['checks'] or report['acceptance']!='execution_failed':return 'result_changed'
            else:
                checks=engine.accepts(report['result'],node['expect']);accepted=all(c['passed'] for c in checks)
                acceptance='passed' if checks and accepted else 'failed' if not accepted else 'not_evaluated'
                if report['checks']!=checks or report['acceptance']!=acceptance or report['error_code']!=code or accepted!=(item['status']=='succeeded'):return 'result_changed'
    except (Problem,ValueError,TypeError,KeyError,IndexError,RecursionError):return 'result_changed'
    return None


def _fail(store,run,error):
    run.update(status='failed',passed=False,in_flight=None,error_code=error)
    _save(store,run,'plan.failed')
    return _public(run)


def _acquire():
    if not _LOCK.acquire(False):_bad('عملية خطة أخرى قيد التنفيذ',409)


def start(store,project_id,plan,instantiation_id=None):
    plan=validate(plan);_acquire()
    try:
        with store.lock:
            store.project(project_id);_guard(store)
            origin=None
            if instantiation_id is not None:
                from . import plan_templates
                origin=plan_templates.verify_instantiation(store,project_id,instantiation_id,plan)
            sources={}
            for node in plan['nodes']:
                if 'evidence_id' in node['input']:
                    eid=node['input']['evidence_id'];record=store.evidence(project_id,eid)
                    if record['size']>LIMITS['input_bytes']:_bad('مدخل الخطة يتجاوز4MiB',413)
                    sources[eid]=hashlib.sha256(store.read_evidence(project_id,eid)).hexdigest()
            prefix=PREFIX+project_id+'.'
            rows=store.rows('SELECT key FROM settings WHERE key LIKE ? LIMIT 21',(prefix+'%',))
            old=[_load(store,project_id,r['key'][len(prefix):]) for r in rows]
            if len(old)>LIMITS['runs']:_bad(status=409)
            evict=None
            if len(old)>=LIMITS['runs']:
                terminal=sorted((r for r in old if r['status'] in ('completed','failed')),key=lambda r:(r['created'],r['id']))
                if not terminal:_bad('يوجد20تشغيلًا نشطًا؛ أكمل أحدها أولًا',409)
                evict=terminal[0]['id']
            now=time.time();run={'schema':'was.plan-run/1','id':uid(),'project_id':project_id,'version':__version__,
                'created':now,'updated':now,'plan':plan,'plan_sha256':_digest(plan),'engine_sha256':fingerprint(),'sources':sources,
                'status':'pending','passed':False,'counts':{},'results':[],'in_flight':None,'notice':NOTICE,'template_origin':origin}
            _stamp(run)
            with store.db,_directories(store) as (_,check):
                _guard(store)
                if evict:store.db.execute('DELETE FROM settings WHERE key=?',(_key(project_id,evict),))
                store.db.execute('INSERT INTO settings VALUES(?,?)',(_key(project_id,run['id']),encode(run)))
                store.audit('plan.started',{'project':project_id,'id':run['id'],'nodes':len(plan['nodes'])});check()
            return _public(run)
    except OSError:_bad('التخزين تغير أو غير آمن',409)
    finally:_LOCK.release()


def _publish(store,run,item,report,raw):
    if len(raw)>LIMITS['output_bytes']:_bad('نتيجة الخطة تتجاوز4MiB',413)
    eid=item['evidence_id'];pid=run['project_id'];_stamp(run)
    try:
        with store.lock,_directories(store) as (blobs,check):
            created=False
            try:
                with store.db:
                    _guard(store)
                    resources=store.resources()
                    if resources['evidence_bytes']+len(raw)>store.quota or resources['filesystem_free']<len(raw)+256*1024*1024:_bad('حصة الأدلة أو مساحة القرص لا تكفي',409)
                    fd=os.open(eid,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=blobs);created=True
                    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                    store.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)',(eid,pid,'plan-'+item['node_id']+'.json',hashlib.sha256(raw).hexdigest(),len(raw),'plan-result',item['input_evidence'],time.time()))
                    store.db.execute('INSERT INTO relations VALUES(?,?,?,?,?)',(uid(),pid,item['input_evidence'],eid,'اشتقاق نتيجة عقدة خطة'))
                    store.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(_key(pid,run['id']),encode(run)))
                    store.audit('plan.node_finished',{'project':pid,'id':run['id'],'node_id':item['node_id'],'status':item['status'],'evidence_id':eid});check()
            except BaseException:
                if created:os.unlink(eid,dir_fd=blobs)
                raise
    except OSError:_bad('التخزين تغير أو غير آمن',409)


def advance(store,project_id,run_id):
    _acquire()
    try:
        with store.lock:
            _guard(store);run=_load(store,project_id,run_id)
            if run['status']=='failed':return _public(run)
            if run['in_flight'] is not None:return _fail(store,run,'interrupted_node')
            error=_provenance(store,run)
            if error:return _fail(store,run,error)
            if run['status'] in ('completed','paused'):return _public(run)
        deadline=time.monotonic()+LIMITS['batch_seconds'];count=0
        while len(run['results'])<len(run['plan']['nodes']) and count<LIMITS['batch_nodes'] and time.monotonic()<deadline:
            with store.lock:
                error=_provenance(store,run)
                if error:return _fail(store,run,error)
                node=run['plan']['nodes'][len(run['results'])];reason=_skip_reason(node,run['results'])
                if reason:
                    run['results'].append({'node_id':node['id'],'status':'skipped','reason':reason,'elapsed_ms':0})
                    if len(run['results'])==len(run['plan']['nodes']):run['status']='completed'
                    else:run['status']='running'
                    _save(store,run,'plan.node_skipped');count+=1;continue
                source=_input_id(node,run['results']);data=store.read_evidence(project_id,source)
                if len(data)>LIMITS['input_bytes']:_bad('مدخل العقدة يتجاوز4MiB',413)
                input_hash=hashlib.sha256(data).hexdigest()
                run.update(status='running',in_flight=node['id']);_save(store,run,'plan.node_started')
            started=time.monotonic();code=None;result=None;checks=[]
            try:
                result=worker.analyze(node['tool'],data,timeout=LIMITS['worker_seconds'])
                checks=engine.accepts(result,node['expect'])
                if not all(c['passed'] for c in checks):code='acceptance_failed'
            except (ValueError,TypeError,KeyError,IndexError,OverflowError,RuntimeError,OSError):code='worker_error';result=None;checks=[]
            item={'node_id':node['id'],'status':'failed' if code else 'succeeded','evidence_id':uid(),'input_evidence':source,
                  'input_sha256':input_hash,'output_sha256':'','checks':checks,'elapsed_ms':min(3600000,max(0,int((time.monotonic()-started)*1000)))}
            if code:item['error_code']=code
            report={'schema':'was.plan-result/1','node_id':node['id'],'tool':node['tool'],'plan_sha256':run['plan_sha256'],
                    'engine_sha256':run['engine_sha256'],'input_evidence':source,'input_sha256':input_hash,'result':result,'checks':checks,
                    'acceptance':'execution_failed' if code=='worker_error' else 'failed' if code else 'passed' if checks else 'not_evaluated','error_code':code}
            raw=encode(report).encode();item['output_sha256']=hashlib.sha256(raw).hexdigest()
            with store.lock:
                error=_provenance(store,run)
                if error:return _fail(store,run,error)
                if hashlib.sha256(store.read_evidence(project_id,source)).hexdigest()!=input_hash:return _fail(store,run,'source_changed')
                run['results'].append(item);run['in_flight']=None
                if len(run['results'])==len(run['plan']['nodes']):run['status']='completed'
                _publish(store,run,item,report,raw)
            count+=1
        return _public(run)
    finally:_LOCK.release()


def _control(store,pid,run_id,operation):
    _acquire()
    try:
        with store.lock:
            _guard(store);run=_load(store,pid,run_id)
            if run['status']=='failed':return _public(run)
            if run['in_flight'] is not None:return _fail(store,run,'interrupted_node')
            error=_provenance(store,run)
            if error:return _fail(store,run,error)
            if run['status']=='completed':return _public(run)
            if operation=='pause':run['status']='paused'
            elif run['status']=='paused':run['status']='running' if run['results'] else 'pending'
            _save(store,run,'plan.'+operation)
            return _public(run)
    finally:_LOCK.release()


def pause(store,project_id,run_id):return _control(store,project_id,run_id,'pause')


def resume(store,project_id,run_id):return _control(store,project_id,run_id,'resume')


def status(store,project_id,run_id):
    try:
        with store.lock,_directories(store) as (_,check):
            store.project(project_id);_guard(store);run=_load(store,project_id,run_id)
            error=_provenance(store,run)
            if error:
                run.update(status='failed',passed=False,error_code=error)
            check()
            return _public(run)
    except OSError:_bad('التخزين تغير أو غير آمن',409)


def history(store,project_id):
    with store.lock:
        store.project(project_id);_guard(store);prefix=PREFIX+project_id+'.'
        rows=store.rows('SELECT key FROM settings WHERE key LIKE ? LIMIT 21',(prefix+'%',))
        if len(rows)>LIMITS['runs']:_bad(status=409)
        runs=[_load(store,project_id,r['key'][len(prefix):]) for r in rows]
        return {'runs':[{k:r[k] for k in ('id','project_id','created','updated','status','passed','counts','plan_sha256','engine_sha256','version')}|{'name':r['plan']['name'],'verification':'recorded_summary'} for r in sorted(runs,key=lambda r:(r['created'],r['id']),reverse=True)],'limits':dict(LIMITS),'notice':NOTICE}
