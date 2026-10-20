"""Explicit owner reports: immutable metadata snapshots, bounded provenance checks."""
import hashlib
import html
import math
import re
import time
from pathlib import Path
from . import __version__, detection, tools
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode, uid

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
NOTICE = 'تقرير لقطة تاريخية خاصة، لا ينسخ محتوى الملفات الأصلية. سلامة البصمات لا تثبت صحة الادعاءات أو حماية حية. نتائج الخطط والتغطية محفوظة بتاريخها وليست إعادة تنفيذ شاملة.'
FIELDS = {'schema','id','version','title','created','project','engine_sha256','evidence','plans','coverage','audit','notice','digest'}


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _fingerprint():
    root = Path(__file__).parent
    return _digest({'version': __version__, 'files': {n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('case_reports.py','plans.py','coverage_scans.py','coverage.py','detection.py','event_ingest.py','event_adapters.py','tools.py','worker.py') + tools.ANALYZER_FILES}})


def _ids(values, maximum):
    if not isinstance(values,list) or len(values)>maximum or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{32}',v) for v in values) or len(set(values)) != len(values):
        raise Problem('قائمة مراجع التقرير غير صالحة')
    return values


def _hash(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def _plan_cost(store,pid,run_id):
    """Preflight every known read made by plans.status, including duplicates."""
    from . import plans
    run=plans._load(store,pid,run_id)
    def size(eid):
        n=store.evidence(pid,eid)['size']
        if type(n) is not int or not 0<=n<=4*1024*1024:raise Problem('حجم مرجع خطة غير صالح',413)
        return n
    cost=sum(size(eid) for eid in run['sources'])
    cost+=sum(size(r['evidence_id'])+size(r['input_evidence']) for r in run['results'] if r['status']!='skipped')
    if run['template_origin'] is not None:
        eid=run['template_origin']['evidence_id'];proof_size=size(eid)
        if proof_size>98304:raise Problem('حجم ربط القالب غير صالح',413)
        proof=detection._json(store.read_evidence(pid,eid))
        cost+=2*proof_size+sum(size(b['evidence_id']) for b in proof['bindings'].values())
        # Library verification reads every retained owner revision and one selected revision.
        sizes=[r['size'] for r in store.rows("SELECT size FROM evidence WHERE project_id=? AND kind='plan-template'",(pid,))]
        if len(sizes)>300 or any(type(n) is not int or not 0<=n<=98304 for n in sizes):raise Problem('ميزانية مراجعات القوالب غير صالحة',413)
        cost+=2*sum(sizes)
    return cost


def _load(store,pid,eid):
    record=store.evidence(pid,eid)
    if record['kind']!='project-report' or record['size']>MAX_REPORT_BYTES:
        raise Problem('ليس تقرير مشروع محفوظًا مدعومًا',409)
    value=detection._json(store.read_evidence(pid,eid))
    if not isinstance(value,dict) or set(value)!=FIELDS or value['schema']!='was.project-report/1' or not isinstance(value['project'],dict) or value['project'].get('id')!=pid or value['digest']!=_digest({k:v for k,v in value.items() if k!='digest'}):
        raise Problem('تقرير المشروع غير سليم',409)
    if not isinstance(value['evidence'],list) or len(value['evidence'])>50 or not isinstance(value['plans'],list) or len(value['plans'])>5 or value['coverage'] is not None and not isinstance(value['coverage'],dict):
        raise Problem('مراجع التقرير المحفوظة غير صالحة',409)
    try:
        _ids([value['id']],1)
        if not isinstance(value['title'],str) or not 1<=len(value['title'])<=120 or not _hash(value['engine_sha256']) or type(value['created']) not in (int,float) or not math.isfinite(value['created']) or value['created']<=0:raise ValueError()
        consumed=0
        for entry in value['evidence']:
            fields={'id','name','kind','sha256','size','created','verification','summary'}
            if not isinstance(entry,dict) or set(entry)!=fields or not _hash(entry['sha256']) or type(entry['size']) is not int or not 0<=entry['size']<=4*1024*1024:raise ValueError()
            _ids([entry['id']],1);consumed+=entry['size']
            if any(not isinstance(entry[k],str) for k in ('name','kind','verification')) or entry['summary'] is not None and not isinstance(entry['summary'],dict):raise ValueError()
        if consumed>MAX_INPUT_BYTES:raise ValueError()
        _ids([e['id'] for e in value['evidence']],50)
        for entry in value['plans']:
            if not isinstance(entry,dict) or set(entry)!={'run_id','record_sha256','snapshot'} or not _hash(entry['record_sha256']) or not isinstance(entry['snapshot'],dict) or _digest(entry['snapshot'])!=entry['record_sha256'] or entry['snapshot'].get('id')!=entry['run_id'] or entry['snapshot'].get('project_id')!=pid:raise ValueError()
        _ids([e['run_id'] for e in value['plans']],5)
        entry=value['coverage']
        if entry is not None:
            if set(entry)!={'scan_id','record_sha256','snapshot','current_validity'} or not _hash(entry['record_sha256']) or not isinstance(entry['snapshot'],dict) or _digest(entry['snapshot'])!=entry['record_sha256'] or entry['current_validity']!='snapshot_only' or entry['snapshot'].get('id')!=entry['scan_id'] or entry['snapshot'].get('project_id')!=pid or entry['snapshot'].get('status')!='completed':raise ValueError()
            _ids([entry['scan_id']],1)
    except (Problem,ValueError,TypeError,KeyError,RecursionError):
        raise Problem('حقول مراجع التقرير أو ميزانيتها غير سليمة',409) from None
    return value


def history(store,pid):
    store.project(pid)
    rows=store.rows("SELECT id,name,sha256,size,created FROM evidence WHERE project_id=? AND kind='project-report' ORDER BY created DESC LIMIT 50",(pid,))
    return {'reports':rows,'notice':NOTICE}


def read(store,pid,eid):
    with store.lock,_directories(store):
        _guard(store)
        return _load(store,pid,eid)


def build(store,pid,title,evidence_ids,plan_run_ids,coverage_scan_id=None):
    from . import plans,coverage_scans
    if not isinstance(title,str) or not 1<=len(title.strip())<=120 or any(ord(c)<32 or ord(c)==127 for c in title):
        raise Problem('عنوان التقرير يحتاج1–120حرفًا دون محارف تحكم')
    _ids(evidence_ids,50);_ids(plan_run_ids,5)
    if coverage_scan_id is not None:_ids([coverage_scan_id],1)
    if not evidence_ids and not plan_run_ids and coverage_scan_id is None:
        raise Problem('اختر دليلًا أو خطة أو فحص تغطية للتقرير')
    try:
        with store.lock,_directories(store) as (_,validate):
            _guard(store)
            project=store.project(pid)
            if store.rows("SELECT COUNT(*) AS n FROM evidence WHERE project_id=? AND kind='project-report'",(pid,))[0]['n']>=50:
                raise Problem('حد المشروع50تقريرًا محفوظًا',413)
            consumed=0;entries=[];replays=0;deadline=time.monotonic()+3
            fingerprint=_fingerprint()
            for eid in evidence_ids:
                rec=store.evidence(pid,eid)
                if rec['kind']=='project-report':raise Problem('لا تضمن تقرير مشروع داخل تقرير آخر')
                consumed+=rec['size']
                if rec['size']>4*1024*1024 or consumed>MAX_INPUT_BYTES:
                    raise Problem('مراجع التقرير تتجاوز حدود القراءة:4MiBللدليل و32MiBللمجموع',413)
                raw=store.read_evidence(pid,eid)
                entry={k:rec[k] for k in ('id','name','kind','sha256','size','created')}
                entry.update(verification='hash_checked',summary=None)
                if rec['kind']=='detection-test':
                    if replays<3 and time.monotonic()<deadline:
                        replays+=1
                        checked=detection.verify_report(store,pid,eid)
                        entry['verification']='replayed_'+checked['status']
                        if checked.get('report'):
                            report=checked['report']
                            entry['summary']={'evaluation_status':report['evaluation_status'],'evaluated_rules':report['evaluated_rules'],'rules':report['result']['rules']}
                    else:entry['verification']='not_replayed_budget'
                entries.append(entry)
            runs=[]
            for run_id in plan_run_ids:
                consumed+=_plan_cost(store,pid,run_id)
                if consumed>MAX_INPUT_BYTES:raise Problem('مصادر التقرير وإثبات الخطط تتجاوز32MiB',413)
                run=plans.status(store,pid,run_id)
                runs.append({'run_id':run_id,'record_sha256':_digest(run),'snapshot':run})
            scan=None
            if coverage_scan_id is not None:
                value=coverage_scans.status(store,pid,coverage_scan_id)
                if value['status']!='completed':raise Problem('اختر فحص تغطية مكتملًا للتقرير',409)
                scan={'scan_id':coverage_scan_id,'record_sha256':_digest(value),'snapshot':value,'current_validity':'snapshot_only'}
            audit=store.verify_audit()
            if not audit['valid'] or fingerprint!=_fingerprint():raise Problem('تغير نطاق التقرير أثناء البناء',409)
            report={'schema':'was.project-report/1','id':uid(),'version':__version__,'title':title.strip(),'created':time.time(),'project':project,'engine_sha256':fingerprint,'evidence':entries,'plans':runs,'coverage':scan,'audit':audit,'notice':NOTICE}
            report['digest']=_digest(report)
            if len(encode(report).encode())>MAX_REPORT_BYTES:raise Problem('حجم التقرير يتجاوز1MiB؛ اختر مراجع أقل',413)
            validate()
            artifact=detection._persist(store,pid,report,'project-report',parent=evidence_ids[0] if evidence_ids else None)
            return {'evidence':artifact,'report':report}
    except OSError:
        raise Problem('التخزين تغيّر أو غير آمن',409) from None


def verify(store,pid,eid):
    """Recheck bytes and referenced saved records, not real-world effectiveness."""
    from . import plans,coverage_scans
    with store.lock,_directories(store):
        _guard(store);report=_load(store,pid,eid);issues=[];consumed=0
        if report['engine_sha256']!=_fingerprint():issues.append({'type':'engine','reason':'changed'})
        for entry in report['evidence']:
            try:
                consumed+=entry['size']
                if consumed>MAX_INPUT_BYTES or entry['size']>4*1024*1024:raise Problem('budget')
                rec=store.evidence(pid,entry['id'])
                if any(rec[k]!=entry[k] for k in ('sha256','size','kind')):raise Problem('changed')
                raw=store.read_evidence(pid,entry['id'])
                if hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise Problem('changed')
            except (Problem,KeyError,TypeError,ValueError):issues.append({'type':'evidence','id':entry.get('id'),'reason':'changed_missing_or_budget'})
        for entry in report['plans']:
            try:
                consumed+=_plan_cost(store,pid,entry['run_id'])
                if consumed>MAX_INPUT_BYTES:raise Problem('budget')
                if _digest(plans.status(store,pid,entry['run_id']))!=entry['record_sha256']:raise Problem('changed')
            except (Problem,KeyError,TypeError,ValueError):issues.append({'type':'plan','id':entry.get('run_id'),'reason':'changed_or_missing'})
        if report['coverage'] is not None:
            entry=report['coverage']
            try:
                if _digest(coverage_scans.status(store,pid,entry['scan_id']))!=entry['record_sha256']:raise Problem('changed')
            except (Problem,KeyError,TypeError,ValueError):issues.append({'type':'coverage','id':entry.get('scan_id'),'reason':'changed_or_missing'})
        return {'report_evidence_id':eid,'checked_at':time.time(),'passed':not issues,'issues':issues,'meaning':'مطابقة بايتات الأدلة وسجلات المراجع المحفوظة فقط؛ لا إعادة تنفيذ أو إثبات فعالية دفاعية'}


def render_html(report):
    """Standalone, script-free HTML. Every dynamic value is escaped as text."""
    def esc(value):return html.escape(str(value),quote=True)
    def pre(value):return '<pre>'+esc(encode(value))+'</pre>'
    rows=''.join('<tr>'+''.join('<td>'+esc(e[k])+'</td>' for k in ('name','kind','size','sha256','verification'))+'</tr>' for e in report['evidence'])
    return ('<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
            '<title>'+esc(report['title'])+'</title><style>body{font-family:system-ui;margin:2rem;line-height:1.8}table{border-collapse:collapse;width:100%}td,th{border:1px solid #888;padding:.5rem;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}section{break-inside:avoid}</style>'
            '<h1>'+esc(report['title'])+'</h1><p>'+esc(report['notice'])+'</p><h2>المشروع ووقت اللقطة</h2>'+pre({'project':report['project'],'created':report['created'],'version':report['version']})+
            '<h2>الأدلة المختارة</h2><table><tr><th>الاسم</th><th>النوع</th><th>الحجم</th><th>البصمة</th><th>التحقق</th></tr>'+rows+'</table><h2>ملخصات الكشف</h2>'+pre([e['summary'] for e in report['evidence'] if e['summary'] is not None])+
            '<h2>خطط التحليل المحفوظة</h2>'+pre(report['plans'])+'<h2>لقطة التغطية التاريخية</h2>'+pre(report['coverage'])+'<h2>التدقيق والبصمات</h2>'+pre({'audit':report['audit'],'report_digest':report['digest'],'engine_sha256':report['engine_sha256']})+'</html>').encode('utf-8')
