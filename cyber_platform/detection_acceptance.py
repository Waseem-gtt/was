"""Version-bound rule fixtures and reproducible whole-library acceptance tests."""
import hashlib
import json
import re
import time
from pathlib import Path
from . import detection, tools, worker
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode

PREFIX = 'detection.fixtures.'
LIMITS = {'source_bytes':1024*1024,'aggregate_bytes':4*1024*1024,'events_per_fixture':1000,
          'aggregate_events':10000,'fixture_revisions':20,'rules':58,'runs':20}
NOTICE = 'اختبارات ملفات مرجعية بتسميات مصدرها؛ التغطية تخص القواعد وإصداراتها في هذه المكتبة، وليست حماية حية أو إثبات صحة كل ادعاء. Sigma مرجع قابل للتكامل، وليس صيغة القواعد الحالية.'


def _bad(message='بيانات قبول القواعد أو إثباتها غير صالحة', status=400):
    raise Problem(message,status)


def fingerprint():
    root=Path(__file__).parent
    return detection._digest({name:hashlib.sha256((root/name).read_bytes()).hexdigest()
                             for name in ('detection_acceptance.py','detection.py','tools.py','worker.py')+tools.ANALYZER_FILES})


def _execute_batch(raw):
    """Fixed worker dispatch, never a callable supplied by an uploaded document."""
    value=detection._json(raw)
    if not isinstance(value,dict) or set(value)!={'cases'} or not isinstance(value['cases'],list) or not 1<=len(value['cases'])<=LIMITS['rules']:
        raise ValueError('صيغة دفعة القواعد غير صالحة')
    results=[];total=0
    for case in value['cases']:
        if not isinstance(case,dict) or set(case)!={'rule','content','expected_indexes'} or not isinstance(case['content'],str):
            raise ValueError('صيغة حالة القاعدة غير صالحة')
        content=case['content'].encode('utf-8')
        if len(content)>LIMITS['source_bytes']:raise ValueError('تجاوز حجم عينة القاعدة')
        events,_=detection._events(detection._json(content))
        expected=case['expected_indexes']
        if not 2<=len(events)<=LIMITS['events_per_fixture'] or not isinstance(expected,list) or not 0<len(expected)<len(events) or any(type(index)is not int or not 0<=index<len(events) for index in expected) or len(set(expected))!=len(expected):
            raise ValueError('العينة تحتاج تسميات موجبة وسالبة صريحة دون تكرار')
        total+=len(events)
        if total>LIMITS['aggregate_events']:raise ValueError('تجاوز مجموع أحداث الدفعة')
        rule=detection._rule(case['rule'])
        analyzed=tools.analyze('rules',encode({'events':events,'rules':[{**rule,'expected_event_indexes':expected}]}).encode())
        result=analyzed['rules'][0]
        metrics=result['metrics']
        tp,fp,fn=(metrics[key] for key in ('true_positive','false_positive','false_negative'))
        metrics['precision']=tp/(tp+fp) if tp+fp else None
        metrics['recall']=tp/(tp+fn) if tp+fn else None
        results.append({'id':rule['id'],'events':len(events),'metrics':metrics,'passed':metrics['passed']})
    return results


def execute_batch(raw):
    try:return _execute_batch(raw)
    except (Problem, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError('بيانات عينات القواعد أو التسميات غير صالحة') from None


def _execute(cases):
    payload=encode({'cases':cases}).encode()
    if len(payload)>LIMITS['aggregate_bytes']:_bad('مجموع عينات الدفعة يتجاوز4ميبيبايت',413)
    try:
        result=worker.analyze('detection-acceptance',payload,timeout=3)
        if not isinstance(result,list) or len(result)!=len(cases) or any(not isinstance(item,dict) or set(item)!={'id','events','metrics','passed'} or item['id']!=case['rule']['id'] or type(item['passed'])is not bool or not isinstance(item['metrics'],dict) or item['metrics'].get('passed') is not item['passed'] for item,case in zip(result,cases)):
            raise ValueError('invalid worker result')
        for item,case in zip(result,cases):
            metrics=item['metrics'];count=item['events'];positives=len(case['expected_indexes'])
            fields=('true_positive','false_positive','false_negative','true_negative')
            if type(count)is not int or not 2<=count<=LIMITS['events_per_fixture'] or any(type(metrics.get(key))is not int or metrics[key]<0 for key in fields):
                raise ValueError('invalid metrics')
            tp,fp,fn,tn=(metrics[key] for key in fields)
            precision=tp/(tp+fp) if tp+fp else None
            recall=tp/(tp+fn) if tp+fn else None
            if tp+fn!=positives or tn+fp!=count-positives or item['passed']!=(fp==0 and fn==0) or metrics.get('precision')!=precision or metrics.get('recall')!=recall:
                raise ValueError('inconsistent metrics')
        return result
    except (ValueError,Problem):_bad('تعذر تنفيذ عينات القواعد ضمن الصيغة وحدود الموارد؛ لم يسجل نجاح',409)


def _proof(store,pid,evidence,kind):
    details=encode({'project':pid,'id':evidence['id'],'sha256':evidence['sha256']})
    if evidence['kind']!=kind or not store.rows('SELECT seq FROM audit WHERE action=? AND details=? LIMIT 1',(kind+'.created',details)):
        _bad('إثبات إنشاء سجل القواعد مفقود',409)
    return detection._json(store.read_evidence(pid,evidence['id']))


def _fixtures(store,pid):
    rows=store.rows("SELECT * FROM evidence WHERE project_id=? AND kind='detection-fixture'",(pid,))
    if len(rows)>LIMITS['rules']*LIMITS['fixture_revisions'] or sum(row['size'] for row in rows)>LIMITS['aggregate_bytes']:
        _bad('تجاوز ميزانية مراجعة عينات القواعد',409)
    enrollments=store.rows("SELECT details FROM audit WHERE action='detection-fixture.created' AND details LIKE ? LIMIT ?",
                           ('%"project":"'+pid+'"%',LIMITS['rules']*LIMITS['fixture_revisions']+1))
    try:
        enrolled=[json.loads(item['details']) for item in enrollments]
        if len(enrolled)>LIMITS['rules']*LIMITS['fixture_revisions'] or any(set(item)!={'project','id','sha256'} or item['project']!=pid for item in enrolled) or len({item['id'] for item in enrolled})!=len(enrolled) or {item['id'] for item in enrolled}!={item['id'] for item in rows}:
            _bad('سجلات العينات لا تطابق كامل إثباتات إنشائها',409)
    except (ValueError,TypeError,KeyError):
        _bad('إثباتات تسجيل عينات القواعد غير صالحة',409)
    grouped={};records={}
    fields={'schema','rule','rule_sha256','input_evidence','input_sha256','expected_indexes','revision','previous_evidence','created'}
    for evidence in rows:
        if evidence['size']>16384:_bad(status=409)
        value=_proof(store,pid,evidence,'detection-fixture')
        if not isinstance(value,dict) or set(value)!=fields or value['schema']!='was.detection-fixture/1' or value['input_evidence']!=evidence['parent_id'] or detection._digest(value['rule'])!=value['rule_sha256'] or type(value['revision'])is not int or not 1<=value['revision']<=LIMITS['fixture_revisions']:
            _bad(status=409)
        rid=value['rule'].get('id')
        if not isinstance(rid,str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,79}',rid):_bad(status=409)
        grouped.setdefault(rid,[]).append((value['revision'],evidence['id']))
        records[evidence['id']]=value
    index={}
    for rid,revisions in grouped.items():
        revisions.sort();previous=None;index[rid]=[]
        for expected,(revision,eid) in enumerate(revisions,1):
            if revision!=expected or records[eid]['previous_evidence']!=previous:_bad('تسلسل عينات القواعد غير سليم',409)
            index[rid].append(eid);previous=eid
    if store.setting(PREFIX+pid,{})!=index:_bad('فهرس عينات القواعد لا يطابق إثباتات إنشائها',409)
    return index,records


def _case(store,pid,rule,index,records,catalog):
    rid=rule['id']
    if rid in index:
        eid=index[rid][-1];receipt=records[eid]
        if receipt['rule']!=rule:return None,{'fixture_status':'stale','fixture_id':eid}
        source=store.evidence(pid,receipt['input_evidence'])
        if source['kind']!='original' or source['size']>LIMITS['source_bytes'] or source['sha256']!=receipt['input_sha256']:_bad('أصل عينة القاعدة غير مطابق',409)
        raw=store.read_evidence(pid,source['id'])
        try:content=raw.decode('utf-8')
        except UnicodeError:_bad('عينة القاعدة تحتاجUTF-8',409)
        return {'rule':{k:rule[k] for k in detection.FIELDS},'content':content,'expected_indexes':receipt['expected_indexes']}, {'fixture_status':'current','fixture_id':eid,'input_evidence':source['id'],'input_sha256':source['sha256']}
    if rule['origin']=='builtin':
        if not isinstance(catalog['fixtures'],list):_bad('عقد عينات المكتبة غير صالح',409)
        for fixture in catalog['fixtures']:
            if not isinstance(fixture,dict) or not isinstance(fixture.get('input'),dict):_bad('عقد عينة المكتبة غير صالح',409)
            indexes=fixture['input'].get('expected_matches',{}).get(rid)
            if indexes is not None:
                raw=encode(fixture['input']).encode()
                return {'rule':{k:rule[k] for k in detection.FIELDS},'content':raw.decode(),'expected_indexes':indexes}, {'fixture_status':'current','fixture_id':'builtin:'+fixture['id'],'input_evidence':None,'input_sha256':hashlib.sha256(raw).hexdigest()}
    return None,{'fixture_status':'missing','fixture_id':None}


def register(store,pid,rule_id,evidence_id,expected_indexes):
    with store.lock,_directories(store):
        _guard(store);catalog=detection.library(store,pid)
        rules={rule['id']:rule for rule in catalog['rules']}
        if not isinstance(rule_id,str) or rule_id not in rules:_bad('اختر قاعدة موجودة',404)
        source=store.evidence(pid,evidence_id)
        if source['kind']!='original' or source['size']>LIMITS['source_bytes']:_bad('اختر ملفJSONأصليًا لا يتجاوز1ميبيبايت',413)
        raw=store.read_evidence(pid,evidence_id)
        try:content=raw.decode('utf-8')
        except UnicodeError:_bad('عينة القاعدة تحتاجUTF-8')
        rule=rules[rule_id];before=fingerprint();index,records=_fixtures(store,pid)
    _execute([{'rule':{k:rule[k] for k in detection.FIELDS},'content':content,'expected_indexes':expected_indexes}])
    with store.lock,_directories(store):
        _guard(store)
        current=detection.library(store,pid)
        if fingerprint()!=before or current!=catalog or store.read_evidence(pid,evidence_id)!=raw:_bad('تغير مصدر العينة أو القاعدة أثناء التحقق',409)
        index,records=_fixtures(store,pid);prior=index.get(rule_id,[])
        if len(prior)>=LIMITS['fixture_revisions']:_bad('بلغت القاعدة حد20مراجعة للعينة',409)
        receipt={'schema':'was.detection-fixture/1','rule':rule,'rule_sha256':detection._digest(rule),'input_evidence':evidence_id,'input_sha256':source['sha256'],
                 'expected_indexes':sorted(expected_indexes),'revision':len(prior)+1,'previous_evidence':prior[-1] if prior else None,'created':time.time()}
        artifact=detection._persist(store,pid,receipt,'detection-fixture',evidence_id,setting=(PREFIX+pid,index,rule_id))
        return {'evidence':artifact,'fixture':receipt,'notice':NOTICE}


def status(store,pid):
    with store.lock,_directories(store):
        _guard(store);catalog=detection.library(store,pid);index,records=_fixtures(store,pid)
        library=[]
        for rule in catalog['rules']:
            _,metadata=_case(store,pid,rule,index,records,catalog);library.append({**rule,**metadata})
        runs=[]
        for row in store.rows("SELECT * FROM evidence WHERE project_id=? AND kind='detection-acceptance' ORDER BY created DESC LIMIT 20",(pid,)):
            saved=_proof(store,pid,row,'detection-acceptance')
            runs.append({'evidence_id':row['id'],**{key:saved[key] for key in ('created','passed','complete','covered_rules','total_rules')}})
        return {'library':library,'runs':runs,'limits':dict(LIMITS),'notice':NOTICE}


def run(store,pid):
    with store.lock,_directories(store):
        _guard(store);catalog=detection.library(store,pid);index,records=_fixtures(store,pid);before=fingerprint()
        if len(store.rows("SELECT id FROM evidence WHERE project_id=? AND kind='detection-acceptance'",(pid,)))>=LIMITS['runs']:_bad('حد تقارير قبول القواعد20تقريرًا لكل مشروع',409)
        cases=[];rows=[]
        for rule in catalog['rules']:
            case,metadata=_case(store,pid,rule,index,records,catalog)
            row={'id':rule['id'],'title':rule['title'],'version':rule['version'],**metadata,'status':'pending' if case else 'stale_fixture' if metadata['fixture_status']=='stale' else 'missing_fixture'}
            rows.append(row)
            if case:cases.append(case)
    actual=_execute(cases) if cases else []
    by_id={item['id']:item for item in actual}
    for row in rows:
        if row['id'] in by_id:
            result=by_id[row['id']];row.update(status='passed' if result['passed'] else 'failed',metrics=result['metrics'],events=result['events'])
    with store.lock,_directories(store):
        _guard(store)
        if fingerprint()!=before or detection.library(store,pid)!=catalog or _fixtures(store,pid)[0]!=index:_bad('تغيرت المكتبة أو العينات أثناء الاختبار؛ لم ينشر التقرير',409)
        for row in rows:
            if row.get('input_evidence'):
                source=store.read_evidence(pid,row['input_evidence'])
                if hashlib.sha256(source).hexdigest()!=row['input_sha256']:_bad('تغير مصدر العينة أثناء الاختبار',409)
        complete=len(actual)==len(rows);passed=complete and all(row['status']=='passed' for row in rows)
        value={'schema':'was.detection-acceptance/1','created':time.time(),'passed':passed,'complete':complete,'covered_rules':len(actual),'total_rules':len(rows),
               'rules':catalog['rules'],'bundle_sha256':catalog['bundle_sha256'],'engine_sha256':before,'rows':rows,'notice':NOTICE,'historical':True}
        artifact=detection._persist(store,pid,value,'detection-acceptance')
        return {'evidence':artifact,'report':value}


def report(store,pid,eid):
    with store.lock,_directories(store):
        _guard(store);store.project(pid);evidence=store.evidence(pid,eid)
        value=_proof(store,pid,evidence,'detection-acceptance')
        if not isinstance(value,dict) or value.get('schema')!='was.detection-acceptance/1':_bad(status=409)
        return {'evidence':evidence,'report':value}
