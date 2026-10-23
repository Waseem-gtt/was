"""Owner-scoped immutable entity and relationship assertions with source proofs."""
import datetime
import hashlib
import json
import math
import os
import re
import time
from .integrity import _directories
from .quality import _guard
from .store import Problem, encode, uid

SCHEMA = 'was.knowledge-graph/1'
ENTITY_TYPES = ('asset', 'software', 'vulnerability', 'event', 'evidence', 'experiment')
RELATION_TYPES = ('related_to', 'runs', 'affects', 'observed_on', 'derived_from', 'supports', 'contradicts', 'tested_by')
LIMITS = {'entities':128, 'relations':256, 'source_bytes':1024*1024,
          'reference_bytes':4*1024*1024, 'aggregate_source_bytes':8*1024*1024, 'record_bytes':16384, 'aggregate_record_bytes':2*1024*1024}
NOTICE = 'علاقات وبيانات يصرح بها المالك مع مصادرها وبصماتها وثقتها ووقت ملاحظتها وصلاحيتها وتعارضها؛ ليست تأكيدًا آليًا لصحة الادعاء. الوصول خاص بحساب المالك ومشروعه؛ لا اتصال خارجي أو إرسال للذكاء الاصطناعي.'
COMMON = {'description','source_evidence','confidence','observed_at','valid_from','valid_until'}
ENTITY_FIELDS = COMMON | {'type','label','reference_evidence'}
RELATION_FIELDS = COMMON | {'source','target','type','conflicts_with'}
_TIME = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})')
_ID = re.compile(r'[a-f0-9]{32}')


def _bad(message='بيانات خريطة المعرفة أو إثباتها غير صالحة', status=400):
    raise Problem(message, status)


def describe():
    return {'schema':SCHEMA,'entity_types':list(ENTITY_TYPES),'relation_types':list(RELATION_TYPES),
            'limits':dict(LIMITS),'notice':NOTICE}


def _time(value, nullable=False):
    if value is None and nullable:return None
    if not isinstance(value,str) or not _TIME.fullmatch(value) or value.endswith('-00:00'):
        _bad('التوقيت يحتاج RFC3339 بإزاحة معلومة وبدقة حتى6منازل')
    if value[-1]!='Z' and (int(value[-5:-3])>23 or int(value[-2:])>59):_bad('إزاحة التوقيت غير صالحة')
    try:
        actual = datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
        if actual.utcoffset() is None:raise ValueError('offset')
        return actual
    except (ValueError,OverflowError):_bad('توقيت غير صالح')


def _text(value, limit, required=False):
    if not isinstance(value,str) or len(value)>limit or (required and not value.strip()) or any(ord(char)<32 and char not in '\n\t' for char in value):
        _bad('نص خريطة المعرفة غير صالح أو يتجاوز الحد')
    try:value.encode('utf-8')
    except UnicodeError:_bad('النص يحتاج Unicode صالحًا')
    return value


def _id(value):
    if not isinstance(value,str) or not _ID.fullmatch(value):_bad('معرف خريطة المعرفة غير صالح')
    return value


def _payload(value,kind):
    fields = ENTITY_FIELDS if kind=='entity' else RELATION_FIELDS
    if not isinstance(value,dict) or set(value)!=fields:_bad('حقول خريطة المعرفة غير مطابقة')
    _text(value['description'],2000)
    _id(value['source_evidence'])
    if type(value['confidence'])is not int or not 0<=value['confidence']<=100:_bad('الثقة عدد صحيح بين0و100')
    _time(value['observed_at'])
    start,end = _time(value['valid_from'],True),_time(value['valid_until'],True)
    if start and end and start>end:_bad('بداية الصلاحية بعد نهايتها')
    if kind=='entity':
        if not isinstance(value['type'],str) or value['type'] not in ENTITY_TYPES:_bad('نوع الكيان غير مدعوم')
        _text(value['label'],200,True)
        if value['reference_evidence'] is not None:_id(value['reference_evidence'])
        if value['type'] in ('evidence','experiment') and value['reference_evidence'] is None:_bad('الدليل والتجربة يحتاجان مرجع ملف فعلي محفوظ')
    else:
        if not isinstance(value['type'],str) or value['type'] not in RELATION_TYPES:_bad('نوع العلاقة غير مدعوم')
        _id(value['source']);_id(value['target'])
        if value['source']==value['target']:_bad('طرفا العلاقة يجب أن يكونا مختلفين')
        if value['conflicts_with'] is not None:_id(value['conflicts_with'])
    return dict(value)


def _validity(value,at):
    start,end=_time(value['valid_from'],True),_time(value['valid_until'],True)
    if start is None and end is None:return 'unbounded'
    if start and at<start:return 'future'
    if end and at>end:return 'expired'
    return 'active'


def _source(store,pid,eid,cache,reference=False):
    record=store.evidence(pid,eid)
    if not reference and record['kind']!='original':_bad('مصدر الادعاء يجب أن يكون ملفًا أصليًا في المشروع')
    if record['size']>LIMITS['reference_bytes' if reference else 'source_bytes']:_bad('مصدر الادعاء أو مرجعه يتجاوز حد الحجم',413)
    if eid in cache:
        if record!=cache[eid]:_bad('تغير وصف مصدر الخريطة أثناء المراجعة',409)
        return cache[eid]
    total=sum(item['size'] for item in cache.values())+record['size']
    if total>LIMITS['aggregate_source_bytes']:_bad('مجموع مصادر الخريطة يتجاوز8ميبيبايت',413)
    store.read_evidence(pid,eid)
    cache[eid]=record
    return record


def _recheck(store,pid,cache):
    for eid,record in cache.items():
        if store.evidence(pid,eid)!=record or hashlib.sha256(store.read_evidence(pid,eid)).hexdigest()!=record['sha256']:
            _bad('تغير أصل الخريطة أو مرجعها أثناء العملية',409)


def _load(store,pid):
    """Verify full enrolled membership and every immutable record/source before use."""
    _id(pid);store.project(pid);_guard(store)
    rows=store.rows("SELECT * FROM evidence WHERE project_id=? AND kind IN ('graph-entity','graph-relation') ORDER BY created,id LIMIT ?",(pid,LIMITS['entities']+LIMITS['relations']+1))
    if len(rows)>LIMITS['entities']+LIMITS['relations'] or sum(item['size'] for item in rows)>LIMITS['aggregate_record_bytes']:_bad('تجاوز ميزانية مراجعة الخريطة',409)
    enrollments=store.rows("SELECT seq,action,details FROM audit WHERE action IN ('graph-entity.created','graph-relation.created') AND details LIKE ? LIMIT ?",('%"project":"'+pid+'"%',LIMITS['entities']+LIMITS['relations']+1))
    if len(enrollments)!=len(rows):_bad('عضوية الخريطة لا تطابق سجلات الإنشاء',409)
    proofs={}
    try:
        for item in enrollments:
            proof=json.loads(item['details'])
            if not isinstance(proof,dict) or set(proof)!={'project','id','sha256'} or proof['project']!=pid or proof['id'] in proofs:_bad(status=409)
            proofs[proof['id']]=(item['action'],proof['sha256'],item['seq'])
    except (ValueError,TypeError,KeyError):_bad(status=409)
    if set(proofs)!={row['id'] for row in rows}:_bad('سجل خريطة محذوف أو غير مسجل',409)
    entities={};relations={};cache={}
    fields={'schema','kind','data','source_sha256','reference_sha256','created'}
    for row in rows:
        if row['size']>LIMITS['record_bytes'] or proofs[row['id']][:2]!=(row['kind']+'.created',row['sha256']):_bad('إثبات سجل الخريطة غير مطابق',409)
        try:
            raw=store.read_evidence(pid,row['id'])
            if hashlib.sha256(raw).hexdigest()!=row['sha256']:_bad('تغير سجل الخريطة أثناء المراجعة',409)
            value=json.loads(raw)
            kind='entity' if row['kind']=='graph-entity' else 'relation'
            if not isinstance(value,dict) or set(value)!=fields or value['schema']!=SCHEMA or value['kind']!=kind or type(value['created'])not in (int,float) or not math.isfinite(value['created']) or value['created']<=0 or value['created']!=row['created']:_bad(status=409)
            data=_payload(value['data'],kind)
            source=_source(store,pid,data['source_evidence'],cache)
            if row['parent_id']!=source['id'] or value['source_sha256']!=source['sha256']:_bad('مصدر الادعاء أو بصمته غير مطابق',409)
            reference=_source(store,pid,data['reference_evidence'],cache,True) if kind=='entity' and data['reference_evidence'] else None
            if value['reference_sha256']!=(reference['sha256'] if reference else None):_bad('بصمة مرجع الدليل أو التجربة غير مطابقة',409)
            result={'id':row['id'],**data,'source_sha256':value['source_sha256'],'created':value['created']}
            if kind=='entity':result['reference_sha256']=value['reference_sha256']
            (entities if kind=='entity' else relations)[row['id']]=result
        except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):_bad(status=409)
    if len(entities)>LIMITS['entities'] or len(relations)>LIMITS['relations']:_bad('تجاوز عدد كيانات الخريطة أو علاقاتها',409)
    for relation in relations.values():
        if relation['source'] not in entities or relation['target'] not in entities:_bad('طرف علاقة مفقود أو خارج المشروع',409)
        conflict=relation['conflicts_with']
        if conflict is not None:
            if conflict not in relations or conflict==relation['id']:_bad('مرجع تعارض مفقود',409)
            if proofs[conflict][2] >= proofs[relation['id']][2]:_bad('مرجع التعارض يجب أن يسبق الادعاء',409)
    return entities,relations,cache


def _conflicts(relations):
    result=[];seen=set()
    for relation in relations.values():
        if relation['conflicts_with']:
            pair=tuple(sorted((relation['id'],relation['conflicts_with'])))
            result.append({'relations':list(pair),'kind':'explicit'});seen.add(pair)
    items=list(relations.values())
    for i,left in enumerate(items):
        for right in items[i+1:]:
            pair=tuple(sorted((left['id'],right['id'])))
            if pair not in seen and left['source']==right['source'] and left['target']==right['target'] and {left['type'],right['type']}=={'supports','contradicts'}:
                result.append({'relations':list(pair),'kind':'opposed_assertions'});seen.add(pair)
    return result


def status(store,pid,at=None):
    actual=_time(at) if at is not None else datetime.datetime.now(datetime.timezone.utc)
    try:
        with store.lock,_directories(store) as (_,validate):
            entities,relations,cache=_load(store,pid)
            _recheck(store,pid,cache)
            validate()
            return {**describe(),'at':actual.isoformat(),
                    'entities':[{**item,'validity':_validity(item,actual)} for item in entities.values()],
                    'relations':[{**item,'validity':_validity(item,actual)} for item in relations.values()],
                    'conflicts':_conflicts(relations)}
    except OSError:_bad('تغير التخزين أو أصبح غير آمن',409)


def _create(store,pid,payload,kind):
    data=_payload(payload,kind)
    eid=uid();artifactkind='graph-'+kind;created=False
    with store.lock,_directories(store) as (blobs_fd,validate):
        try:
            # One write reservation serializes validation and insertion across Store connections.
            store.db.execute('BEGIN IMMEDIATE')
            entities,relations,cache=_load(store,pid)
            existing=entities if kind=='entity' else relations
            if len(existing)>=LIMITS['entities' if kind=='entity' else 'relations']:_bad('بلغت الخريطة الحد الأقصى',409)
            source=_source(store,pid,data['source_evidence'],cache)
            if kind=='relation':
                if data['source'] not in entities or data['target'] not in entities:_bad('اختر كيانين من المشروع الحالي',404)
                if data['conflicts_with'] is not None and data['conflicts_with'] not in relations:_bad('علاقة التعارض غير موجودة في المشروع',404)
            reference=_source(store,pid,data['reference_evidence'],cache,True) if kind=='entity' and data['reference_evidence'] else None
            value={'schema':SCHEMA,'kind':kind,'data':data,'source_sha256':source['sha256'],
                   'reference_sha256':reference['sha256'] if reference else None,'created':time.time()}
            raw=encode(value).encode()
            if len(raw)>LIMITS['record_bytes']:_bad('حجم سجل الخريطة يتجاوز الحد',413)
            existingbytes=store.db.execute("SELECT coalesce(sum(size),0) FROM evidence WHERE project_id=? AND kind IN ('graph-entity','graph-relation')",(pid,)).fetchone()[0]
            if existingbytes+len(raw)>LIMITS['aggregate_record_bytes']:_bad('تجاوز حجم سجلات الخريطة',413)
            resources=store.resources()
            if resources['evidence_bytes']+len(raw)>store.quota or resources['filesystem_free']<len(raw)+256*1024*1024:_bad('المساحة أو حصة الأدلة لا تكفي',409)
            fd=os.open(eid,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=blobs_fd);created=True
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            digest=hashlib.sha256(raw).hexdigest()
            store.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)',(eid,pid,artifactkind+'.json',digest,len(raw),artifactkind,source['id'],value['created']))
            # Keep the pre-existing evidence graph linked to the original assertion source.
            store.db.execute('INSERT INTO relations VALUES(?,?,?,?,?)',(uid(),pid,source['id'],eid,artifactkind))
            store.audit(artifactkind+'.created',{'project':pid,'id':eid,'sha256':digest})
            _,_,freshcache=_load(store,pid)
            _recheck(store,pid,freshcache)
            _guard(store);validate();store.db.commit()
        except BaseException:
            store.db.rollback()
            if created:os.unlink(eid,dir_fd=blobs_fd)
            raise
    record=store.evidence(pid,eid)
    item={'id':eid,**data,'source_sha256':value['source_sha256'],'created':value['created'],
          'validity':_validity(data,datetime.datetime.now(datetime.timezone.utc))}
    if kind=='entity':item['reference_sha256']=value['reference_sha256']
    return {'evidence':record,kind:item,'notice':NOTICE}


def create_entity(store,pid,payload):
    try:return _create(store,pid,payload,'entity')
    except OSError:_bad('تغير التخزين أو أصبح غير آمن',409)


def create_relation(store,pid,payload):
    try:return _create(store,pid,payload,'relation')
    except OSError:_bad('تغير التخزين أو أصبح غير آمن',409)
