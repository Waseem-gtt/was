"""Versioned was.event/1 dictionary and strict normalized-output verification.

No schema URL is fetched. Validation runs as part of the trusted bounded adapter.
"""
import copy
import hashlib
import ipaddress
import json
import re
from datetime import datetime

ID = 'was.event/1'
VERSION = '1.0.0'
BASE = {'time','actor','action','outcome','original'}
ADAPTERS = {
    'windows-json': {'required': BASE|{'event_id'}, 'allowed': BASE|{'event_id','host'}},
    'windows-xml': {'required': BASE|{'event_id'}, 'allowed': BASE|{'event_id','host'}},
    'syslog-rfc5424': {'required': BASE|{'host','application','process_id','message_id','facility','severity','structured_data','message'},
                        'allowed': BASE|{'host','application','process_id','message_id','facility','severity','structured_data','message'}},
    'flows-csv': {'required': BASE|{'source','destination','protocol','bytes'},
                  'allowed': BASE|{'source','destination','protocol','bytes'}},
}
FIELDS = [
    {'name':'time','type':'string','required':True,'description':'التوقيت الأصلي RFC3339 مع الإزاحة وبدقة تصل7منازل؛ unknown عند عدم توفره.'},
    {'name':'actor','type':'string','required':True,'description':'الفاعل المعلن في المصدر أو unknown؛ لا استنتاج هوية.'},
    {'name':'action','type':'string','required':True,'description':'الفعل المعلن أو unknown؛ لا تحويل ضمني لرقم الحدث إلى هجوم.'},
    {'name':'outcome','type':'enum','required':True,'description':'success أو failure أو unknown بحسب تصريح المصدر فقط.'},
    {'name':'original','type':'object|string','required':True,'description':'تمثيل السجل المدعوم قبل التطبيع؛ بايتات الملف الكامل محفوظة منفصلة وبصمتها في النتيجة.'},
    {'name':'event_id','type':'integer','required':False,'description':'رقم حدثWindowsبين0و65535.'},
    {'name':'host','type':'string','required':False,'description':'المضيف المعلن؛ unknown عند NILVALUE فيsyslog.'},
    {'name':'source','type':'ip-address','required':False,'description':'عنوان مصدر التدفق، بصيغةIPموحدة.'},
    {'name':'destination','type':'ip-address','required':False,'description':'عنوان وجهة التدفق، بصيغةIPموحدة.'},
    {'name':'protocol','type':'string','required':False,'description':'اسم بروتوكول التدفق المعلن.'},
    {'name':'bytes','type':'integer','required':False,'description':'حجم التدفق المعلن: عدد صحيح غير سالب64بت.'},
    {'name':'application','type':'string','required':False,'description':'اسم التطبيق المعلن فيsyslog.'},
    {'name':'process_id','type':'string','required':False,'description':'معرف العملية النصي المعلن فيsyslog.'},
    {'name':'message_id','type':'string','required':False,'description':'معرف رسالةsyslog.'},
    {'name':'facility','type':'integer','required':False,'description':'فئةsyslogبين0و23، مشتقة منPRIالمعلن.'},
    {'name':'severity','type':'integer','required':False,'description':'شدةsyslogبين0و7؛ ليست تقييم خطر مستقلًا.'},
    {'name':'structured_data','type':'string','required':False,'description':'مقطع البيانات المنظمة كما ورد فيسطرsyslog.'},
    {'name':'message','type':'string','required':False,'description':'نص رسالةsyslogكما ورد؛ قد يتضمن بيانات حساسة.'},
]
QUALITY_FLAGS = [
    {'code':'unknown_time','description':'المصدر لا يحدد توقيتًا صالحًا معروفًا.'},
    {'code':'unknown_actor','description':'لم يحدد المصدر الفاعل.'},
    {'code':'unknown_action','description':'لم يحدد المصدر الفعل؛ لا يُستنتج تلقائيًا.'},
    {'code':'unknown_outcome','description':'لم يحدد المصدر نجاح العملية أو فشلها.'},
    {'code':'offset_unspecified','description':'الإزاحة-00:00تعني أن إزاحة المصدر غير معلومة؛ لم تحول إلىUTCمؤكد.'},
]
NOTICE = 'لغة أحداث أمنية محلية بإصدار وقاموس وجودة قابلة للتحقق. لا تعني توافقOCSFكاملًا أو جمعًا حيًا أو صحة ادعاءات المصدر، ولا تُفرض على بيانات الرادار والفيزياء.'


def _canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _dictionary():
    return {'id':ID,'version':VERSION,'fields':FIELDS,
            'adapters':[{'id':name,'required_fields':sorted(value['required']),'allowed_fields':sorted(value['allowed'])} for name,value in ADAPTERS.items()],
            'quality_flags':QUALITY_FLAGS,'limits':{'input_bytes':1048576,'records':1000,'record_bytes':8192},
            'json_schema':_json_schema(),'supported_versions':[VERSION]}


def digest():
    return hashlib.sha256(_canonical(_dictionary())).hexdigest()


def _event_schema(adapter):
    props = {item['name']:{'type':'string','maxLength':8192} for item in FIELDS}
    props.update(original={'type':['object','string']},event_id={'type':'integer','minimum':0,'maximum':65535},
                 bytes={'type':'integer','minimum':0,'maximum':2**64-1},
                 facility={'type':'integer','minimum':0,'maximum':23},severity={'type':'integer','minimum':0,'maximum':7},
                 outcome={'enum':['success','failure','unknown']},
                 time={'type':'string','pattern':r'^(unknown|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?(Z|[+-][0-9]{2}:[0-9]{2}))$'})
    allowed=ADAPTERS[adapter]
    return {'type':'object','required':sorted(allowed['required']),'additionalProperties':False,
            'properties':{key:props[key] for key in sorted(allowed['allowed'])}}


def _json_schema():
    bounded_int={'type':'integer','minimum':0,'maximum':1000}
    index={'type':'integer','minimum':0,'maximum':999}
    timestamp={'type':'object','additionalProperties':False,
               'required':['index','original','offset','offset_known','fraction_digits'],
               'properties':{'index':index,'original':{'type':'string','maxLength':80},
                             'offset':{'type':['string','null'],'maxLength':6},
                             'offset_known':{'type':'boolean'},
                             'fraction_digits':{'type':'integer','minimum':0,'maximum':7}}}
    flags={'type':'object','additionalProperties':False,'required':['index','codes'],
           'properties':{'index':index,'codes':{'type':'array','minItems':1,'maxItems':5,'uniqueItems':True,
                         'items':{'enum':[flag['code'] for flag in QUALITY_FLAGS]}}}}
    quality={'type':'object','additionalProperties':False,
             'required':['schema','records','records_with_gaps','unknown_counts','flags','timestamps','order_preserved','source_bytes_preserved'],
             'properties':{'schema':{'const':'was.event-quality/1'},'records':{'type':'integer','minimum':1,'maximum':1000},
                           'records_with_gaps':bounded_int,
                           'unknown_counts':{'type':'object','additionalProperties':False,
                            'required':['time','actor','action','outcome'],
                            'properties':{key:bounded_int for key in ('time','actor','action','outcome')}},
                           'flags':{'type':'array','maxItems':1000,'items':flags},
                           'timestamps':{'type':'array','minItems':1,'maxItems':1000,'items':timestamp},
                           'order_preserved':{'const':True},'source_bytes_preserved':{'const':True}}}
    required=['schema','adapter','events','count','failed','limitations','input_sha256','schema_version','dictionary_sha256','quality']
    branches=[]
    for adapter in ADAPTERS:
        branches.append({'type':'object','additionalProperties':False,'required':required,
            'properties':{'schema':{'const':ID},'schema_version':{'const':VERSION},'adapter':{'const':adapter},
                          'events':{'type':'array','minItems':1,'maxItems':1000,'items':{'$ref':'#/$defs/'+adapter}},
                          'count':{'type':'integer','minimum':1,'maximum':1000},'failed':bounded_int,
                          'limitations':{'type':'string','minLength':1,'maxLength':8192},
                          'input_sha256':{'type':'string','pattern':'^[a-f0-9]{64}$'},
                          'dictionary_sha256':{'type':'string','pattern':'^[a-f0-9]{64}$'},'quality':quality}})
    return {'$schema':'https://json-schema.org/draft/2020-12/schema',
            '$id':'urn:was:event-contract:1.0.0','title':'was.event/1 registered adapter output',
            'description':'Complete adapter envelopes; semantic timing, byte limits, counts and quality relationships are additionally checked by the Python validator.',
            'oneOf':branches,'$defs':{name:_event_schema(name) for name in ADAPTERS}}


def describe():
    dictionary=copy.deepcopy(_dictionary())
    dictionary.update(dictionary_sha256=digest(),notice=NOTICE,digest_scope=sorted(_dictionary()))
    return dictionary


def _string(value, empty=False):
    if not isinstance(value,str) or not empty and not value or len(value.encode('utf-8'))>8192:
        raise ValueError('Invalid normalized event string')


def _timestamp(value,index):
    _string(value)
    if value=='unknown':return {'index':index,'original':value,'offset':None,'offset_known':False,'fraction_digits':0}
    match=re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.([0-9]{1,7}))?(Z|[+-][0-9]{2}:[0-9]{2})',value)
    if not match:raise ValueError('Invalid normalized event timestamp')
    offset=match[2]
    if offset!='Z' and (int(offset[1:3])>23 or int(offset[4:])>59):raise ValueError('Invalid normalized event offset')
    datetime.fromisoformat(value.replace('Z','+00:00'))
    return {'index':index,'original':value,'offset':offset,'offset_known':offset!='-00:00','fraction_digits':len(match[1] or '')}


def validate_and_quality(result):
    """Validate the complete registered-adapter batch and derive quality only."""
    if not isinstance(result,dict) or result.get('schema')!=ID or result.get('adapter') not in ADAPTERS:
        raise ValueError('Invalid normalized event envelope')
    fields={'schema','adapter','events','count','failed','limitations','input_sha256'}
    if set(result) != fields:raise ValueError('Unknown normalized event envelope field')
    events=result['events']; adapter=result['adapter']
    if not isinstance(events,list) or not 1<=len(events)<=1000 or type(result['count']) is not int or result['count']!=len(events):
        raise ValueError('Invalid normalized event count')
    if not isinstance(result['input_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',result['input_sha256']):
        raise ValueError('Invalid normalized source hash')
    _string(result['limitations'])
    unknown={key:0 for key in ('time','actor','action','outcome')}; flags=[]; timestamps=[]
    for index,event in enumerate(events):
        contract=ADAPTERS[adapter]
        if not isinstance(event,dict) or not contract['required']<=event.keys() or set(event)-contract['allowed']:
            raise ValueError('Unknown or missing normalized event field')
        if not isinstance(event['original'],str if adapter=='syslog-rfc5424' else dict):
            raise ValueError('Invalid normalized original representation')
        encoded_original=_canonical(event['original'])
        # JSON escaping adds a small overhead to raw syslog strings; the input
        # adapter already checked the original record's precise UTF-8 byte cap.
        if len(encoded_original)>6*8192+128:raise ValueError('Invalid normalized original size')
        timestamp=_timestamp(event['time'],index);timestamps.append(timestamp)
        for key in ('actor','action','outcome'):_string(event[key])
        if event['outcome'] not in ('unknown','success','failure'):raise ValueError('Invalid normalized outcome')
        codes=[]
        for key in unknown:
            if event[key]=='unknown':unknown[key]+=1;codes.append('unknown_'+key)
        if timestamp['offset']=='-00:00':codes.append('offset_unspecified')
        if codes:flags.append({'index':index,'codes':codes})
        for key,maximum in (('event_id',65535),('bytes',2**64-1),('facility',23),('severity',7)):
            if key in event and (type(event[key]) is not int or not 0<=event[key]<=maximum):raise ValueError('Invalid normalized numeric field')
        for key in set(event)-BASE-{'event_id','bytes','facility','severity'}:_string(event[key],empty=key=='message')
        if adapter=='flows-csv':
            for key in ('source','destination'):
                if str(ipaddress.ip_address(event[key]))!=event[key]:raise ValueError('Noncanonical normalized address')
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}',event['protocol']):raise ValueError('Invalid normalized protocol')
    if type(result['failed']) is not int or result['failed']!=sum(event['outcome']=='failure' for event in events):raise ValueError('Invalid normalized failure count')
    return {'schema':'was.event-quality/1','records':len(events),'records_with_gaps':len(flags),'unknown_counts':unknown,
            'flags':flags,'timestamps':timestamps,'order_preserved':True,'source_bytes_preserved':True}


def enrich(result):
    quality=validate_and_quality(result)
    return {**result,'schema_version':VERSION,'dictionary_sha256':digest(),'quality':quality}


def verify(result):
    if not isinstance(result,dict) or not {'schema_version','dictionary_sha256','quality'}<=result.keys():
        raise ValueError('Missing normalized event contract')
    if result['schema_version']!=VERSION or result['dictionary_sha256']!=digest():raise ValueError('Unknown event dictionary version')
    core={key:value for key,value in result.items() if key not in ('schema_version','dictionary_sha256','quality')}
    quality=validate_and_quality(core)
    if _canonical(result['quality'])!=_canonical(quality):raise ValueError('Event quality differs from complete batch')
    return True
