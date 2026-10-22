"""Bounded static review of rendered Kubernetes JSON; never contacts a cluster."""
from collections import Counter
import hashlib
import re
from .event_adapters import strict_json
from .store import encode

LIMITS = {'input_bytes':4194304, 'resources':200, 'containers':1000,
          'findings':1000, 'json_depth':32, 'json_nodes':100000}
LIMITATIONS = ('مراجعة ثابتة للحقول الموثقة في JSON فقط؛ ليست تحقق Kubernetes كاملًا أو CIS أو إثبات عزل حي. '
               'لا تطبيق أو اتصال؛ الموارد not_reviewed والحقول غير المفحوصة لا تحصل على حكم سلامة. '
               'قيم البيئة والأوامر والأسرار لا تصدر، وبصمة الإعداد تخص الحقول المفحوصة فقط.')
_PODS = {('v1','Pod'):(), ('apps/v1','Deployment'):('template','spec'),
         ('apps/v1','DaemonSet'):('template','spec'), ('apps/v1','StatefulSet'):('template','spec'),
         ('batch/v1','Job'):('template','spec'), ('batch/v1','CronJob'):('jobTemplate','spec','template','spec')}
_RBAC = {'Role','ClusterRole','RoleBinding','ClusterRoleBinding'}


def _bad(message='Invalid Kubernetes review input'):
    raise ValueError(message)


def _json(data):
    if not isinstance(data,bytes) or len(data)>LIMITS['input_bytes']:
        _bad('Kubernetes input exceeds 4 MiB')
    try: value=strict_json(data.decode('utf-8'))
    except (ValueError,UnicodeError,RecursionError): _bad('Invalid Kubernetes JSON')
    stack=[(value,0)]; count=0
    while stack:
        item,depth=stack.pop();count+=1
        if depth>LIMITS['json_depth'] or count>LIMITS['json_nodes']: _bad('Kubernetes JSON structure exceeds limits')
        if isinstance(item,dict): stack.extend((v,depth+1) for v in item.values())
        elif isinstance(item,list): stack.extend((v,depth+1) for v in item)
        elif isinstance(item,int) and not isinstance(item,bool) and abs(item)>2**63: _bad()
    if not isinstance(value,dict): _bad()
    return value


def _obj(value):
    if not isinstance(value,dict): _bad()
    return value


def _name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}',value): _bad('Invalid Kubernetes object name')
    return value


def _bools(value, fields):
    for key in fields:
        if key in value and type(value[key]) is not bool: _bad('Invalid Kubernetes boolean')


def _context(value):
    value=_obj(value)
    _bools(value, ('privileged','allowPrivilegeEscalation','runAsNonRoot','readOnlyRootFilesystem'))
    for key in ('runAsUser','runAsGroup','fsGroup'):
        if key in value and (type(value[key]) is not int or not 0<=value[key]<=2**32-1): _bad('Invalid Kubernetes identity')
    result={k:value[k] for k in ('privileged','allowPrivilegeEscalation','runAsNonRoot','readOnlyRootFilesystem','runAsUser','runAsGroup','fsGroup') if k in value}
    if 'seccompProfile' in value:
        profile=_obj(value['seccompProfile']);kind=profile.get('type')
        if kind not in ('RuntimeDefault','Localhost','Unconfined'): _bad('Invalid seccomp profile')
        if kind=='Localhost' and (not isinstance(profile.get('localhostProfile'),str) or not profile['localhostProfile'] or len(profile['localhostProfile'])>1024): _bad('Invalid seccomp profile')
        result['seccompProfile']={'type':kind}
        if kind=='Localhost': result['seccompProfile']['profile_sha256']=hashlib.sha256(profile['localhostProfile'].encode()).hexdigest()
    if 'capabilities' in value:
        capabilities=_obj(value['capabilities']);result['capabilities']={}
        for key in ('add','drop'):
            values=capabilities.get(key,[])
            if not isinstance(values,list) or len(values)>64 or any(not isinstance(v,str) or not re.fullmatch('[A-Z][A-Z0-9_]{0,63}',v) for v in values): _bad('Invalid capability list')
            if len(set(values))!=len(values): _bad('Duplicate capability')
            result['capabilities'][key]=sorted(values)
    return result


def _quantity(value, resource):
    if not isinstance(value,str) or len(value)>40: _bad('Invalid resource quantity')
    pattern=r'(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:m)?' if resource=='cpu' else r'(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[EPTGMK]i?|[eE][+-]?[0-9]+)?'
    if not re.fullmatch(pattern,value): _bad('Invalid resource quantity')
    return value


def analyze(data):
    value=_json(data)
    if value.get('kind')=='List':
        if value.get('apiVersion')!='v1' or not isinstance(value.get('items'),list): _bad('Invalid Kubernetes List')
        items=value['items']
    else: items=[value]
    if len(items)>LIMITS['resources']: _bad('Too many Kubernetes resources')
    resources=[];findings=[];seen=set();container_count=0

    def finding(identifier,container,code,field,severity='medium',gap=False):
        if len(findings)>=LIMITS['findings']: _bad('Too many Kubernetes findings')
        findings.append({'resource_id':identifier,'container':container,'code':code,'field':field,
                         'severity':severity,'baseline_gap':gap,'message':'Static baseline observation: '+code})

    for item in items:
        item=_obj(item);api=item.get('apiVersion');kind=item.get('kind')
        if not isinstance(api,str) or not re.fullmatch(r'[A-Za-z0-9./-]{1,100}',api) or not isinstance(kind,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,79}',kind): _bad('Invalid Kubernetes API kind')
        metadata=_obj(item.get('metadata'));name=_name(metadata.get('name'))
        namespace=None if kind in ('ClusterRole','ClusterRoleBinding','Namespace') else _name(metadata.get('namespace','default'))
        identifier='/'.join((api,kind,namespace or '-',name))
        if identifier in seen: _bad('Duplicate Kubernetes resource')
        seen.add(identifier)
        row={'id':identifier,'api_version':api,'kind':kind,'namespace':namespace,'name':name,'container_count':0,'review_status':'reviewed'}
        config={}
        known=(api,kind) in _PODS or (api=='v1' and kind=='Service') or (api=='rbac.authorization.k8s.io/v1' and kind in _RBAC)
        if not known:
            if kind in {k for _,k in _PODS}|_RBAC|{'Service'}: _bad('Unsupported API version for known Kubernetes kind')
            row['review_status']='not_reviewed';row['configuration_sha256']=None;resources.append(row);continue
        if (api,kind) in _PODS:
            pod=_obj(item.get('spec'));prefix='spec'
            for part in _PODS[(api,kind)]: pod=_obj(pod.get(part));prefix+='.'+part
            context=_context(pod.get('securityContext',{}))
            if set(context)&{'privileged','allowPrivilegeEscalation','readOnlyRootFilesystem','capabilities'}: _bad('Container-only security context field at Pod level')
            config['pod_context']=context
            _bools(pod,('hostNetwork','hostPID','hostIPC','automountServiceAccountToken'))
            config['pod_flags']={k:pod[k] for k in ('hostNetwork','hostPID','hostIPC','automountServiceAccountToken') if k in pod}
            for key in ('hostNetwork','hostPID','hostIPC'):
                if pod.get(key,False):finding(identifier,None,key,prefix+'.'+key,'high')
            if pod.get('automountServiceAccountToken',True):finding(identifier,None,'service_account_token_mount',prefix+'.automountServiceAccountToken',gap='automountServiceAccountToken' not in pod)
            volumes=pod.get('volumes',[])
            if not isinstance(volumes,list) or len(volumes)>1000: _bad('Invalid volume list')
            config['volumes']=[]
            for index,volume in enumerate(volumes):
                volume=_obj(volume);_name(volume.get('name'))
                if 'hostPath' in volume:
                    host=_obj(volume['hostPath']);path=host.get('path')
                    if not isinstance(path,str) or not path or len(path)>4096: _bad('Invalid hostPath')
                    config['volumes'].append({'name':volume['name'],'host_path_sha256':hashlib.sha256(path.encode()).hexdigest()})
                    finding(identifier,None,'host_path_volume',f'{prefix}.volumes[{index}].hostPath','high')
            containers=pod.get('containers')
            if not isinstance(containers,list) or not containers: _bad('A Pod requires containers')
            config['containers']=[];container_names=set()
            for group in ('containers','initContainers','ephemeralContainers'):
                values=pod.get(group,[])
                if not isinstance(values,list): _bad('Invalid container list')
                for index,container in enumerate(values):
                    container_count+=1;row['container_count']+=1
                    if container_count>LIMITS['containers']: _bad('Too many Kubernetes containers')
                    container=_obj(container);cname=_name(container.get('name'))
                    if cname in container_names:_bad('Duplicate container name')
                    container_names.add(cname);base=f'{prefix}.{group}[{index}]'
                    own=_context(container.get('securityContext',{}))
                    if 'fsGroup' in own: _bad('Pod-only identity field at container level')
                    effective={**context,**own}
                    image=container.get('image')
                    if not isinstance(image,str) or not image or len(image)>2048 or any(ord(c)<33 for c in image):_bad('Invalid container image')
                    safe={'group':group,'name':cname,'context':effective,'image_sha256':hashlib.sha256(image.encode()).hexdigest()}
                    if effective.get('privileged',False):finding(identifier,cname,'privileged_container',base+'.securityContext.privileged','high')
                    for key,desired,code in [('allowPrivilegeEscalation',False,'privilege_escalation'),('runAsNonRoot',True,'non_root_not_required'),('readOnlyRootFilesystem',True,'writable_root_filesystem')]:
                        if effective.get(key)!=desired:
                            where=base+'.securityContext.'+key if key in own or key not in context else prefix+'.securityContext.'+key
                            finding(identifier,cname,code,where,gap=key not in effective)
                    if effective.get('runAsUser')==0:finding(identifier,cname,'root_uid',base+'.securityContext.runAsUser' if 'runAsUser' in own else prefix+'.securityContext.runAsUser','high')
                    capabilities=effective.get('capabilities',{})
                    if 'ALL' not in capabilities.get('drop',[]):finding(identifier,cname,'capabilities_not_dropped',base+'.securityContext.capabilities.drop',gap=not capabilities)
                    if capabilities.get('add'):finding(identifier,cname,'added_capabilities',base+'.securityContext.capabilities.add','high')
                    if effective.get('seccompProfile',{}).get('type') not in ('RuntimeDefault','Localhost'):
                        finding(identifier,cname,'seccomp_not_confined',base+'.securityContext.seccompProfile' if 'seccompProfile' in own else prefix+'.securityContext.seccompProfile',gap='seccompProfile' not in effective)
                    if not re.search(r'@sha256:[a-fA-F0-9]{64}$',image):finding(identifier,cname,'image_not_digest_pinned',base+'.image')
                    limits=_obj(_obj(container.get('resources',{})).get('limits',{}));safe['resource_limits']={}
                    for resource in ('cpu','memory'):
                        if resource not in limits:finding(identifier,cname,'missing_'+resource+'_limit',base+'.resources.limits.'+resource,gap=True)
                        else:
                            safe['resource_limits'][resource]=_quantity(limits[resource],resource)
                            if float(re.match(r'[0-9]+(?:\.[0-9]+)?',limits[resource])[0])==0:
                                finding(identifier,cname,'zero_'+resource+'_limit',base+'.resources.limits.'+resource)
                    config['containers'].append(safe)
        elif kind=='Service':
            spec=_obj(item.get('spec'));stype=spec.get('type','ClusterIP')
            if stype not in ('ClusterIP','NodePort','LoadBalancer','ExternalName'): _bad('Invalid Service type')
            config['type']=stype
            if stype in ('NodePort','LoadBalancer'):finding(identifier,None,'exposed_service','spec.type')
        elif kind in ('Role','ClusterRole'):
            rules=item.get('rules',[])
            if not isinstance(rules,list) or len(rules)>1000:_bad('Invalid RBAC rules')
            config['rules']=[]
            for index,rule in enumerate(rules):
                rule=_obj(rule);safe={}
                for key in ('verbs','apiGroups','resources','resourceNames','nonResourceURLs'):
                    entries=rule.get(key,[])
                    if not isinstance(entries,list) or len(entries)>1000 or any(not isinstance(v,str) or len(v)>1024 for v in entries): _bad('Invalid RBAC rule')
                    safe[key]=sorted(entries)
                    if '*' in entries:finding(identifier,None,'wildcard_rbac',f'rules[{index}].'+key,'high')
                if not safe['verbs']: _bad('RBAC rule requires verbs')
                config['rules'].append(safe)
        else:
            role=_obj(item.get('roleRef'))
            if role.get('apiGroup')!='rbac.authorization.k8s.io' or role.get('kind') not in ('Role','ClusterRole') or kind=='ClusterRoleBinding' and role['kind']!='ClusterRole': _bad('Invalid RBAC role reference')
            config['role_ref']={'kind':role['kind'],'name':_name(role.get('name'))}
            subjects=item.get('subjects',[])
            if not isinstance(subjects,list) or len(subjects)>1000: _bad('Invalid RBAC subjects')
            config['subjects']=[]
            for index,subject in enumerate(subjects):
                subject=_obj(subject);skind=subject.get('kind')
                if skind not in ('User','Group','ServiceAccount'): _bad('Invalid RBAC subject')
                if subject.get('apiGroup','' if skind=='ServiceAccount' else 'rbac.authorization.k8s.io')!=('' if skind=='ServiceAccount' else 'rbac.authorization.k8s.io'): _bad('Invalid RBAC subject API group')
                sname=subject.get('name')
                if skind=='ServiceAccount':sname=_name(sname)
                elif not isinstance(sname,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,252}',sname): _bad('Invalid RBAC subject name')
                safe={'kind':skind,'name':sname}
                if skind=='ServiceAccount':safe['namespace']=_name(subject.get('namespace') or namespace)
                elif subject.get('namespace') is not None:_bad('Unexpected namespace on RBAC subject')
                config['subjects'].append(safe)
                if skind=='Group' and sname in ('system:unauthenticated','system:authenticated'):finding(identifier,None,'broad_subject_binding',f'subjects[{index}]','high')
        row['configuration_sha256']=hashlib.sha256(encode(config).encode()).hexdigest();resources.append(row)
    summary={'findings':len(findings),'baseline_gaps':sum(f['baseline_gap'] for f in findings),
             'not_reviewed_resources':sum(r['review_status']=='not_reviewed' for r in resources)}
    summary.update({severity:sum(f['severity']==severity for f in findings) for severity in ('high','medium','low')})
    return {'schema':'was.kubernetes-review/1','resource_count':len(resources),'container_count':container_count,
            'resources':resources,'findings':findings,'summary':summary,'complete':True,'network':False,'applied':False,
            'source_sha256':hashlib.sha256(data).hexdigest(),'limits':dict(LIMITS),'limitations':LIMITATIONS}


def analyze_diff(data):
    value=_json(data)
    if set(value)!={'left','right'} or any(not isinstance(value[k],dict) for k in value):_bad('Kubernetes comparison requires exactly left and right objects')
    before,after=[analyze(encode(value[k]).encode()) for k in ('left','right')]
    a,b=[{r['id']:r for r in report['resources']} for report in (before,after)]
    added=sorted(b.keys()-a.keys());removed=sorted(a.keys()-b.keys())
    changed=[{'id':rid,'fields':[k for k in a[rid] if a[rid][k]!=b[rid][k]]} for rid in sorted(a.keys()&b.keys()) if a[rid]!=b[rid]]
    old,new=[Counter(encode(f) for f in report['findings']) for report in (before,after)]
    added_findings=[strict_json(key) for key,n in sorted((new-old).items()) for _ in range(n)]
    removed_findings=[strict_json(key) for key,n in sorted((old-new).items()) for _ in range(n)]
    return {'schema':'was.kubernetes-diff/1','complete':True,'added_resources':added,'removed_resources':removed,
            'changed_resources':changed,'added_findings':added_findings,'removed_findings':removed_findings,
            'normalized_review_equal':not(added or removed or changed or added_findings or removed_findings),
            'unreviewed_resources_present':any(r['review_status']=='not_reviewed' for report in (before,after) for r in report['resources']),
            'left_summary':before['summary'],'right_summary':after['summary'],'left_sha256':before['source_sha256'],
            'right_sha256':after['source_sha256'],'source_bundle_sha256':hashlib.sha256(data).hexdigest(),
            'embedded_document_encoding':'canonical_json','network':False,'applied':False,
            'notice':'مقارنة كاملة للحقول المفحوصة والملاحظات فقط؛ ليست مساواة كل حقول المصدر أو الأسرار أو الأوامر أو خصائص Service غير المفحوصة. موارد not_reviewed تبقى خارج التقييم.'}


def sample():
    return {'apiVersion':'v1','kind':'List','items':[
        {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'synthetic-web','namespace':'demo'},
         'spec':{'selector':{'matchLabels':{'app':'web'}},'template':{'metadata':{'labels':{'app':'web'}},'spec':{
             'hostNetwork':True,'containers':[{'name':'web','image':'example.test/web:latest','securityContext':{'privileged':True}}]}}}},
        {'apiVersion':'v1','kind':'Service','metadata':{'name':'synthetic-service','namespace':'demo'},
         'spec':{'type':'LoadBalancer','selector':{'app':'web'},'ports':[{'port':443,'targetPort':8443}]}}]}


def diff_sample():
    left,right=sample(),sample()
    right['items'][0]['spec']['template']['spec']['containers'][0]['securityContext']['privileged']=False
    return {'left':left,'right':right}
