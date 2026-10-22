"""Static review of documented service-unit directives; no host service actions."""
import hashlib
import re

LIMITS={'input_bytes':4194304,'lines':10000,'line_bytes':8192,'continuations':8,'directives':2000}
LIMITATIONS=('مراجعة ثابتة لحقول تقوية خدمةsystemdالموثقة فقط، لا تحقق كامل لصيغة الوحدة أو حالة المضيف. '
             'لا تشغيل أو تطبيق أو استدعاءsystemctl؛ قيم الأوامر والبيئة والأسرار لا تُصدّر. '
             'الملاحظات خط أساس وليست شهادة أمان أو اختبار توافق تشغيل.')
_BOOL={'NoNewPrivileges','PrivateDevices','ProtectKernelTunables','ProtectKernelModules','ProtectKernelLogs',
       'ProtectControlGroups','RestrictSUIDSGID','MemoryDenyWriteExecute','LockPersonality','DynamicUser'}
_ENUM={'PrivateTmp':{'yes','no','disconnected'},'ProtectSystem':{'no','yes','full','strict'},
       'ProtectHome':{'no','yes','read-only','tmpfs'}}
_KNOWN=_BOOL|set(_ENUM)|{'User','CapabilityBoundingSet','AmbientCapabilities','RestrictNamespaces'}
_TRUE={'yes','true','on','1'};_FALSE={'no','false','off','0'}


def _bad(message='Invalid systemd unit input'):
    raise ValueError(message)


def _bool(value):
    value=value.lower()
    if value in _TRUE:return 'yes'
    if value in _FALSE:return 'no'
    _bad('Invalid systemd boolean value')


def analyze(data):
    if not isinstance(data,bytes) or len(data)>LIMITS['input_bytes']: _bad('Systemd input exceeds 4 MiB')
    try:text=data.decode('utf-8')
    except UnicodeError:_bad('Systemd input must be UTF-8')
    if any(ord(c)<32 and c not in '\n\r\t' or ord(c)==127 for c in text):_bad('Invalid control character in unit')
    lines=text.splitlines()
    if len(lines)>LIMITS['lines'] or any(len(line.encode())>LIMITS['line_bytes'] for line in lines):_bad('Systemd line limit exceeded')
    logical=[];current='';continued=0
    for line in lines:
        if current and line.lstrip().startswith(('#',';')):continue
        if line.endswith('\\'):
            continued+=1
            if continued>LIMITS['continuations']:_bad('Too many unit continuations')
            current+=line[:-1]+' '
            if len(current.encode())>LIMITS['line_bytes']:_bad('Systemd logical line exceeds limit')
        else:
            if len((current+line).encode())>LIMITS['line_bytes']:_bad('Systemd logical line exceeds limit')
            logical.append(current+line);current='';continued=0
    if current:_bad('Unterminated unit continuation')
    section=None;values={};unknown=0;total=0;exec_start=False;environment=False;has_service=False
    for line in logical:
        line=line.strip()
        if not line or line.startswith(('#',';')):continue
        if line.startswith('['):
            if line not in ('[Unit]','[Service]','[Install]'):_bad('Unsupported or invalid unit section')
            section=line[1:-1];has_service=has_service or section=='Service';continue
        if section is None or '=' not in line:_bad('Directive outside a unit section')
        key,value=line.split('=',1);key=key.strip();value=value.strip();total+=1
        if not re.fullmatch('[A-Za-z][A-Za-z0-9]{0,79}',key) or total>LIMITS['directives']:_bad('Invalid or excessive unit directive')
        if section!='Service':continue
        if key=='ExecStart':exec_start=bool(value);continue
        if key in ('Environment','EnvironmentFile','PassEnvironment','LoadCredential','LoadCredentialEncrypted','SetCredential','SetCredentialEncrypted'):
            environment=environment or bool(value);continue
        if key not in _KNOWN:unknown+=1;continue
        if not value:
            values.pop(key,None)
            # Empty list is an explicit empty capability set, unlike scalar reset.
            if key in ('CapabilityBoundingSet','AmbientCapabilities'):values[key]=[]
            continue
        if key in _BOOL:values[key]=_bool(value)
        elif key in _ENUM:
            if value.lower() in _TRUE|_FALSE:value=_bool(value)
            if value not in _ENUM[key]:_bad('Invalid systemd protection value')
            values[key]=value
        elif key=='User':
            if not re.fullmatch(r'(?:[a-zA-Z_][a-zA-Z0-9_.-]{0,63}|[0-9]{1,10})',value):_bad('Invalid unit user')
            # Only root/non-root semantics are exported, not arbitrary account names.
            values[key]='root' if value=='root' or value.isdigit() and int(value)==0 else 'non_root_declared'
        elif key=='RestrictNamespaces':
            if value.lower() in _TRUE|_FALSE:values[key]=_bool(value)
            else:
                tokens=value.lstrip('~').split()
                if not tokens or any(t not in {'cgroup','ipc','net','mnt','pid','user','uts'} for t in tokens):_bad('Invalid namespace restriction')
                mode='deny_list' if value.startswith('~') else 'allow_list'
                prior=values.get(key)
                if isinstance(prior,dict) and prior['mode']!=mode:_bad('Mixed namespace restrictions are outside review subset')
                existing=prior['namespaces'] if isinstance(prior,dict) else []
                values[key]={'mode':mode,'namespaces':sorted(set(existing+tokens))}
        else:
            tokens=value.lstrip('~').split()
            if not tokens or len(tokens)>64 or any(not re.fullmatch('CAP_[A-Z0-9_]{1,63}',t) for t in tokens):_bad('Invalid capability directive')
            # Multiple capability lines combine; empty lines reset; do not pretend last line overrides.
            form='complement' if value.startswith('~') else 'list'
            prior=values.get(key)
            if isinstance(prior,dict) and prior['mode']!=form:_bad('Mixed capability complements are outside review subset')
            existing=prior['capabilities'] if isinstance(prior,dict) else []
            values[key]={'mode':form,'capabilities':sorted(set(existing+tokens))}
    if not has_service:_bad('A Service section is required')
    findings=[]
    def add(code,field,severity='medium'):
        findings.append({'code':code,'field':'Service.'+field,'severity':severity,'message':'Static service baseline observation: '+code})
    for key in sorted(_BOOL-{'DynamicUser'}):
        if values.get(key)!='yes':add('missing_'+key,key)
    for key in ('PrivateTmp','ProtectSystem','ProtectHome'):
        if values.get(key) in (None,'no'):add('missing_'+key,key)
    if values.get('User')=='root' or values.get('User') is None and values.get('DynamicUser')!='yes':add('root_or_unspecified_user','User','high')
    if values.get('RestrictNamespaces')!='yes':add('namespaces_not_fully_restricted','RestrictNamespaces')
    if values.get('CapabilityBoundingSet')!=[]:add('capability_bounding_not_empty','CapabilityBoundingSet')
    if values.get('AmbientCapabilities',[])!=[]:add('ambient_capabilities','AmbientCapabilities','high')
    if not exec_start:add('no_exec_start_recorded','ExecStart','low')
    return {'schema':'was.systemd-review/1','directives':values,'findings':findings,
            'summary':{'findings':len(findings),**{s:sum(f['severity']==s for f in findings) for s in ('high','medium','low')}},
            'exec_start_present':exec_start,'environment_present':environment,'unknown_directive_count':unknown,
            'source_sha256':hashlib.sha256(data).hexdigest(),'network':False,'applied':False,
            'limits':dict(LIMITS),'limitations':LIMITATIONS}


def sample():
    return '[Unit]\nDescription=Synthetic service\n[Service]\nExecStart=/usr/bin/true\nUser=root\nNoNewPrivileges=no\nPrivateTmp=no\n[Install]\nWantedBy=default.target\n'
