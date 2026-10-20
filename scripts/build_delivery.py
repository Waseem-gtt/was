#!/usr/bin/env python3
"""Build and byte-verify a delivery from a reviewed commit, excluding old bundles.

python scripts/build_delivery.py FULL_SHA WHEEL [--output NEW_DIRECTORY]
No network, runtime data, private keys, signing, Git mutations or publishing.
"""
import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
import zipfile

ROOT=Path(__file__).resolve().parents[1]
MAX_BYTES=64*1024*1024


def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT)


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def build(commit,wheel,output=None):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('Use a complete reviewed commit SHA')
    version=tomllib.loads(git('show',commit+':pyproject.toml').decode())['project']['version']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version):raise ValueError('Invalid version')
    out=Path(output).absolute() if output else ROOT/'releases'/version
    if out.exists() or out.is_symlink():raise ValueError('Output must be a new directory')
    wheel=Path(wheel).resolve()
    if wheel.name!='was_cyber_platform-'+version+'-py3-none-any.whl' or not wheel.is_file() or wheel.stat().st_size>MAX_BYTES:raise ValueError('Wrong or oversized wheel')
    entries=[];source={};total=0
    for entry in git('ls-tree','-rz',commit).split(b'\0'):
        if not entry:continue
        header,name=entry.split(b'\t',1);mode,kind,_=header.split();name=name.decode()
        if name.startswith('releases/'):continue
        if kind!=b'blob' or mode not in (b'100644',b'100755'):raise ValueError('Unsupported source object')
        parts=Path(name).parts
        if name.startswith('/') or '..' in parts or any(p in ('.git','.state','.env','setup-token','platform.db') for p in parts) or name.endswith(('.pem','.key','.db','.sqlite','.sqlite3','.cyberbackup','.gguf')):raise ValueError('Runtime or secret path in source')
        data=git('show',commit+':'+name);total+=len(data)
        if total>MAX_BYTES:raise ValueError('Source exceeds delivery budget')
        source[name]=data;entries.append((name,int(mode,8)))
    report=source['reports/validation-'+'.'.join(version.split('.')[:2])+'.json']
    if json.loads(report)['version']!=version:raise ValueError('Report version mismatch')
    with zipfile.ZipFile(wheel) as archive:
        if sum(i.file_size for i in archive.infolist())>MAX_BYTES or len(archive.namelist())!=len(set(archive.namelist())):raise ValueError('Unsafe wheel members')
        metadata=BytesParser().parsebytes(archive.read('was_cyber_platform-'+version+'.dist-info/METADATA'))
        if metadata['Version']!=version or metadata['Name']!='was-cyber-platform':raise ValueError('Wheel distribution metadata mismatch')
        names={n for n in archive.namelist() if n.startswith('cyber_platform/') and not n.endswith('/')}
        if names!={n for n in source if n.startswith('cyber_platform/')}:raise ValueError('Wheel package file set mismatch')
        for name in names:
            if archive.read(name)!=source[name]:raise ValueError('Wheel bytes differ from reviewed source: '+name)
    timestamp=datetime.fromtimestamp(int(git('show','-s','--format=%ct',commit)),timezone.utc)
    zip_date=(max(1980,timestamp.year),timestamp.month,timestamp.day,timestamp.hour,timestamp.minute,timestamp.second)
    out.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent) as temp:
        stage=Path(temp)/'bundle';stage.mkdir()
        archive_path=stage/('was-cyber-platform-'+version+'-source.zip')
        with zipfile.ZipFile(archive_path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            archive.comment=commit.encode()
            for name,mode in sorted(entries):
                info=zipfile.ZipInfo(name,zip_date);info.create_system=3;info.external_attr=mode<<16;info.compress_type=zipfile.ZIP_DEFLATED
                archive.writestr(info,source[name])
        with zipfile.ZipFile(archive_path) as archive:
            if set(archive.namelist())!=set(source):raise ValueError('Source archive file set mismatch')
            for name in source:
                if archive.read(name)!=source[name]:raise ValueError('Source archive byte mismatch')
        shutil.copyfile(wheel,stage/wheel.name);(stage/'validation.json').write_bytes(report)
        (stage/'README.md').write_text('# حزمة '+version+'\n\nتضم المصدر والبرنامج وتقرير التحقق وبصمات الملفات. راجع فهرس المشروع وأدلة الوظائف داخل المصدر.\n\nالمصدر يطابق الالتزام المحدد مع استثناء مجلد releases كاملًا لمنع تداخل الحزم التاريخية وتضخم الأرشيف؛ تبقى الحزم السابقة في المستودع الخاص.\n\nهذه حزمة غير موقعة بمفتاح ناشر؛ البصمات ليست توقيعًا. لا تتضمن بيانات تشغيل المالك أو مفاتيحه أو نماذجه. للتحقق شغّل `sha256sum -c SHA256SUMS` داخل المجلد.\n')
        files={p.name:{'bytes':p.stat().st_size,'sha256':digest(p)} for p in sorted(stage.iterdir())}
        provenance={'version':version,'source_commit':commit,'source_exclusions':['releases/'],'files':files,'verification':{'source_archive_exact_selected_tracked_files':len(source),'wheel_package_files_exact':len(names),'runtime_agent_modules':'absent' if not names&{'cyber_platform/agents.py','cyber_platform/agent_roles.py'} else 'present','installed_wheel':'see_validation_json','github_actions_result':'not_observed'},'signature':'unsigned; SHA-256 is not a publisher signature','privacy':'No owner runtime files, evidence, backups, secrets, private keys or model weights included.'}
        if provenance['verification']['runtime_agent_modules']!='absent':raise ValueError('Removed runtime agent modules present')
        (stage/'provenance.json').write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+'\n')
        (stage/'SHA256SUMS').write_text(''.join(digest(p)+'  '+p.name+'\n' for p in sorted(stage.iterdir())))
        stage.rename(out)
    return {'output':str(out),'version':version,'source_commit':commit,'source_files_verified':len(source),'package_files_verified':len(names),'source_exclusions':['releases/']}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('commit');parser.add_argument('wheel');parser.add_argument('--output');args=parser.parse_args()
    print(json.dumps(build(args.commit,args.wheel,args.output)))


if __name__=='__main__':main()
