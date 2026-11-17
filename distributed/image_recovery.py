"""Recover deleted published images, never failed or ambiguous protocol work."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid
import budget
import topology

ACTIVE={'WORKING','QUEUED','PENDING'}
TERMINAL={'SUCCESS','FAILURE','INTERNAL_ERROR','TIMEOUT','CANCELLED','EXPIRED'}

def write(path,value):
    path=Path(path)
    pending=path.with_name(path.name+'.'+uuid.uuid4().hex+'.pending')
    with pending.open('x') as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    pending.replace(path)

def retain_result(directory,value):
    path=Path(directory)/'cloud-build-result.json'
    if path.exists():
        if json.loads(path.read_text())==value:return path
        path=path.with_name('cloud-build-result-observation-'+uuid.uuid4().hex+'.json')
    write(path,value)
    return path

def prepare_upload(directory,record):
    """Submit the public closure only, never recovery history or Terraform state."""
    import image
    directory=Path(directory)
    upload=directory/'cloud-build-upload'
    upload.mkdir(mode=0o700)
    for name in ('app','upstream'):shutil.copytree(directory/name,upload/name,symlinks=True)
    for name in ('Dockerfile','distributed-source.json'):shutil.copy2(directory/name,upload/name)
    for path in upload.rglob('*'):
        if path.is_symlink() and not path.resolve().is_relative_to(upload.resolve()):
            raise ValueError('public build input symlink escapes the isolated upload closure')
    image.verify_inputs(upload,record)
    (upload/'.gcloudignore').write_text('**\n!Dockerfile\n!distributed-source.json\n!app/\n!app/**\n!upstream/\n!upstream/**\n')
    return upload

def exists(args):
    args=list(map(str,args))
    result=subprocess.run(['gcloud',*args,'--format=json'],capture_output=True,text=True)
    if result.returncode==0:return True
    error=result.stderr or ''
    compute_missing=False
    if args and args[0]=='compute' and 'describe' in args:
        command='gcloud.'+'.'.join(args[:args.index('describe')+1])
        compute_missing=re.fullmatch(
            r'ERROR: \('+re.escape(command)+r"\) Could not fetch resource:\s*-\s*The resource '[^'\r\n]+' was not found",
            error.strip(),re.I) is not None
    # Some services intentionally combine absence and permission errors. Such
    # errors cannot authorize another paid build.
    if (re.search(r'permission|forbidden|unauthoriz|unauthenticat|denied|or.*(?:access|exist)',error,re.I)
            or not (re.search(r'\bNOT_FOUND\b',error) or compute_missing)):
        raise ValueError('Cannot confirm cloud resource absence. Inspect authentication, permissions or transport.')
    return False

def missing_images(config,published):
    return [digest for digest in (published['digest'],published['besuDigest'])
            if not exists(['artifacts','docker','images','describe',digest,'--project',config['project_id']])]

def require_success(published,source_sha):
    if published.get('buildStatus')!='SUCCESS' or published.get('sourceSha256')!=source_sha:
        raise ValueError('Only a source-bound successful image build may be recreated automatically')

def no_active(builds):
    for row in builds:
        if row.get('status') in ACTIVE:
            raise ValueError('A campaign build is still active. No duplicate compilation is allowed.')
        if row.get('status') not in TERMINAL:
            raise ValueError('A campaign build has an unknown outcome. Inspect it before another paid attempt.')
        if row.get('startTime') and not row.get('finishTime'):
            raise ValueError('A completed build lacks its finish time. Cumulative cost cannot be established.')
        if row.get('status')=='SUCCESS' and not (row.get('startTime') and row.get('finishTime')):
            raise ValueError('Successful build timing is unavailable. Cumulative cost cannot be established.')

def gce_reservations(config,ledger):
    ledger=Path(ledger)
    value=json.loads(ledger.read_text()) if ledger.exists() else {'reservations':[]}
    return sum((budget.amount(row['upperUsd']) for row in value['reservations']
                if row['project']==config['project_id'] and row['campaign']==config['campaign']),budget.amount(0))

def require_no_pending(directory):
    if (Path(directory)/'image-recovery-pending.json').exists():
        raise ValueError('An earlier image recovery was interrupted. Inspect its retained records before any new build.')

def prove_gce_cleanup(config,work=None):
    """Check stored state and every disposable named resource without mutation."""
    name=config['campaign']+'-image-builder'
    location=topology.builder_location(config)
    if work is not None:
        work=Path(work)
        previous=work/'cleanup.local.json'
        if previous.exists() and json.loads(previous.read_text()).get('status')!='passed':
            raise ValueError('Prior GCE cleanup failed or is ambiguous. Inspect retained state before another attempt.')
        state=work/'terraform/terraform.tfstate'
        if not state.is_file():raise ValueError('Prior GCE Terraform state is unavailable. Cannot establish cleanup.')
        result=subprocess.run(['terraform','-chdir='+str(work/'terraform'),'show','-json'],
                              capture_output=True,text=True)
        if result.returncode:raise ValueError('Cannot inspect prior GCE Terraform state')
        value=json.loads(result.stdout)
        def managed(module):
            return [r.get('address','unknown') for r in module.get('resources',[]) if r.get('mode')!='data']+[
                address for child in module.get('child_modules',[]) for address in managed(child)]
        remaining=managed(value.get('values',{}).get('root_module',{}))
        if remaining:raise ValueError('Prior GCE Terraform state still owns resources. No automatic replacement.')
    checks=[['compute','instances','describe',name,'--zone',location['zone']],
            ['compute','networks','describe',name],
            ['compute','networks','subnets','describe',name,'--region',location['name']],
            ['compute','firewall-rules','describe',name+'-iap']]
    for args in checks:
        if exists([*args,'--project',config['project_id']]):
            raise ValueError('A prior disposable builder resource still exists. Preserve and inspect it.')
    return {'schema':'vcfhe-gce-image-cleanup-v1','status':'passed',
            'verifiedAt':datetime.now(timezone.utc).isoformat(),'builder':name,
            'builderZone':location['zone'],'builderRegion':location['name'],
            'managedResourcesRemaining':[],'namedResourcesAbsent':True}

def archive(directory,names,missing,**details):
    """Move only successful build metadata/state into private retained history."""
    directory=Path(directory)
    require_no_pending(directory)
    if (directory/'ambiguous-cloud-build-submission.json').exists():
        raise ValueError('An ambiguous prior cloud build must be reconciled before replacement')
    target=directory/'history'/('deleted-image-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8])
    pending=directory/'image-recovery-pending.json'
    with pending.open('x') as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump({'target':str(target),'sourceRecords':names},stream);stream.flush();os.fsync(stream.fileno())
    target.mkdir(parents=True,mode=0o700)
    moved={}
    for name in names:
        item=Path(name)
        if item.is_absolute() or '..' in item.parts:raise ValueError('invalid build archive path')
        source=directory/item
        if not source.exists():continue
        if source.is_symlink():raise ValueError('unexpected build-record symlink')
        if source.is_file():moved[name]=hashlib.sha256(source.read_bytes()).hexdigest()
        else:
            moved[name]={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in source.rglob('*') if p.is_file() and not p.is_symlink()}
        source.rename(target/item)
    write(target/'recovery.json',{'schema':'vcfhe-deleted-image-recovery-v1',
        'reason':'Registry explicitly reported NOT_FOUND for an earlier successful build',
        'missingImages':missing,'preservedRecords':moved,**details})
    pending.rename(target/'completed-recovery.json')
    return target
