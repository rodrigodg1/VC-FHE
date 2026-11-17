"""Full-run cloud preservation, strictly after the unchanged run validator passes."""
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from cloud_results.common import check_full,digest,gcloud,now,read,require,run,sha,write
from cloud_results.storage import Store
from cloud_results.infra import names
import cloud_archive
import smoke_cleanup
import topology


def validate_bucket(config,store):
    project=gcloud('projects','describe',config['project_id'])
    bucket=store.api('')
    require(bucket['name']==names(config)['bucket'] and str(bucket['projectNumber'])==str(project['projectNumber'])
        and bucket['location'].lower()==config['regions'][0]['name'] and bucket['storageClass']=='STANDARD'
        and bucket.get('iamConfiguration',{}).get('uniformBucketLevelAccess',{}).get('enabled') is True
        and bucket.get('iamConfiguration',{}).get('publicAccessPrevention')=='enforced'
        and bucket.get('labels',{}).get('vcfhe-purpose')=='complete-results'
        and bucket.get('labels',{}).get('vcfhe-campaign')==config['campaign']
        and not bucket.get('lifecycle',{}).get('rule'),'Private full-results bucket ownership or policy differs')
    return {k:bucket[k] for k in ('name','id','projectNumber','timeCreated','location')}


def plan(campaign):
    """Complete TF scope and exact resource IDs, without the smoke-only cleanup path."""
    config=check_full(campaign.config)
    resources,state_sha=smoke_cleanup._state(config,campaign.run)
    result={'run':str(campaign.run),'campaign':config['campaign'],'configSha256':digest(config),
        'terraformStateSha256':state_sha,'hosts':topology.hosts(config),'resources':[]}
    for row in resources.values():
        args=smoke_cleanup._describe_args(row)
        if args is None:continue
        live=smoke_cleanup._cloud(smoke_cleanup._args(config,args))
        smoke_cleanup._check_identity(config,row,live)
        result['resources'].append(dict(row,describe=args,identity=smoke_cleanup._identity(live)))
    for host in result['hosts']:
        key=host['id'].replace('-','_')
        vm=next(r for r in result['resources'] if r['type']=='google_compute_instance' and r['key']==key)
        actual=smoke_cleanup._cloud(smoke_cleanup._args(config,vm['describe']))
        require(actual['status']=='RUNNING' and actual.get('labels',{}).get('experiment')==config['campaign'],
                'Private backup needs the original running experiment host')
        expected={host['name'],host['name']+'-state'}
        attached={smoke_cleanup._disk_ref(config,d['source'],host['zone']) for d in actual['disks']}
        require(attached==expected and len(actual['disks'])==2,'Unexpected disk attachment')
        args=['compute','disks','describe',host['name'],'--zone',host['zone']]
        boot=smoke_cleanup._cloud(smoke_cleanup._args(config,args))
        require(boot.get('users')==[actual['selfLink']],'Boot disk is shared or attached elsewhere')
        result['resources'].append({'address':'boot.'+key,'type':'google_compute_disk','key':key,
            'attributes':{'name':host['name'],'zone':host['zone']},'describe':args,
            'identity':smoke_cleanup._identity(boot)})
    result['iam']=[row for row in resources.values() if row['type'].endswith('_iam_member')]
    return result


def set_grants(store,bindings,add):
    policy=store.api('/iam?optionsRequestedPolicyVersion=3')
    require(policy.get('etag'),'IAM concurrency etag required')
    current=policy.get('bindings',[])
    for binding in bindings:
        if add and binding not in current:current.append(binding)
        elif not add:current=[b for b in current if b!=binding]
    store.api('/iam','PUT',{**policy,'version':3,'bindings':current})
    checked=store.api('/iam?optionsRequestedPolicyVersion=3').get('bindings',[])
    require(all((b in checked) if add else (b not in checked) for b in bindings),'Scoped archive IAM update failed')


def preserve_hosts(campaign):
    """Stop completed actors, then reuse the tested host-side TAR/readback worker."""
    import deployment
    check_full(campaign.config)
    deployment.campaign_module().verify(campaign.run)
    cfg=read(campaign.run/'config/campaign.json')
    require(not cfg.get('smoke') and cfg.get('half')=='both','Full preservation cannot replace a smoke result')
    app=read(campaign.run/'reports/application.json')
    require(len(app['cases'])==27 and read(campaign.run/'state.json')['status']=='passed','Full source is incomplete')
    directory=campaign.run/'preservation';directory.mkdir(mode=0o700)
    ownership=plan(campaign);write(directory/'ownership.local.json',ownership,new=True)
    store=Store(names(campaign.config)['bucket'],campaign.config['project_id'])
    bucket=validate_bucket(campaign.config,store)
    prefix=digest({'run':str(campaign.run),'config':digest(campaign.config)})[:32]
    expires=(datetime.now(timezone.utc)+timedelta(hours=4)).strftime('%Y-%m-%dT%H:%M:%SZ')
    bindings=[];maximum=100*1024**3
    for host in ownership['hosts']:
        key=host['id'].replace('-','_')
        account=next(r['attributes']['email'] for r in ownership['resources'] if r['type']=='google_service_account' and r['key']==key)
        condition={'title':'vcfhe-full-'+prefix+'-'+host['id'],'expression':
            'resource.name.startsWith("projects/_/buckets/'+store.bucket+'/objects/runs/'+prefix+'/'+host['id']+'/")'
            ' && request.time < timestamp("'+expires+'")'}
        bindings.extend({'role':role,'members':['serviceAccount:'+account],'condition':condition}
                        for role in ('roles/storage.objectCreator','roles/storage.objectViewer'))
    write(directory/'archive-grants.local.json',bindings,new=True)
    set_grants(store,bindings,True)
    # Validate all host scopes and disk headroom before stopping any actor.
    total=0
    for host,remote in campaign.remotes.items():
        require(remote.text(['sudo','cat','/srv/vcfhe/scope.txt'])==campaign.config['campaign']+'/'+host,'Foreign state mount')
        size=int(remote.text(['sudo','du','-sb','/srv/vcfhe']).split()[0]);total+=size
        free=int(remote.text(['df','-B1','--output=avail','/var/tmp']).splitlines()[-1])
        require(free>2*size+1024**3,'Insufficient cloud boot-disk archive/readback headroom')
    require(total+4*1024**3<=maximum,'Full private-state archive allowance exceeded')
    for host,remote in campaign.remotes.items():
        remote.run(['sudo','touch',campaign.base+'/'+host+'/stop-sampler'])
        identifiers=remote.text(['sudo','docker','ps','-q','--filter','label=com.docker.compose.project='+campaign.config['campaign']+'-'+host]).split()
        require(all(re.fullmatch('[0-9a-f]{12,64}',v) for v in identifiers),'Unexpected container identity')
        if identifiers:remote.run(['sudo','docker','stop','--time','45',*identifiers],stdout=subprocess.DEVNULL)
        require(not remote.text(['sudo','docker','ps','-q','--filter','label=com.docker.compose.project='+campaign.config['campaign']+'-'+host]),'Actor remains active')
        pattern='^python3 /srv/vcfhe/'+campaign.config['campaign']+'/'+host+'/probe[.]py '
        remote.run(['sudo','sh','-c','pids=$(pgrep -f "$1" || true); test -z "$pids" || kill $pids','sampler-stop',pattern])
        remote.run(['sudo','sync'])
    description={'bucket':bucket,'prefix':prefix,'bindings':bindings}
    receipts={}
    for host in ownership['hosts']:
        remaining=maximum-sum(v['archiveBytes'] for v in receipts.values())
        receipts[host['id']]=cloud_archive.export_host(campaign.config,ownership,host,campaign.remotes[host['id']],
                                                      directory,description,remaining)
    set_grants(store,bindings,False)
    receipt={'schema':'full-host-private-preservation-v1','status':'verified-cloud-readback','bucket':bucket,
             'prefix':prefix,'hosts':receipts,'temporaryHostGrantsRevoked':True,'ownershipSha256':sha(directory/'ownership.local.json')}
    write(directory/'private-hosts.local.json',receipt,new=True)
    return receipt


def archive_controller(run_dir,base,job,hosts):
    """Preserve complete raw evidence on cloud disk and GCS, without downloading it."""
    require(hosts.get('status')=='verified-cloud-readback' and len(hosts.get('hosts',{}))==4,'Four private host archives are required')
    store=Store(job['bucket'],job['config']['project_id'])
    directory=Path(job['work'])/'archives';directory.mkdir(mode=0o700,exist_ok=True)
    archive=directory/'complete-evidence.tar'
    roots={'run':Path(run_dir),'composite':Path(base)}
    files={}
    for prefix,root in roots.items():
        for p in sorted(root.rglob('*')):
            require(not p.is_symlink(),'Symlink in full raw evidence')
            if p.is_file():files[prefix+'/'+p.relative_to(root).as_posix()]={'sha256':sha(p),'bytes':p.stat().st_size}
    projected=sum(v['bytes']+2048 for v in files.values())+10240
    require(projected+sum(v['archiveBytes'] for v in hosts['hosts'].values())+job['sourceObject']['bytes']<=100*1024**3,
            'Quoted complete evidence allowance would be exceeded')
    import shutil
    require(shutil.disk_usage(directory).free>2*projected+1024**3,'Cloud archive/readback disk headroom insufficient')
    with archive.open('xb') as out:
        os.fchmod(out.fileno(),0o600)
        with tarfile.open(fileobj=out,mode='w') as tar:
            for name in files:
                prefix,relative=name.split('/',1);tar.add(roots[prefix]/relative,arcname=name,recursive=False)
        out.flush();os.fsync(out.fileno())
    require(archive.stat().st_size+sum(v['archiveBytes'] for v in hosts['hosts'].values())<=100*1024**3,
            'Quoted aggregate cloud evidence cap exceeded')
    obj=store.upload(archive,'runs/'+job['jobId']+'/complete-evidence.tar')
    returned=directory/'readback.tar';store.download(obj,returned)
    # Entire object SHA is checked by download. Inspect every member again.
    with tarfile.open(returned,'r:') as tar:
        seen=set()
        for member in tar:
            require(member.isfile() and member.name in files and member.name not in seen,'Unexpected archive entry')
            seen.add(member.name);h=__import__('hashlib').sha256();count=0
            stream=tar.extractfile(member)
            for data in iter(lambda:stream.read(1024**2),b''):h.update(data);count+=len(data)
            require(count==files[member.name]['bytes'] and h.hexdigest()==files[member.name]['sha256'],'Cloud archive member changed')
        require(seen==set(files),'Cloud raw archive is incomplete')
    receipt={'schema':'complete-cloud-preservation-v1','status':'verified-cloud-preservation',
        'rawArchive':obj,'rawFileInventorySha256':digest(files),'privateHosts':hosts,
        'sourceArchive':job['sourceObject'],
        'controllerSourceSha256':sha(Path(run_dir)/'distributed/cloud-controller-source.json')}
    write(directory/'preservation.local.json',receipt,new=True)
    return receipt
