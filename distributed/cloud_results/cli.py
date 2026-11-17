#!/usr/bin/env python3
"""Prepare, explicitly start, observe and deliver a cloud-controlled evaluation run."""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results.common import ROOT,VERSION,MAX_PACKAGE_BYTES,check_full,digest,gcloud,now,private,read,require,run,sha,sources,write
from cloud_results import bundle,infra,package,quote as pricing,cleanup
from cloud_results.storage import Store
from remote import Remote
import budget
from cloud_results.completion_budget import assess as assess_completion_budget


def verify_prepared(path):
    path=private(path);p=read(path/'prepared.local.json');m=read(path/'source-manifest.local.json')
    require(p['sourceManifestSha256']==sha(path/'source-manifest.local.json') and m['controllerSources']==sources(),
            'Prepared controller source changed. Prepare a fresh directory')
    require(sha(path/p['sourceArchive'])==p['sourceArchiveSha256'] and (path/p['sourceArchive']).stat().st_size==p['sourceBytes'],
            'Prepared source archive changed')
    cfg=check_full(read(path/'outer-config.local.json'));inner=check_full(read(path/'inner-config.local.json'))
    require(inner==infra.inner_config(cfg) and digest(inner)==m['innerConfigSha256'],'Configuration differs from source snapshot')
    require(read(path/'terraform/main.tf.json')==infra.terraform(cfg),'Controller declarations changed')
    require(read(path/'quote.local.json')==read_archive_job(path/p['sourceArchive'],'job/quote.local.json'),
            'Quoted cost changed after source freeze')
    smoke=read_archive_job(path/p['sourceArchive'],'build/successful-smoke.local.json')
    from cloud_results.smoke_gate import validate_proof
    attestation=(read_archive_job(path/p['sourceArchive'],'build/postcollection-smoke-attestation.local.json')
                 if smoke.get('schema')=='source-matched-postcollection-functional-smoke-v1' else None)
    validate_proof(smoke,read_archive_job(path/p['sourceArchive'],'build/distributed-source.json'),
                   read_archive_job(path/p['sourceArchive'],'build/published-image.json'),attestation)
    require(smoke.get('status')=='passed' and smoke.get('sourceSha256')==m['protocolImageSourceSha256']
            and smoke.get('privateCloudBackupVerified') is True and smoke.get('ownedInfrastructureRemoved') is True,
            'Source-matched smoke validation was not frozen in the full preparation')
    return cfg,inner,p,m


def read_archive_job(path,name):
    import tarfile
    with tarfile.open(path,'r:gz') as archive:return json.load(archive.extractfile(name))


def controller_remote(config):
    return Remote(config,{'name':infra.names(config)['controller'],'zone':config['regions'][0]['zone']})


def controller_script(root):
    repo=root+'/input/repository/VC-FHE'
    python=repo+'/threshold-kms/.cache/postprocess-python/bin/python'
    # Validation imports the selected figure definitions too. Keep the entire
    # administrative process in the already checked plotting environment,
    # including unchanged subprocesses that inherit sys.executable.
    # Only the original locked npm-ci calls use the already reviewed Linux
    # correction. Node/Python readiness and all protocol code remain original.
    installer=shlex.join(['python3',repo+'/distributed/cloud_results/controller_js.py',
        '--root',repo,'--build',root+'/input/build','--cache','/srv/vcfhe-controller/dependency-cache',
        '--report',root+'/input/controller-js-proof.local.json'])
    wrapper=('\nnpm() {\n'
        '  if [ "${1:-}" = --prefix ] && [ "${3:-}" = ci ]; then\n'
        '    '+installer+' --project "$2"\n'
        '  else command npm "$@"; fi\n}\n')
    return ('set -Eeuo pipefail\ncd '+shlex.quote(repo)+wrapper+
            'source distributed/controller-bootstrap.sh --install\nunset -f npm\n'+
            shlex.join([python,'distributed/cloud_results/worker.py','--input',root+'/input'])+'\n')


def prepare(config,quote,build,out):
    value=bundle.prepare(config,quote,build,out)
    folder=Path(out)/'terraform';folder.mkdir(mode=0o700)
    write(folder/'main.tf.json',infra.terraform(config),new=True)
    shutil.copy2(Path(__file__).resolve().parents[1]/'terraform.lock.hcl',folder/'.terraform.lock.hcl')
    verify_prepared(out)
    return value


def explicit(execute):
    require(execute,'This operation requires --execute. Preparation and checks never start an evaluation')


def start(path,*,execute=False):
    explicit(execute)
    config,inner,p,m=verify_prepared(path);path=Path(path)
    # Cost/source gates precede API mutations and the first billed VM.
    admission=assess_completion_budget(inner,read(path/'quote.local.json'))
    require(admission['status']=='admit','Cumulative budget refuses this full campaign: '+json.dumps(admission))
    require(not (path/'start-intent.local.json').exists(),'Launch was already requested. Inspect status, never relaunch a protocol run')
    from cloud_tools import ensure
    ensure()
    from cloud_results.controller_api import ensure as ensure_controller_apis
    api_setup=ensure_controller_apis(config,execute=True)
    write(path/'controller-management-apis.local.json',api_setup)
    import cloud_setup
    inspected=cloud_setup.inspect(config,enable=False)
    require(inspected['operatorPrincipal']==config['operator_principal'],'Wrong outer cloud identity')
    globalq=gcloud('compute','project-info','describe','--project',config['project_id'])['quotas']
    allcpu=next(v for v in globalq if v['metric']=='CPUS_ALL_REGIONS')
    import topology
    cpus=sum(int(h['machine_type'].rsplit('-',1)[1]) for h in topology.hosts(config))+2
    require(float(allcpu['limit'])-float(allcpu['usage'])>=cpus,'Insufficient global CPU quota including the controller')
    regional=gcloud('compute','regions','describe',config['regions'][0]['name'],'--project',config['project_id'])['quotas']
    def quota_available(metric,need):
        row=next((v for v in regional if v['metric']==metric),None)
        require(row is not None and float(row['limit'])-float(row['usage'])>=need,'Insufficient controller-inclusive '+metric+' quota')
    quota_available('E2_CPUS' if any(v['metric']=='E2_CPUS' for v in regional) else 'CPUS',2)
    quota_available('SSD_TOTAL_GB',config['boot_disk_gib']+config['state_disk_gib']+200)
    quota_available('IN_USE_ADDRESSES',2)
    from image_recovery import missing_images
    require(not missing_images(config,read_archive_job(path/p['sourceArchive'],'build/published-image.json')),
            'Pinned images unavailable. This route never compiles a replacement')
    from smoke_cleanup import _cloud
    targets=[*topology.hosts(config),{'name':infra.names(config)['controller'],'zone':config['regions'][0]['zone']}]
    for host in targets:
        require(_cloud(['compute','instances','describe',host['name'],'--zone',host['zone'],
                        '--project',config['project_id']],missing=True) is None,
                'A target VM already exists. Never reuse or stop an earlier campaign implicitly')
    write(path/'start-intent.local.json',{'requestedAt':now(),'configSha256':digest(config),
          'sourceManifestSha256':p['sourceManifestSha256'],'admission':admission},new=True)
    tf=['terraform','-chdir='+str(path/'terraform')]
    try:
        run(tf+['init','-input=false']);run(tf+['validate']);run(tf+['plan','-input=false','-out=controller.tfplan'])
        budget_result=assess_completion_budget(inner,read(path/'quote.local.json'))
        require(budget_result['status']=='admit','Cost admission expired before VM creation')
        run(tf+['apply','-input=false','controller.tfplan'])
        state=read(path/'terraform/terraform.tfstate')
        write(path/'controller-ownership.local.json',cleanup.controller_ownership(config,state),new=True)
        infra.allocate_accounts(config,path)
        remote=controller_remote(config)
        # Startup apt transactions are allowed to finish before bootstrap.
        deadline=time.monotonic()+900
        while True:
            try:
                remote.run(['sudo','test','-d','/srv/vcfhe-controller'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=45)
                break
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
                if time.monotonic()>=deadline:raise TimeoutError('Controller startup deadline exceeded')
                time.sleep(10)
        root='/srv/vcfhe-controller/'+m['jobId']
        remote.run(['sudo','test','!','-e',root])
        with __import__('tempfile').TemporaryDirectory() as tmp:
            handoff=Path(tmp)
            shutil.copy2(path/p['sourceArchive'],handoff/'controller-source.tar.gz')
            shutil.copy2(path/'actor-accounts.local.json',handoff/'actor-accounts.local.json')
            write(handoff/'source-archive.local.json',{'sha256':p['sourceArchiveSha256'],'bytes':p['sourceBytes']},new=True)
            # Fixed extraction helper, outside the frozen protocol-image closure.
            shutil.copy2(Path(__file__).with_name('extract_source.py'),handoff/'extract_source.py')
            remote.upload(handoff,root)
        remote.run(['sudo','python3',root+'/extract_source.py',root,p['sourceArchiveSha256'],p['sourceManifestSha256']])
        repo=root+'/input/repository/VC-FHE'
        script=controller_script(root)
        # systemd owns one execution. Disconnecting SSH cannot duplicate it.
        remote.run(['sudo','systemd-run','--unit=vcfhe-controller-'+m['jobId'],
                    '--property=WorkingDirectory='+repo,'--property=UMask=0077',
                    '--property=TimeoutStopSec=300',
                    '--property=StandardOutput=append:'+root+'/controller.log',
                    '--property=StandardError=append:'+root+'/controller.log',
                    '--property=RuntimeMaxSec='+str(config['maximum_vm_runtime_seconds']+7000),
                    '--property=ExecStopPost=/usr/bin/python3 '+repo+'/distributed/cloud_results/stop_compute.py '+root+'/input',
                    '/bin/bash','-c',script])
        write(path/'launched.local.json',{'status':'launched-once','jobId':m['jobId'],'remoteRoot':root,
             'createdAt':now(),'controller':infra.names(config)['controller']},new=True)
        return {'status':'launched-once','jobId':m['jobId']}
    except BaseException:
        # Stop owned compute after preparation failures. Never remove state or
        # rerun an ambiguous detached launch. Maximum durations remain a backstop.
        stop_compute_local(config,path)
        raise


def stop_compute_local(config,path):
    import topology
    from smoke_cleanup import _cloud
    hosts=[*topology.hosts(config),{'name':infra.names(config)['controller'],'zone':config['regions'][0]['zone']}]
    result=[]
    for host in hosts:
        try:
            live=_cloud(['compute','instances','describe',host['name'],'--zone',host['zone'],'--project',config['project_id']],missing=True)
            if live is not None:
                require(live.get('labels',{}).get('experiment')==config['campaign'],'Foreign compute stop refused')
                if live.get('status')!='TERMINATED':run(['gcloud','compute','instances','stop',host['name'],'--zone',host['zone'],'--project',config['project_id'],'--quiet'])
                confirmed=_cloud(['compute','instances','describe',host['name'],'--zone',host['zone'],'--project',config['project_id']],missing=True)
                require(confirmed is None or confirmed.get('status')=='TERMINATED','Compute stop not confirmed')
            result.append({'name':host['name'],'stoppedOrAbsent':True})
        except (subprocess.CalledProcessError,ValueError):result.append({'name':host['name'],'stoppedOrAbsent':False})
    write(Path(path)/'controller-compute-stop.local.json',{'hosts':result,'statePreserved':True})
    require(all(v['stoppedOrAbsent'] for v in result),'Compute stop failed. Inspect retained report')


def terminal(path):
    config,inner,p,m=verify_prepared(path)
    if not (Path(path)/'start-intent.local.json').exists():
        return {'status':'not-started','jobId':m['jobId']}
    store=Store(infra.names(config)['bucket'],config['project_id'])
    name='runs/'+m['jobId']+'/terminal.json'
    # NOT_FOUND is a running state. Authorization, malformed JSON and API
    # failures propagate and cannot be reported as completion.
    import urllib.error
    try:meta=store.metadata(name)
    except urllib.error.HTTPError as error:
        if error.code==404:
            try:
                failed=store.metadata('runs/'+m['jobId']+'/failure.json')
            except urllib.error.HTTPError as failure_error:
                if failure_error.code==404:return {'status':'not-completed','jobId':m['jobId']}
                raise
            return {'status':'failed-preserved','inspectionRequired':True,'errorReportAvailable':True}
        raise
    expected={'bucket':store.bucket,'object':name,'generation':meta['generation'],'bytes':int(meta['size']),
              'md5Hash':meta['md5Hash'],'sha256':meta['metadata']['vcfhe-sha256']}
    require(expected['bytes']<=2*1024**2,'Oversized terminal report')
    destination=Path(path)/'terminal-download.local.json'
    if destination.exists():require(sha(destination)==expected['sha256'],'Different terminal report retained')
    else:store.download(expected,destination,maximum=2*1024**2)
    result=read(destination)
    require(result['schema']==VERSION and result['status']=='awaiting-verified-local-delivery', 'Cloud run needs inspection')
    return result


def status(path):
    config,inner,p,m=verify_prepared(path)
    if not (Path(path)/'start-intent.local.json').exists():
        return {'status':'prepared-not-started','cloudResourcesCreated':False,
                'admission':assess_completion_budget(inner,read(Path(path)/'quote.local.json'))}
    from cloud_tools import ensure
    ensure()
    result=terminal(path)
    if result['status']=='failed-preserved':return result
    if result['status']!='not-completed':return {'status':result['status'],'fullCases':27,'computeStop':'verify with finish', 'rawDownloaded':False}
    remote=controller_remote(config);root='/srv/vcfhe-controller/'+m['jobId']
    script='import json;from pathlib import Path;r=Path('+repr(root+'/input/repository/VC-FHE/threshold-kms/runs/'+m['runName'])+');p=r/"launch-state.json";q=r/"live-progress.local.json";print(json.dumps({"launch":json.loads(p.read_text()) if p.exists() else None,"progress":json.loads(q.read_text()) if q.exists() else None}))'
    value=remote.json(['sudo','python3','-c',script])
    launch=value['launch'] or {}
    return {'status':launch.get('status','controller-preparation'),'stages':launch.get('stages',[]),'progress':value['progress']}


def finish(path,*,execute=False):
    explicit(execute)
    config,inner,p,m=verify_prepared(path);path=Path(path)
    result=terminal(path)
    require(result['status']=='awaiting-verified-local-delivery','Full campaign is not ready for local delivery')
    store=Store(infra.names(config)['bucket'],config['project_id'])
    controlfile=path/'control-download.local.json'
    if not controlfile.exists():store.download(result['control'],controlfile,maximum=8*1024**2)
    require(sha(controlfile)==result['control']['sha256'],'Cloud control file changed')
    control=read(controlfile)
    cleanup.validate_preservation(store,control)
    exported=result['results']
    archive=path/'results.tar'
    if not archive.exists():store.download(exported,archive,maximum=MAX_PACKAGE_BYTES)
    delivery=path/'results'
    if not delivery.exists():package.unpack(archive,delivery,exported)
    verified=package.verify_local(delivery)
    require(verified['manifestSha256']==exported['manifestSha256'],
            'Local delivery belongs to a different cloud export')
    package.verify_delivery_ready(delivery)
    # Stop confirmation is separate from evidence preservation. Never equate
    # an old progress report with a stalled protocol or stopped VM.
    stop_compute_local(config,path)
    if not (path/'protocol-teardown-complete.local.json').exists():cleanup.complete(path,delivery,control)
    if not (path/'controller-teardown-complete.local.json').exists():cleanup.complete_controller(path,delivery)
    return {'status':'delivered-and-cleaned','rawEvidenceInCloud':True,'rawEvidenceDownloaded':False,
            'results':str(delivery)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('test',help='offline adapter, recovery and Node regressions, no cloud execution')
    q=sub.add_parser('quote');q.add_argument('--config',type=Path,required=True);q.add_argument('--output',type=Path,required=True)
    q.add_argument('--prior-usd',required=True);q.add_argument('--hours',type=float,default=14);q.add_argument('--transfer-gib',type=float,default=48)
    q.add_argument('--retention-hours',type=float,default=24)
    p=sub.add_parser('prepare')
    for name in ('config','quote','build','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('check','start','status','finish','stop-compute'):
        p=sub.add_parser(name);p.add_argument('--prepared',type=Path,required=True)
        if name in ('start','finish','stop-compute'):p.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if args.command=='test':
        from cloud_results.reliability import run as offline_checks
        print(json.dumps(offline_checks(),indent=2));return
    if args.command=='quote':
        from cloud_tools import ensure
        ensure();result=pricing.make(read(args.config),hours=args.hours,transfer_gib=args.transfer_gib,
                                    retention_hours=args.retention_hours,prior_usd=args.prior_usd)
        write(private(args.output),result,new=True)
        print(json.dumps({'admission':result['admission'],'resourcesCreated':False},indent=2));return
    if args.command=='prepare':result=prepare(read(args.config),read(args.quote),args.build,args.output)
    elif args.command=='check':
        cfg,inner,p,m=verify_prepared(args.prepared)
        admission=assess_completion_budget(inner,read(args.prepared/'quote.local.json'))
        result={'status':'ready' if admission['status']=='admit' else 'budget-refused',
                'sourceIntegrity':'passed','readyToStart':admission['status']=='admit','admission':admission,
                'sourceFiles':len(m['files']),'smokeStarted':False,'fullCampaignStarted':False}
    elif args.command=='start':result=start(args.prepared,execute=args.execute)
    elif args.command=='status':
        result=status(args.prepared)
    elif args.command=='finish':
        explicit(args.execute)
        from cloud_tools import ensure
        ensure();result=finish(args.prepared,execute=True)
    else:
        explicit(args.execute)
        from cloud_tools import ensure
        ensure();cfg,_,_,_=verify_prepared(args.prepared);stop_compute_local(cfg,args.prepared)
        result={'status':'compute-stopped-state-retained'}
    print(json.dumps(result,indent=2))
    if args.command=='check' and not result['readyToStart']:sys.exit(2)

if __name__=='__main__':main()
