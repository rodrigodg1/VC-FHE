"""Explicit temporary GCE builder, independent of Cloud Build high-CPU quotas."""
from datetime import datetime,timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import time
import budget
import cloud_build
import cloud_setup
import image
import image_recovery
from remote import Remote
import topology

BUILDER_SECONDS=14400
ATTEMPT_USD=Decimal('2.00')

def read_probe(remote,args,json_result=False):
    """Retry bounded reads only. Never restart an upload or compilation job."""
    for attempt in range(3):
        try:
            options={'timeout':40}
            if json_result:options.update(stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            result=remote.run(args,**options)
            return json.loads(result.stdout) if json_result else result
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired,json.JSONDecodeError):
            if attempt==2:raise
            time.sleep(2*(attempt+1))

def builder_price_ceiling(config,quote):
    location=topology.builder_location(config)
    evidence=quote.get('builderRateEvidence')
    if evidence is not None:
        if (evidence.get('region')!=location['name']
                or evidence.get('machineType')!=topology.builder_machine_type(config)
                or evidence.get('cpuPlatform')!=topology.builder_cpu_platform(config)
                or evidence.get('ceilingMachineType')!='n2-standard-8'):
            raise ValueError('builder price evidence does not match the selected N2 builder')
        compute=budget.amount(evidence['computeCeilingHourlyUsd']);disk=budget.amount(evidence['diskHourlyUsd'])
        if compute<=0 or disk<=0:raise ValueError('positive independent builder prices required')
        return (compute+disk+Decimal('0.005'))*4
    if any(host['machine_type'].startswith('n2d-') for host in topology.hosts(config)):
        raise ValueError('N2D hosts require independent N2 builder price evidence')
    first=next((v for v in quote.get('rateEvidence',[]) if v['region']==location['name']),None)
    if first is None:raise ValueError('builder requires current regional catalog price evidence')
    return (budget.amount(first['computeHourlyUsd'])*2+budget.amount(first['diskHourlyUsd'])/2+Decimal('0.005'))*4

def terraform(config,setup,resources):
    location=topology.builder_location(config)
    name=config['campaign']+'-image-builder';zone=location['zone'];region=location['name']
    principal=setup['operatorPrincipal']
    account=resources['builderServiceAccount'].split('/serviceAccounts/')[1]
    ref=lambda kind,field='id':'${'+kind+'.builder.'+field+'}'
    return {'terraform':{'required_version':'>= 1.9.8, < 2.0.0',
        'required_providers':{'google':{'source':'hashicorp/google','version':'6.50.0'}}},
        'provider':{'google':{'project':config['project_id']}},
        'data':{'google_compute_image':{'debian':{'family':'debian-12','project':'debian-cloud'}}},
        'resource':{
            'google_compute_network':{'builder':{'name':name,'auto_create_subnetworks':False}},
            'google_compute_subnetwork':{'builder':{'name':name,'region':region,'network':ref('google_compute_network'),
                'ip_cidr_range':'10.90.0.0/24'}},
            'google_compute_firewall':{'builder':{'name':name+'-iap','network':ref('google_compute_network'),
                'source_ranges':['35.235.240.0/20'],'target_service_accounts':[account],
                'allow':[{'protocol':'tcp','ports':['22']}]}},
            'google_compute_instance':{'builder':{'name':name,'zone':zone,'machine_type':topology.builder_machine_type(config),
                'min_cpu_platform':topology.builder_cpu_platform(config),
                'boot_disk':{'initialize_params':{'image':'${data.google_compute_image.debian.self_link}',
                    'size':100,'type':'pd-balanced'}},
                'network_interface':[{'subnetwork':ref('google_compute_subnetwork'),'access_config':[{}]}],
                'service_account':{'email':account,'scopes':['cloud-platform']},
                'metadata':{'enable-oslogin':'TRUE','block-project-ssh-keys':'TRUE'},
                'metadata_startup_script':(image.HERE/'build-bootstrap.sh').read_text(),
                'labels':{'experiment':config['campaign'],'purpose':'temporary-image-builder'},
                'scheduling':{'automatic_restart':False,'instance_termination_action':'STOP',
                              'max_run_duration':{'seconds':BUILDER_SECONDS}}}},
            'google_compute_instance_iam_member':{'builder':{'project':config['project_id'],'zone':zone,
                'instance_name':ref('google_compute_instance','name'),'role':'roles/compute.osAdminLogin','member':principal}},
            'google_iap_tunnel_instance_iam_member':{'builder':{'project':config['project_id'],'zone':zone,
                'instance':ref('google_compute_instance','name'),'role':'roles/iap.tunnelResourceAccessor','member':principal}}}}

def reserve(config,quote,ledger,cloud_builds):
    """Bound attempts cumulatively. Unknown remote outcomes cannot be refunded."""
    records=json.loads(ledger.read_text()) if ledger.exists() else {'reservations':[]}
    image_recovery.no_active(cloud_builds)
    prior=Decimal(0)
    for item in cloud_builds:
        if item['status'] in ['WORKING','QUEUED','PENDING']:raise ValueError('A cloud build is still active')
        if item.get('startTime') and item.get('finishTime'):
            seconds=(datetime.fromisoformat(item['finishTime'].replace('Z','+00:00'))-
                     datetime.fromisoformat(item['startTime'].replace('Z','+00:00'))).total_seconds()
            prior+=Decimal(str(seconds))*cloud_build.BUILD_USD_PER_MINUTE/60
    relevant=[r for r in records['reservations'] if r['project']==config['project_id'] and r['campaign']==config['campaign']]
    total=sum((Decimal(r['upperUsd']) for r in relevant),prior)+ATTEMPT_USD+Decimal('0.50')
    if total>budget.amount(quote['build_registry']):raise ValueError('Cumulative image-build allowance exhausted')
    records['reservations'].append({'project':config['project_id'],'campaign':config['campaign'],
        'upperUsd':str(ATTEMPT_USD),'createdAt':datetime.now(timezone.utc).isoformat(),
        'scope':'temporary GCE builder, at most four hours. Conservative reservation.'})
    ledger.parent.mkdir(parents=True,exist_ok=True)
    pending=ledger.with_suffix('.pending')
    with pending.open('x') as stream:json.dump(records,stream,indent=2)
    pending.replace(ledger)

def build(config,quote,directory,_recovering=False):
    cost=budget.assess(config,quote)
    if cost['status']!='admit':raise ValueError('complete campaign exceeds USD 50')
    setup=cloud_setup.inspect(config,enable=True)
    location=topology.builder_location(config)
    # Keep the standard-8 ceiling for either permitted builder. Highmem-4
    # has the same 32 GiB RAM and fewer vCPUs in the same N2 price schedule.
    upper=builder_price_ceiling(config,quote)
    if upper>ATTEMPT_USD:raise ValueError('Current four-hour builder price exceeds the conservative attempt reservation')
    directory=Path(directory).resolve()
    if not directory.exists():image.prepare(image.ROOT/'threshold-kms/.cache',directory)
    image_recovery.require_no_pending(directory)
    if (directory/'ambiguous-cloud-build-submission.json').exists():
        raise ValueError('A prior cloud build has an unknown outcome. Inspect it before a GCE attempt.')
    record=json.loads((directory/'distributed-source.json').read_text());image.verify_inputs(directory,record)
    if record['localSource']!=image.deployment.campaign_module().source_manifest():raise ValueError('stale native source context')
    image.verify_adapter_sources(record)
    receipt=directory/'published-image.json'
    if receipt.exists():
        result=json.loads(receipt.read_text())
        if result['sourceSha256']!=topology.digest(record):raise ValueError('stale image receipt')
        prior_work=directory/'gce-builder'
        if (prior_work/'cleanup.local.json').exists() and json.loads((prior_work/'cleanup.local.json').read_text()).get('status')!='passed':
            raise ValueError('Prior builder cleanup did not complete. Inspect it before reuse.')
        missing=image_recovery.missing_images(config,result)
        if not missing:return result
        if _recovering:raise ValueError('Newly rebuilt images are unavailable. Inspect the build without retrying compilation.')
        image_recovery.require_success(result,topology.digest(record))
        if result.get('builder')=='temporary GCE VM' and not prior_work.is_dir():
            raise ValueError('Prior GCE state is missing. Cannot prove safe builder replacement.')
        cleanup=image_recovery.prove_gce_cleanup(config,prior_work if prior_work.exists() else None)
        history=cloud_setup.gcloud('builds','list','--region',topology.registry_region(config),
            '--project',config['project_id'],'--filter=tags:vcfhe-'+config['campaign'])
        image_recovery.no_active(history)
        image_recovery.archive(directory,['published-image.json','gce-builder','cloud-build-submission.json',
            'cloud-build-result.json','cloudbuild.json','cloud-build-upload'],missing,cleanup=cleanup)
        return build(config,quote,directory,_recovering=True)
    work=directory/'gce-builder'
    if work.exists():raise ValueError('Prior builder state retained. Inspect it before creating a new attempt.')
    if (directory/'cloud-build-submission.json').exists():
        raise ValueError('A prior Cloud Build submission is retained. Inspect it with that backend before creating a GCE attempt.')
    resources=cloud_setup.ensure_build_resources(config,setup)
    history=cloud_setup.gcloud('builds','list','--region',resources['region'],'--project',config['project_id'],
                               '--filter=tags:vcfhe-'+config['campaign'])
    reserve(config,quote,image.HERE/'generated/build-cost-ledger.local.json',history)
    work.mkdir();tf=work/'terraform';tf.mkdir()
    (tf/'main.tf.json').write_text(json.dumps(terraform(config,setup,resources),indent=2)+'\n')
    shutil.copy2(image.HERE/'terraform.lock.hcl',tf/'.terraform.lock.hcl')
    command=['terraform','-chdir='+str(tf)]
    for args in [['init','-input=false'],['validate'],['plan','-input=false','-out=builder.tfplan']]:
        subprocess.run(command+args,check=True)
    host={'id':'image-builder','name':config['campaign']+'-image-builder','zone':location['zone']}
    remote=Remote(config,host);provisioned=False;published=None
    try:
        provisioned=True
        subprocess.run(command+['apply','-input=false','builder.tfplan'],check=True)
        deadline=time.monotonic()+1200
        while True:
            try:
                remote.run(['sudo','docker','info'],timeout=40,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);break
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
                if time.monotonic()>deadline:raise
                time.sleep(10)
        # Upload only the public build closure, excluding private Terraform
        # state, account reports, local configurations and credentials.
        upload=work/'upload';upload.mkdir()
        for name in ['app','upstream']:shutil.copytree(directory/name,upload/name)
        for name in ['Dockerfile','distributed-source.json']:shutil.copy2(directory/name,upload/name)
        remote.upload(upload,'/srv/vcfhe-build/context')
        besu=cloud_build.docker_manifest('hyperledger/besu','25.3.0')
        spec,tag,besu_tag=cloud_build.specification(config,record,resources,besu)
        registry=resources['region']+'-docker.pkg.dev'
        script=['#!/bin/bash','set -euo pipefail',
            "trap 'status=$?; printf \"{\\\"exitCode\\\":%s}\\n\" \"$status\" > /srv/vcfhe-build/status.json' EXIT",
            'mkdir /srv/vcfhe-build/start-once',
            'cd /srv/vcfhe-build/context',
            "registry_login() { curl -fsS -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | python3 -c 'import json,sys;print(json.load(sys.stdin)[\"access_token\"])' | docker login -u oauth2accesstoken --password-stdin "+shlex.quote(registry)+'; }',
            'registry_login','export DOCKER_BUILDKIT=1',
            spec['steps'][0]['args'][1].replace('\ndocker push ','\nregistry_login\ndocker push ')]
        for step in spec['steps'][1:]:script+=['registry_login',shlex.join(['docker',*step['args']])]
        for value in [tag,besu_tag]:script+=['registry_login',shlex.join(['docker','push',value])]
        script += ["python3 - <<'PY'",'import json,subprocess',f'tags={repr([tag,besu_tag])}',
            'result={}',
            'for tag in tags:',
            " digests=json.loads(subprocess.check_output(['docker','image','inspect',tag,'--format','{{json .RepoDigests}}']))",
            " prefix=tag.rsplit(':',1)[0]+'@sha256:'",
            ' matches=[d for d in digests if d.startswith(prefix)]',
            " assert len(matches)==1,'immutable image identity missing'",
            ' result[tag]=matches[0]',
            "open('/srv/vcfhe-build/image-result.json','w').write(json.dumps(result))",'PY']
        job=work/'job';job.mkdir();(job/'build.sh').write_text('\n'.join(script)+'\n')
        subprocess.run(['bash','-n',str(job/'build.sh')],check=True)
        remote.upload(job,'/srv/vcfhe-build/job')
        remote.shell("sudo sh -c 'nohup bash /srv/vcfhe-build/job/build.sh > /srv/vcfhe-build/build.log 2>&1 </dev/null &' ")
        deadline=time.monotonic()+BUILDER_SECONDS-1200
        while True:
            read_probe(remote,['sudo','tail','-n','8','/srv/vcfhe-build/build.log'])
            status=read_probe(remote,['sudo','python3','-c',
                "from pathlib import Path; p=Path('/srv/vcfhe-build/status.json'); print(p.read_text() if p.is_file() else 'null')"],json_result=True)
            if status is not None:
                if status['exitCode']!=0:raise ValueError('native image compilation failed')
                break
            if time.monotonic()>deadline:raise ValueError('image builder duration exhausted')
            time.sleep(30)
        result=read_probe(remote,['sudo','cat','/srv/vcfhe-build/image-result.json'],json_result=True)
        published={'digest':result[tag],'besuDigest':result[besu_tag],'besuSource':besu,
            'sourceSha256':topology.digest(record),'budget':cost,'builder':'temporary GCE VM',
            'builderMachineType':topology.builder_machine_type(config),
            'builderCpuPlatform':topology.builder_cpu_platform(config),
            'builderZone':location['zone'],'builderRegion':location['name'],
            'buildStatus':'SUCCESS','maximumBuilderSeconds':BUILDER_SECONDS}
        receipt.write_text(json.dumps(published,indent=2)+'\n')
        return published
    finally:
        if provisioned:
            try:
                with (work/'build.log').open('w') as log:
                    remote.run(['sudo','cat','/srv/vcfhe-build/build.log'],stdout=log,stderr=subprocess.STDOUT,timeout=60)
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired):pass
            # Only disposable build resources exist in this Terraform state.
            # No KMS, owner identity, chain or release counter is stored here.
            try:
                subprocess.run(command+['destroy','-auto-approve','-input=false'],check=True)
                cleanup=image_recovery.prove_gce_cleanup(config,work)
                image_recovery.write(work/'cleanup.local.json',cleanup)
                if receipt.exists():
                    stored=json.loads(receipt.read_text())
                    stored['cleanup']={'status':'passed','reportSha256':hashlib.sha256((work/'cleanup.local.json').read_bytes()).hexdigest()}
                    image_recovery.write(receipt,stored)
                    if published is not None:published.update(stored)
            except BaseException as error:
                image_recovery.write(work/'cleanup.local.json',{'schema':'vcfhe-gce-image-cleanup-v1',
                    'status':'failed','errorType':type(error).__name__,
                    'instruction':'Inspect retained Terraform state. Do not automatically repeat the build.'})
                raise
