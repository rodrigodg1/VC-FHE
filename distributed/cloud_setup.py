"""Project preflight and scoped build resources. Never creates evaluation VMs."""
from datetime import datetime,timezone
import json
from pathlib import Path
import subprocess
import topology
import gcp
from cloud_tools import ensure

APIS=['compute.googleapis.com','artifactregistry.googleapis.com','cloudbuild.googleapis.com',
      'iam.googleapis.com','iamcredentials.googleapis.com','iap.googleapis.com','oslogin.googleapis.com',
      'storage.googleapis.com','logging.googleapis.com','cloudbilling.googleapis.com']

def gcloud(*args):
    return json.loads(subprocess.check_output(['gcloud',*map(str,args),'--format=json'],text=True))

def inspect(config,enable=False,login=False):
    ensure()
    account=subprocess.check_output(['gcloud','auth','list','--filter=status:ACTIVE','--format=value(account)'],text=True).strip()
    if not account and login:
        subprocess.run(['gcloud','auth','login','--update-adc'],check=True)
        account=subprocess.check_output(['gcloud','auth','list','--filter=status:ACTIVE','--format=value(account)'],text=True).strip()
    if not account:raise ValueError('Google login required. Run setup --login and complete the browser sign-in.')
    project=config['project_id']
    info=gcloud('projects','describe',project)
    if info.get('lifecycleState')!='ACTIVE':raise ValueError('project is not active')
    billing=gcloud('billing','projects','describe',project)
    if billing.get('billingEnabled') is not True:raise ValueError('Enable billing for this project in the Google Cloud console before continuing.')
    active=gcloud('services','list','--enabled','--project',project)
    enabled={v['config']['name'] for v in active}
    missing=sorted(set(APIS)-enabled)
    if missing:
        if not enable:raise ValueError('Missing APIs: '+', '.join(missing)+'. Use setup --enable-apis.')
        subprocess.run(['gcloud','services','enable',*missing,'--project',project,'--quiet'],check=True)
    physical=topology.hosts(config)
    global_quotas=gcloud('compute','project-info','describe','--project',project).get('quotas',[])
    wanted=sum(int(h['machine_type'].rsplit('-',1)[1]) for h in physical)
    def available(quotas,metric,needed):
        item=next((q for q in quotas if q['metric']==metric),None)
        if item is None or float(item['limit'])-float(item['usage'])<needed:
            raise ValueError(f'Insufficient {metric} quota for {needed}. Request the required quota in Google Cloud before launch.')
        return {'metric':metric,'limit':item['limit'],'usage':item['usage'],'required':needed}
    quota=[available(global_quotas,'CPUS_ALL_REGIONS',wanted)]
    for region in config['regions']:
        hosts=[h for h in physical if h['region']==region['name']]
        details=gcloud('compute','regions','describe',region['name'],'--project',project)
        requirements={}
        for host in hosts:
            metric='N2D_CPUS' if host['machine_type'].startswith('n2d-') else 'N2_CPUS'
            requirements[metric]=requirements.get(metric,0)+int(host['machine_type'].rsplit('-',1)[1])
        if region['name']==topology.builder_location(config)['name'] and config.get('image_build_backend','gce')=='gce':
            # The temporary builder runs before the evaluation hosts.
            requirements['N2_CPUS']=max(requirements.get('N2_CPUS',0),int(topology.builder_machine_type(config).rsplit('-',1)[1]))
        for metric,count in [*requirements.items(),('SSD_TOTAL_GB',len(hosts)*(config['boot_disk_gib']+config['state_disk_gib'])),('IN_USE_ADDRESSES',1)]:
            quota.append({'region':region['name'],**available(details['quotas'],metric,count)})
        zone=gcloud('compute','zones','describe',region['zone'],'--project',project)
        if zone.get('status')!='UP' or config['min_cpu_platform'] not in zone.get('availableCpuPlatforms',[]):
            raise ValueError('Required canonical CPU platform is unavailable in '+region['zone'])
        if (region['name']==topology.builder_location(config)['name'] and config.get('image_build_backend','gce')=='gce'
                and topology.builder_cpu_platform(config) not in zone.get('availableCpuPlatforms',[])):
            raise ValueError('Required builder CPU platform is unavailable in '+region['zone'])
    return {'schema':'vcfhe-gcp-setup-v1','verifiedAt':datetime.now(timezone.utc).isoformat(),
        'projectId':info['projectId'],'projectNumber':str(info['projectNumber']),
        'operatorPrincipal':('serviceAccount:' if account.endswith('.gserviceaccount.com') else 'user:')+account,
        'billingEnabled':True,'enabledApis':APIS,'quota':quota,
        'evaluationVmsCreated':False,'paidBuildStarted':False}

def ensure_build_resources(config,setup):
    """Call only after complete budget admission. No default-SA broad roles."""
    project=config['project_id'];region=topology.registry_region(config);repo=gcp.image_repository(config)
    def absent_or_json(args):
        result=subprocess.run(['gcloud',*args,'--project',project,'--format=json'],capture_output=True,text=True)
        if result.returncode==0:return json.loads(result.stdout)
        if 'NOT_FOUND' not in result.stderr and 'not found' not in result.stderr:raise ValueError(result.stderr)
        return None
    if absent_or_json(['artifacts','repositories','describe',repo,'--location',region]) is None:
        subprocess.run(['gcloud','artifacts','repositories','create',repo,'--location',region,'--project',project,
            '--repository-format=docker','--description=VC-FHE distributed evaluation images','--quiet'],check=True)
    account='vcfhe-builder-'+topology.digest({'project':project,'campaign':repo})[:8]
    email=account+'@'+project+'.iam.gserviceaccount.com'
    if absent_or_json(['iam','service-accounts','describe',email]) is None:
        subprocess.run(['gcloud','iam','service-accounts','create',account,'--project',project,
            '--display-name=VC-FHE image builder','--quiet'],check=True)
    subprocess.run(['gcloud','artifacts','repositories','add-iam-policy-binding',repo,'--location',region,'--project',project,
        '--member=serviceAccount:'+email,'--role=roles/artifactregistry.writer','--quiet'],check=True,stdout=subprocess.DEVNULL)
    subprocess.run(['gcloud','iam','service-accounts','add-iam-policy-binding',email,'--project',project,
        '--member='+setup['operatorPrincipal'],'--role=roles/iam.serviceAccountUser','--quiet'],check=True,stdout=subprocess.DEVNULL)
    bucket='gs://'+project+'-'+repo+'-build'
    found=absent_or_json(['storage','buckets','describe',bucket,'--raw'])
    if found is None:
        subprocess.run(['gcloud','storage','buckets','create',bucket,'--project',project,'--location',region,
            '--uniform-bucket-level-access','--public-access-prevention','--soft-delete-duration=0','--quiet'],check=True)
    elif str(found.get('projectNumber'))!=setup['projectNumber']:
        raise ValueError('Build bucket belongs to another project')
    # Cloud Build validates logsBucket metadata before accepting a build.
    # Grant that read permission only on this experiment's build bucket.
    for role in ['roles/storage.objectViewer','roles/storage.objectCreator','roles/storage.legacyBucketReader']:
        subprocess.run(['gcloud','storage','buckets','add-iam-policy-binding',bucket,'--project',project,
            '--member=serviceAccount:'+email,'--role='+role,'--quiet'],check=True,stdout=subprocess.DEVNULL)
    return {'builderServiceAccount':'projects/'+project+'/serviceAccounts/'+email,
            'bucket':bucket,'region':region,'repository':repo,'project':project}
