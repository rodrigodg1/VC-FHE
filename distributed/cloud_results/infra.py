"""Offline controller declarations and explicit execution-time allocation."""
import copy
import json
from pathlib import Path
import subprocess
import time
from cloud_results.common import check_full,digest,gcloud,require,run,write
import gcp
import topology


def names(config):
    key=digest({'project':config['project_id'],'campaign':config['campaign'],'purpose':'cloud-results'})[:12]
    return {'controller':config['campaign']+'-controller','account':'vcfhe-ctrl-'+key,
            'bucket':'vcfhe-evidence-'+digest({'project':config['project_id'],'campaign':config['campaign'],'purpose':'complete-results'})[:20]}


def inner_config(config):
    result=copy.deepcopy(check_full(config))
    result['operator_principal']='serviceAccount:'+names(config)['account']+'@'+config['project_id']+'.iam.gserviceaccount.com'
    return result


def actor_accounts(config):
    config=inner_config(config)
    resources=gcp.terraform(config)['resource']['google_service_account']
    return {key:{'accountId':value['account_id'],'email':value['account_id']+'@'+config['project_id']+'.iam.gserviceaccount.com'}
            for key,value in resources.items()}


def terraform(config):
    """Separate administration VM, never co-located with a cryptographic role."""
    check_full(config);n=names(config);project=config['project_id'];zone=config['regions'][0]['zone']
    region=config['regions'][0]['name'];outer=config['operator_principal']
    require(outer.startswith(('user:','serviceAccount:')),'Authenticated outer operator required')
    ref=lambda kind,field='id':'${'+kind+'.controller.'+field+'}'
    account='serviceAccount:'+ref('google_service_account','email')
    resources={
      'google_service_account':{'controller':{'account_id':n['account'],'display_name':n['controller']}},
      'google_compute_network':{'controller':{'name':n['controller'],'auto_create_subnetworks':False}},
      'google_compute_subnetwork':{'controller':{'name':n['controller'],'region':region,'network':ref('google_compute_network'),'ip_cidr_range':'10.91.0.0/24'}},
      'google_compute_firewall':{'controller':{'name':n['controller']+'-iap','network':ref('google_compute_network'),
        'source_ranges':['35.235.240.0/20'],'target_service_accounts':[ref('google_service_account','email')],
        'allow':[{'protocol':'tcp','ports':['22']}]}},
      'google_storage_bucket':{'controller':{'name':n['bucket'],'location':region,'storage_class':'STANDARD',
        'uniform_bucket_level_access':True,'public_access_prevention':'enforced','force_destroy':False,
        'labels':{'vcfhe-purpose':'complete-results','vcfhe-campaign':config['campaign']},'lifecycle':{'prevent_destroy':True}}},
      'google_storage_bucket_iam_member':{'controller':{'bucket':ref('google_storage_bucket','name'),
        'role':'roles/storage.admin','member':account}},
      'google_compute_instance':{'controller':{'name':n['controller'],'zone':zone,'machine_type':'e2-standard-2',
        'deletion_protection':True,'allow_stopping_for_update':False,
        'boot_disk':{'initialize_params':{'image':'${data.google_compute_image.debian.self_link}','size':200,'type':'pd-balanced'}},
        'network_interface':[{'subnetwork':ref('google_compute_subnetwork'),'access_config':[{}]}],
        'service_account':{'email':ref('google_service_account','email'),'scopes':['cloud-platform']},
        'metadata':{'enable-oslogin':'TRUE','block-project-ssh-keys':'TRUE','vcfhe-controller':n['controller']},
        'metadata_startup_script':'#!/bin/bash\nset -euo pipefail\napt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=5 update\napt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=5 install -y python3 python3-venv ca-certificates curl git openssh-client tar\ninstall -d -m0700 /srv/vcfhe-controller\n',
        'labels':{'experiment':config['campaign'],'purpose':'results-controller'},
        'scheduling':{'automatic_restart':False,'instance_termination_action':'STOP',
          'max_run_duration':{'seconds':config.get('maximum_vm_runtime_seconds',50400)+7200}}}},
      'google_compute_instance_iam_member':{'controller':{'project':project,'zone':zone,'instance_name':ref('google_compute_instance','name'),
        'role':'roles/compute.osAdminLogin','member':outer}},
      'google_iap_tunnel_instance_iam_member':{'controller':{'project':project,'zone':zone,'instance':ref('google_compute_instance','name'),
        'role':'roles/iap.tunnelResourceAccessor','member':outer}},
      'google_service_account_iam_member':{'controller':{'service_account_id':ref('google_service_account'),
        'role':'roles/iam.serviceAccountUser','member':outer}},
    }
    # No project Owner, project IAM administrator, service-account key creation,
    # or project-wide storage administrator permission is granted.
    resources['google_project_iam_member']={}
    for label,role in [('compute','roles/compute.admin'),('iap','roles/iap.admin'),
                       ('services','roles/serviceusage.serviceUsageConsumer'),('accounts','roles/iam.serviceAccountViewer')]:
        resources['google_project_iam_member'][label]={'project':project,'role':role,'member':account}
    resources['google_artifact_registry_repository_iam_member']={'controller':{
        'project':project,'location':topology.registry_region(config),'repository':gcp.image_repository(config),
        'role':'roles/artifactregistry.admin','member':account}}
    resources['google_compute_instance']['controller']['depends_on']=[
        'google_project_iam_member.'+k for k in resources['google_project_iam_member']]
    resources['google_compute_instance']['controller']['depends_on']+=['google_service_account_iam_member.controller','google_storage_bucket_iam_member.controller']
    return {'terraform':{'required_version':'>=1.9.8,<2.0.0','required_providers':{'google':{'source':'hashicorp/google','version':'6.50.0'}}},
      'provider':{'google':{'project':project}},'data':{'google_compute_image':{'debian':{'family':'debian-12','project':'debian-cloud'}}},
      'resource':resources,'output':{'controller':{'value':{'name':n['controller'],'zone':zone,'bucket':n['bucket'],
        'account':ref('google_service_account','email'),'instanceId':ref('google_compute_instance','instance_id')}}}}


def wait_account(config, email, created, *, timeout=180):
    """Retry only a newly created account's read during IAM propagation."""
    deadline=time.monotonic()+timeout
    while True:
        args=['gcloud','iam','service-accounts','describe',email,'--project',config['project_id'],'--format=json']
        result=subprocess.run(args,capture_output=True,text=True)
        if result.returncode==0:
            live=json.loads(result.stdout)
            require(live.get('email')==created['email']==email
                    and live.get('uniqueId')==created['uniqueId'], 'Created actor account identity changed')
            return live
        if 'NOT_FOUND' not in result.stderr or time.monotonic()>=deadline:
            raise subprocess.CalledProcessError(result.returncode,args,result.stdout,result.stderr)
        time.sleep(min(5,max(0,deadline-time.monotonic())))


def allocate_accounts(config, work):
    """Create once, persist the API identity, then wait for public IAM reads."""
    expected=actor_accounts(config);project=config['project_id'];controller=inner_config(config)['operator_principal']
    current=gcloud('iam','service-accounts','list','--project',project)
    require(not ({v['email'] for v in current}&{v['email'] for v in expected.values()}),
            'Actor service account already exists. Inspect earlier allocation, never reuse it silently')
    result={'schema':'fresh-cloud-actor-accounts-v1','accounts':{},'protocolOperations':0}
    write(Path(work)/'actor-accounts.local.json',result,new=True)
    for key,value in expected.items():
        live=gcloud('iam','service-accounts','create',value['accountId'],'--project',project,
                    '--display-name='+config['campaign']+' '+key,'--quiet')
        require(live.get('email')==value['email'] and str(live.get('uniqueId','')).isdecimal(),
                'New actor creation response is incomplete')
        result['accounts'][key]={**value,'uniqueId':live['uniqueId'],'name':live['name']}
        write(Path(work)/'actor-accounts.local.json',result)
        wait_account(config,value['email'],live)
        # Resource-level permission on these four fresh accounts, not on foreign SAs.
        run(['gcloud','iam','service-accounts','add-iam-policy-binding',value['email'],'--project',project,
             '--member='+controller,'--role=roles/iam.serviceAccountAdmin','--quiet'],stdout=subprocess.DEVNULL)
    return result
