"""Destroy owned compute only after durable cloud evidence and local results."""
import copy
import json
from pathlib import Path
import shutil
import subprocess

from cloud_results.common import check_full,digest,gcloud,read,require,run,sha,write
from cloud_results.storage import Store
from cloud_results import package
import gcp
import smoke_cleanup


def validate_preservation(store,control):
    raw=control['rawPreservation']
    require(raw.get('status')=='verified-cloud-preservation','Missing complete cloud preservation')
    store.verify(raw['rawArchive'])
    store.verify(raw['sourceArchive'])
    hosts=control['privatePreservation']
    require(hosts.get('status')=='verified-cloud-readback' and set(hosts['hosts'])=={'host-1','host-2','host-3','host-4'},
            'Missing original private host archives')
    for host,row in hosts['hosts'].items():
        meta=store.metadata(row['object'],row['generation'])
        require(row['bucket']==store.bucket and int(meta['size'])==row['archiveBytes'] and meta['md5Hash']==row['md5Hash']
                and meta.get('metadata',{}).get('vcfhe-sha256')==row['sha256'],'Private cloud archive changed')


def remove_actor_admin(config,allocations,member):
    for row in allocations['accounts'].values():
        live=smoke_cleanup._cloud(['iam','service-accounts','describe',row['email'],'--project',config['project_id']],missing=True)
        if live is None:continue
        require(live['uniqueId']==row['uniqueId'],'Actor account was replaced')
        policy=gcloud('iam','service-accounts','get-iam-policy',row['email'],'--project',config['project_id'])
        if any(b['role']=='roles/iam.serviceAccountAdmin' and not b.get('condition') and member in b['members'] for b in policy.get('bindings',[])):
            run(['gcloud','iam','service-accounts','remove-iam-policy-binding',row['email'],'--project',config['project_id'],
                 '--member='+member,'--role=roles/iam.serviceAccountAdmin','--condition=None','--quiet'],stdout=subprocess.DEVNULL)


def destroy_copy(config,work,declarations,state,ownership,*,preserve_addresses):
    """A separate forensic-preserving TF copy, restricted to delete-only actions."""
    work=Path(work)
    require(not work.exists(),'Teardown work already exists. Inspect its retained plan, never silently regenerate it')
    for row in ownership:
        smoke_cleanup._require_live(config,row)
    updated=copy.deepcopy(declarations)
    for kind,rows in updated['resource'].items():
        for item in rows.values():
            if kind=='google_compute_instance':item['deletion_protection']=False
            if 'lifecycle' in item:item['lifecycle'].pop('prevent_destroy',None)
    work.mkdir(mode=0o700,parents=True)
    write(work/'main.tf.json',updated,new=True);write(work/'terraform.tfstate',state,new=True)
    if 'variable' in declarations:
        write(work/'terraform.tfvars.json',{'project_id':config['project_id']},new=True)
    if any(v.get('metadata_startup_script')=='${file("bootstrap.sh")}' for v in updated['resource'].get('google_compute_instance',{}).values()):
        shutil.copy2(Path(__file__).resolve().parents[1]/'bootstrap.sh',work/'bootstrap.sh')
    shutil.copy2(Path(__file__).resolve().parents[1]/'terraform.lock.hcl',work/'.terraform.lock.hcl')
    command=['terraform','-chdir='+str(work)]
    run(command+['init','-input=false']);run(command+['validate'])
    for address in preserve_addresses:run(command+['state','rm',address])
    for row in ownership:
        if row['type']=='google_compute_instance':
            live=smoke_cleanup._require_live(config,row)
            if live is not None:
                v=row['attributes']
                run(['gcloud','compute','instances','update',v['name'],'--zone',v['zone'],'--project',config['project_id'],
                     '--no-deletion-protection','--quiet'],stdout=subprocess.DEVNULL)
    run(command+['plan','-destroy','-input=false','-out=destroy.tfplan'])
    planned=json.loads(subprocess.check_output(command+['show','-json','destroy.tfplan'],text=True))
    allowed={
        r['type']+'.'+r['name'] for r in state['resources'] if r.get('mode')!='data'}
    data_addresses={'data.'+r['type']+'.'+r['name'] for r in state['resources'] if r.get('mode')=='data'}
    allowed-=set(preserve_addresses)
    for change in planned.get('resource_changes',[]):
        if change['address'] in data_addresses:
            require(change['change']['actions'] in (['read'],['no-op']), 'Unexpected data-source mutation')
            continue
        require(change['address'] in allowed and change['change']['actions'] in (['delete'],['no-op']),
                'Teardown plan contains an unexpected address or non-delete action')
    require({c['address'] for c in planned.get('resource_changes',[]) if c['address'] not in data_addresses}==allowed,
            'Teardown plan omits owned resources')
    for row in ownership:smoke_cleanup._require_live(config,row)
    run(command+['apply','-input=false','destroy.tfplan'])
    for row in ownership:
        if row['address'] in preserve_addresses:continue
        if row['type']=='google_service_account':
            from service_account_absence import confirm_absence
            confirm_absence(config,row,smoke_cleanup._require_live)
        else:require(smoke_cleanup._require_live(config,row) is None,'Owned resource remains after teardown')
    write(work/'completed.local.json',{'status':'passed','preserved':list(preserve_addresses),'originalStateEdited':False},new=True)


def complete(prepared,delivery,control):
    """No compute operation precedes every delivery, source and cloud check."""
    prepared=Path(prepared)
    local=package.verify_delivery_ready(delivery)
    config=check_full(control['config']);expected=read(prepared/'inner-config.local.json')
    require(config==expected,'Full teardown configuration differs from preparation')
    require(control['sourceManifestSha256']==sha(prepared/'source-manifest.local.json'),'Controller source receipt differs')
    require(control['protocolDeclarations']==gcp.terraform(config),'Protocol declarations changed')
    state=control['protocolTerraform']
    store=Store(control['rawPreservation']['rawArchive']['bucket'],config['project_id'])
    validate_preservation(store,control)
    ownership=control['ownershipPlan']['resources']
    for row in ownership:smoke_cleanup._require_live(config,row)
    remove_actor_admin(config,control['actorAccounts'],config['operator_principal'])
    destroy_copy(config,prepared/'protocol-teardown',control['protocolDeclarations'],state,ownership,
                 preserve_addresses=['google_artifact_registry_repository.images'])
    write(prepared/'protocol-teardown-complete.local.json',{'status':'passed',
        'localResultManifestSha256':local['manifestSha256'],'rawCloudEvidencePreserved':True,
        'imageRegistryPreserved':True,'participantKeysOrRequestsReplayed':False},new=True)


def controller_ownership(config,state):
    from cloud_results.infra import terraform
    import topology
    expected=terraform(config)['resource'];resources=[];seen=set()
    for item in state['resources']:
        if item.get('mode')=='data':continue
        kind,key=item['type'],item['name'];address=kind+'.'+key
        require(not item.get('module') and key in expected.get(kind,{}) and address not in seen
                and len(item.get('instances',[]))==1,'Unknown controller ownership')
        seen.add(address);instance=item['instances'][0]
        require('index_key' not in instance and not instance.get('deposed'),'Ambiguous controller instance')
        attrs=instance['attributes'];declaration=expected[kind][key]
        require(attrs.get('project',config['project_id'])==config['project_id'],'Foreign controller project')
        for field in ('name','zone','region','role','member','account_id'):
            value=declaration.get(field)
            if value is not None and '${' not in str(value):require(attrs.get(field)==value,'Controller identity changed')
        row={'address':address,'type':kind,'key':key,'attributes':attrs}
        args=smoke_cleanup._describe_args(row)
        if args:
            live=smoke_cleanup._cloud(smoke_cleanup._args(config,args))
            smoke_cleanup._check_identity(config,row,live)
            resources.append({**row,'describe':args,'identity':smoke_cleanup._identity(live)})
    require(seen=={kind+'.'+key for kind,rows in expected.items() for key in rows},'Incomplete controller TF ownership')
    vm=next(r for r in resources if r['type']=='google_compute_instance')
    live=smoke_cleanup._require_live(config,vm)
    require(live.get('labels',{}).get('experiment')==config['campaign'],'Foreign controller VM')
    args=['compute','disks','describe',vm['attributes']['name'],'--zone',vm['attributes']['zone']]
    boot=smoke_cleanup._cloud(smoke_cleanup._args(config,args))
    require(boot.get('users')==[live['selfLink']],'Controller boot disk is shared')
    resources.append({'address':'boot.controller','type':'google_compute_disk','key':'controller',
        'attributes':{'name':vm['attributes']['name'],'zone':vm['attributes']['zone']},
        'describe':args,'identity':smoke_cleanup._identity(boot)})
    return {'schema':'cloud-controller-ownership-v1','configSha256':digest(config),
            'terraformStateSha256':digest(state),'resources':resources}


def complete_controller(prepared,delivery):
    from cloud_results.infra import terraform,names
    from cloud_results.preservation import validate_bucket
    prepared=Path(prepared)
    local=package.verify_delivery_ready(delivery)
    report=read(prepared/'protocol-teardown-complete.local.json')
    require(report.get('status')=='passed' and report['localResultManifestSha256']==local['manifestSha256'],
            'Protocol teardown did not finish')
    config=read(prepared/'outer-config.local.json');declarations=read(prepared/'terraform/main.tf.json')
    require(declarations==terraform(config),'Controller declarations changed')
    ownership=read(prepared/'controller-ownership.local.json');state=read(prepared/'terraform/terraform.tfstate')
    require(ownership['configSha256']==digest(config) and ownership['terraformStateSha256']==digest(state),
            'Controller ownership changed')
    store=Store(names(config)['bucket'],config['project_id'])
    validate_bucket(config,store)
    # Revalidate objects and local result hashes immediately before the last VM
    # and controller IAM are removed. The evidence bucket itself is retained.
    control=read(prepared/'control-download.local.json');validate_preservation(store,control)
    package.verify_local(delivery)
    destroy_copy(config,prepared/'controller-teardown',declarations,state,ownership['resources'],
                 preserve_addresses=['google_storage_bucket.controller'])
    write(prepared/'controller-teardown-complete.local.json',{'status':'passed',
        'localResultManifestSha256':local['manifestSha256'],'evidenceBucketPreserved':True,
        'registryPreserved':True,'cloudStorageStillBillable':True},new=True)
