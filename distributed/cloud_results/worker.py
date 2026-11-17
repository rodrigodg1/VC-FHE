#!/usr/bin/env python3
"""Cloud-only controller entry. No invocation occurs during local preparation."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import traceback
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results.common import ROOT,VERSION,check_full,digest,gcloud,now,read,require,run,sha,write
from cloud_results.bundle import verify_extracted
from cloud_results.infra import actor_accounts,names
from cloud_results.preservation import preserve_hosts,archive_controller
from cloud_results.storage import Store
from cloud_results import package
import launch
import topology


class CloudCampaign(launch.Campaign):
    """Original workflows with off-path management provenance and retained NATs."""
    def __init__(self,*args,job,**kwargs):
        self.controller_job=job
        from cloud_results.completion_budget import original_admission
        with original_admission(args[0] if args else kwargs['config']):
            super().__init__(*args,**kwargs)
    def initialize(self):
        expected=actor_accounts(self.config)
        # inner_config is idempotent for an already selected controller principal.
        allocations=read(Path(self.controller_job['work'])/'job/actor-accounts.local.json')['accounts']
        require(set(allocations)==set(expected),'Missing preallocated fresh actor accounts')
        for key,value in expected.items():
            stored=allocations[key]
            live=gcloud('iam','service-accounts','describe',value['email'],'--project',self.config['project_id'])
            require(live['email']==stored['email']==value['email'] and live['uniqueId']==stored['uniqueId'],
                    'Preallocated actor account was replaced')
        super().initialize()
        dependency_proof=Path(self.controller_job['work'])/'controller-js-proof.local.json'
        if dependency_proof.exists():
            write(self.run/'distributed/controller-js-dependencies.json',read(dependency_proof),new=True)
        directory=self.run/'terraform'
        run(['terraform','-chdir='+str(directory),'init','-input=false'])
        for key,stored in allocations.items():
            run(['terraform','-chdir='+str(directory),'import','-input=false','google_service_account.'+key,stored['name']])
        write(self.run/'distributed/cloud-controller-source.json',{
            'schema':VERSION,'sourceManifestSha256':self.controller_job['sourceManifestSha256'],
            'controllerSources':self.controller_job['controllerSources'],
            'offPathController':True,'protocolRoles':21,'protocolHosts':4,
            'validationLocation':'cloud','nativeImageRebuilt':False,
            'managementChanges':['fresh empty SA imports','stop without NAT destruction','cloud node-state preservation','bounded evaluation package export']},new=True)
    def collect(self):
        from cloud_results.owner_materials import collect as collect_public_owner_witnesses
        collect_public_owner_witnesses(self)
        super().collect()
        self.private_preservation=preserve_hosts(self)
    def kms(self):
        from cloud_results.public_tls import readable_public_exchange
        with readable_public_exchange(self):
            return super().kms()
    def enrollment(self):
        super().enrollment()
        proof=self.record.get('nativeLayerReuse')
        if proof is not None:
            expected=proof['expectedNativeBinaries']['kms-campaign']
            require(len(self.identities)==21 and all(v['binarySha256']==expected for v in self.identities.values()),
                    'Enrolled native binary differs from the already published and reused build')
            write(self.run/'distributed/native-reuse-validation.json',{'status':'passed',
                'enrolledRoles':21,'binarySha256':expected,'nativeRecompiled':False,
                'sourceImageSha256':proof['sourceImageSha256']},new=True)
    def stop(self):
        # Stop compute after collection/failure. No network, disk, IAM or VM
        # destruction happens before the separately verified local delivery.
        outcomes=[]
        for host,remote in self.remotes.items():
            from smoke_cleanup import _cloud
            for attempt in range(3):
                try:
                    args=['compute','instances','describe',remote.host['name'],'--zone',remote.host['zone'],
                          '--project',self.config['project_id']]
                    live=_cloud(args,missing=True)
                    if live is not None:
                        require(live.get('labels',{}).get('experiment')==self.config['campaign'],'Foreign VM stop refused')
                        if live.get('status')!='TERMINATED':
                            run(['gcloud','compute','instances','stop',remote.host['name'],'--zone',remote.host['zone'],
                                 '--project',self.config['project_id'],'--quiet'],stdout=subprocess.DEVNULL)
                        require(_cloud(args)['status']=='TERMINATED','Compute stop not confirmed')
                    outcomes.append({'host':host,'stopped':True,'absent':live is None})
                    break
                except (subprocess.CalledProcessError,ValueError):
                    if attempt==2:outcomes.append({'host':host,'stopped':False})
                    else:time.sleep(5)
        write(self.run/'compute-stop.local.json',{'hosts':outcomes,'stateDisksPreserved':True,
            'natPreservedUntilLocalDelivery':True,'vmRuntimeBoundSeconds':self.config['maximum_vm_runtime_seconds']})
        require(all(v['stopped'] for v in outcomes),'Compute stop requires inspection')


def restore_cache(input_root,manifest):
    from cloud_results.source_cache import restore
    source=input_root/'source-cache'/manifest['cacheDirectory']
    target=ROOT/'threshold-kms/.cache'/manifest['cacheDirectory']
    return restore(source,target)


def execute(input_root):
    input_root=Path(input_root);manifest=verify_extracted(input_root)
    config=check_full(read(input_root/'job/config.local.json'));quote=read(input_root/'job/quote.local.json')
    require(digest(config)==manifest['innerConfigSha256'],'Controller configuration changed')
    from cloud_tools import ensure
    # Use the already verified plotting venv to expose NumPy to IAP, avoiding
    # repeated Python byte copies during large cloud-to-cloud evidence reads.
    sys.path.insert(0,str(ROOT/'threshold-kms/postprocess'))
    from refresh import plotting_python
    os.environ['CLOUDSDK_PYTHON']=str(plotting_python())
    os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
    ensure()
    import cloud_setup
    setup=cloud_setup.inspect(config,enable=False)
    require(setup['operatorPrincipal']==config['operator_principal'],'Controller metadata identity differs')
    from storage_preflight import check_full_controller_storage
    check_full_controller_storage(config,ROOT/'threshold-kms/runs'/manifest['runName'])
    restore_cache(input_root,manifest)
    job={'work':str(input_root),'config':config,'jobId':manifest['jobId'],
         'bucket':names(config)['bucket'],'sourceManifestSha256':sha(input_root/'source-manifest.json'),
         'controllerSources':manifest['controllerSources']}
    store=Store(job['bucket'],config['project_id'])
    source=read(input_root/'job/source-archive.local.json')
    source_path=input_root.parent/'controller-source.tar.gz'
    require(sha(source_path)==source['sha256'] and source_path.stat().st_size==source['bytes'],
            'Frozen controller upload differs')
    job['sourceObject']=store.upload(source_path,'runs/'+job['jobId']+'/controller-source.tar.gz')
    store.download(job['sourceObject'],input_root.parent/'controller-source.readback.tar.gz')
    target=ROOT/'threshold-kms/runs'/manifest['runName']
    worker=None
    try:
        worker=CloudCampaign(config,quote,input_root/'build',target,job=job)
        from cloud_results.completion_budget import original_admission
        with original_admission(config):
            result=worker.run_all()
        require(result.get('status')=='results-ready',
                'Validated standalone derivation did not finish')
        base=ROOT/'threshold-kms/composites'/(target.name+'-distributed')
        preservation=archive_controller(target,base,job,worker.private_preservation)
        output=input_root/'result-delivery'
        exported=package.build_results(target,base,output,compact_preservation(preservation))
        obj=store.upload(Path(exported['archive']),'runs/'+job['jobId']+'/results.tar')
        # Exported small package itself also gets a complete cloud readback.
        store.download(obj,output/'results.readback.tar',maximum=package.MAX_PACKAGE_BYTES)
        control={'schema':'cloud-full-control-v1','config':config,
            'protocolTerraform':read(target/'terraform/terraform.tfstate'),
            'protocolDeclarations':read(target/'terraform/main.tf.json'),
            'actorAccounts':read(input_root/'job/actor-accounts.local.json'),
            'ownershipPlan':read(target/'preservation/ownership.local.json'),
            'privatePreservation':compact_hosts(worker.private_preservation),'rawPreservation':compact_preservation(preservation),
            'sourceManifestSha256':job['sourceManifestSha256']}
        write(input_root/'control.local.json',control,new=True)
        terminal={'schema':VERSION,'status':'awaiting-verified-local-delivery','createdAt':now(),
            'results':{**obj,'manifestSha256':exported['manifestSha256']},
            'control':store.upload(input_root/'control.local.json','runs/'+job['jobId']+'/control.json'),
            'rawPreservation':compact_preservation(preservation),'protocolOperationsCompleted':True,'computeStopped':True,
            'teardownPermitted':False,'smokeStarted':False,'fullCampaignCompleted':True}
        write(input_root/'terminal.local.json',terminal,new=True)
        final=store.upload(input_root/'terminal.local.json','runs/'+job['jobId']+'/terminal.json')
        write(input_root/'terminal-object.local.json',final,new=True)
        return terminal
    except BaseException as error:
        # run_all owns its protocol stop. This also covers publication/export
        # failures without re-entering any protocol stage.
        if worker is not None and worker.provisioned:worker.stop()
        traceback.print_exc()
        failed={'schema':VERSION,'status':'failed-preserved','createdAt':now(),'errorType':type(error).__name__,
            'error':str(error),'teardownPermitted':False,'protocolReplayed':False,
            'instruction':'Inspect preserved controller disk and protocol disks. Never restart the campaign or repeat a release.'}
        write(input_root/'failure.local.json',failed)
        try:
            store.upload(input_root/'failure.local.json','runs/'+job['jobId']+'/failure.json')
        except Exception:
            # The controller disk remains authoritative if storage is unavailable.
            traceback.print_exc()
        raise


def compact_hosts(value):
    result={k:v for k,v in value.items() if k!='hosts'}
    result['hosts']={host:{k:v for k,v in row.items() if k!='files'} for host,row in value['hosts'].items()}
    return result


def compact_preservation(value):
    return {**value,'privateHosts':compact_hosts(value['privateHosts'])}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    args=parser.parse_args()
    execute(args.input.resolve())
