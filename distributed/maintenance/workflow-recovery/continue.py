#!/usr/bin/env python3
"""Explicit workflows-only continuation after a verified, unused release prefix.

This route never calls initialize, provision, enrollment, policy, kms or roles.
Frozen sources, the image and the failed predecessor are not overwritten.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import threading
import time
import traceback
import types


def main(input_root, segment):
    input_root=Path(input_root).resolve();segment=Path(segment).resolve()
    root=input_root/'repository/VC-FHE';sys.path.insert(0,str(root/'distributed'))
    os.environ['CLOUDSDK_PYTHON']=sys.executable
    os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
    from cloud_tools import ensure
    ensure()
    from cloud_results.common import read,write,sha,require,now,VERSION
    from cloud_results.worker import CloudCampaign,compact_preservation,compact_hosts
    from cloud_results.storage import Store
    from cloud_results import package
    from transforms import retention_overlay
    from analysis import derive
    import topology
    import deployment

    continuation=segment/'distributed/workflow-continuation'
    prepared=read(continuation/'prepared.json');manifest=read(continuation/'manifest.json')
    require(prepared['status']=='prepared-not-started' and prepared['newRun']==str(segment), 'Wrong prepared continuation')
    require(prepared['manifestSha256']==sha(continuation/'manifest.json'), 'Changed continuation manifest')
    require(prepared['newCampaignConfigSha256']==sha(continuation/'config.json'), 'Changed continuation config')
    require(manifest['profile']=='distributed-same-keyset-workflows-only-v1', 'Unsupported recovery profile')
    tag=manifest['continuationTag']
    require(tag in ('workflows-c1','workflows-c2','workflows-c3'),'Unsupported continuation identity')
    for name,row in manifest['overlays'].items():
        require(sha(continuation/name)==row['overlaySha256'], 'Execution overlay changed')
    require(not (continuation/'start-intent.json').exists(), 'Continuation already requested. Inspect, never restart blindly')
    cfg=read(input_root/'job/config.local.json');job=prepared['job'];quote=read(input_root/'job/quote.local.json')
    worker=CloudCampaign(cfg,quote,input_root/'build',segment.with_name(segment.name+'-unused'),job=job)
    worker.run=segment;worker.provisioned=True
    worker.identities=read(segment/'distributed/public-identities.json')
    worker.datasets=read(segment/'distributed/controller-inputs.json')['datasets']
    worker.state=read(segment/'launch-state.json')
    require(worker.state['status']=='workflow-continuation-prepared','Unexpected continuation state')
    worker.plan=topology.plan(cfg);worker.nodes={n['id']:n for n in worker.plan['nodes']}
    for node in worker.nodes.values():
        if node['role']!='validator':node['state_directory']=prepared['newBase']+'/'+node['id']
    worker.compose={h['id']:read(segment/'compose'/h['id']/'compose.json') for h in worker.plan['hosts']}
    def compose_args(self,node,*args):
        host=self.nodes[node]['host']
        return ['sudo','docker','compose','-f',self.base+'/'+host+'/workflow-continuation-compose/compose.json',*args]
    worker.compose_args=types.MethodType(compose_args,worker)
    # The unchanged validator and archive/readback worker retain their checks.
    # Only this continuation's off-path capacity grows with the real evidence.
    retention_source=(root/'distributed/cloud_results/preservation.py').read_text()
    retention_file=continuation/'retention.py'
    retention_file.write_text(retention_overlay(retention_source,scratch=bool(manifest.get('archiveScratch'))))
    import importlib.util
    retention_spec=importlib.util.spec_from_file_location('continued_evidence_retention',retention_file)
    retention=importlib.util.module_from_spec(retention_spec);retention_spec.loader.exec_module(retention)
    from cloud_results.owner_materials import collect as collect_public_owner_witnesses
    from collect import collect as collect_original
    def continued_collect(self):
        collect_public_owner_witnesses(self);collect_original(self)
        self.private_preservation=retention.preserve_hosts(self)
    worker.collect=types.MethodType(continued_collect,worker)
    parent_state=read(Path(prepared['parentRun'])/'launch-state.json')
    original_start=datetime.fromisoformat(parent_state['createdAt'])
    elapsed=(datetime.now(timezone.utc)-original_start).total_seconds()
    worker.started=time.monotonic()-elapsed
    deadline=worker.started+float(quote['planned_hours'])*3600
    require(deadline-time.monotonic()>3600,'Less than one hour remains inside the original technical duration')
    for remote in worker.remotes.values():remote.read_deadline=deadline
    store=Store(job['bucket'],cfg['project_id'])
    stop_checkpoints=threading.Event();checkpoint_errors=[];last_checkpoint=None
    checkpoint_dir=continuation/'checkpoints';checkpoint_dir.mkdir(mode=0o700)
    checkpoint_lock=threading.Lock()
    def checkpoint():
        nonlocal last_checkpoint
        with checkpoint_lock:
            target=worker.root('coordinator-1')+'/reports/application.json'
            result=worker.remote('coordinator-1').run(['sudo','cat',target],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=45)
            data=result.stdout.encode();value=json.loads(data)
            digest=__import__('hashlib').sha256(data).hexdigest()
            if digest==last_checkpoint:return
            file=checkpoint_dir/(digest+'.json')
            if not file.exists():file.write_bytes(data);file.chmod(0o600)
            object_name='runs/'+job['jobId']+'/checkpoints/'+digest+'.json'
            import urllib.error
            try:metadata=store.metadata(object_name)
            except urllib.error.HTTPError as error:
                if error.code!=404:raise
                receipt=store.upload(file,object_name)
            else:
                receipt={'bucket':store.bucket,'object':object_name,'generation':metadata['generation'],
                    'bytes':int(metadata['size']),'md5Hash':metadata['md5Hash'],
                    'sha256':metadata['metadata']['vcfhe-sha256']}
                require(receipt['sha256']==digest and receipt['bytes']==len(data),'Existing checkpoint differs')
                store.verify(receipt)
            readback=checkpoint_dir/(digest+'.readback.json')
            if not readback.exists():store.download(receipt,readback,maximum=64*1024**2)
            require(readback.read_bytes()==data,'Checkpoint full readback differs')
            write(continuation/'latest-checkpoint.json',{'status':'verified-cloud-readback','createdAt':now(),
                'caseRows':len(value['cases']),'kmsCalls':value['kmsCalls'],'receipt':receipt})
            last_checkpoint=digest
    def monitor_checkpoints():
        while not stop_checkpoints.wait(60):
            try:checkpoint()
            except Exception as error:
                checkpoint_errors.append({'observedAt':now(),'errorType':type(error).__name__})
                write(continuation/'checkpoint-observation-errors.json',checkpoint_errors)
    def prepare_host(host):
        remote=worker.remotes[host['id']];old_compose=worker.base+'/'+host['id']+'/compose.json'
        logs_dir=worker.base+'/'+host['id']+'/predecessor-container-logs'
        # Retain the original logs before Compose replaces stopped applications.
        remote.run(['sudo','install','-d','-m','700',logs_dir])
        script='set -eu\n'+shlex.join(['sudo','docker','compose','-f',old_compose,'logs','--no-color'])+' >'+shlex.quote(logs_dir+'/all.log')+' 2>&1\n'
        remote.run(['sudo','sh','-c',script],stdout=subprocess.DEVNULL)
        index=int(host['id'].split('-')[1])
        remote.run(['sudo','docker','compose','-f',old_compose,'stop','kms-'+str(index)+'-core','kms-'+str(index)+'-public'],stdout=subprocess.DEVNULL)
        services=[name for name in worker.compose[host['id']]['services'] if name not in ['init','setup','policy-init'] and not name.startswith('validator-')]
        remote.run(['sudo','docker','compose','-f',worker.base+'/'+host['id']+'/workflow-continuation-compose/compose.json',
                    'up','-d','--no-deps',*services],stdout=subprocess.DEVNULL)
        sampler=worker.base+'/'+host['id']
        require(remote.text(['sudo','test','!','-e',sampler+'/stop-sampler'])=='','Sampler stop marker already exists')
        remaining=max(1,math.ceil((deadline-time.monotonic())/15))
        args=['python3',sampler+'/probe.py','--plan',sampler+'/plan.json','--host',host['id'],
              '--output',sampler+'/host-observations-'+tag+'.jsonl','--samples',str(remaining),'--interval','15',
              '--network','--stop-file',sampler+'/stop-sampler']
        remote.run(['sudo','sh','-c','nohup '+shlex.join(args)+' >'+shlex.quote(sampler+'/probe-'+tag+'.log')+' 2>&1 </dev/null &'])
    def open_gate(node):
        remote=worker.remote(node);marker=worker.root(node)+'/config/start-role.json'
        remote.run(['sudo','touch',marker]);remote.run(['sudo','chown','10001:10001',marker])
    def check_execution_sources():
        expected={name:row['overlaySha256'] for name,row in manifest['overlays'].items()}
        expected['guard.mjs']=sha(continuation/'guard.mjs')
        expected['manifest.json']=sha(continuation/'manifest.json')
        for host,remote in worker.remotes.items():
            folder=prepared['newBase']+'/'+host+'/continuation'
            script="import json,hashlib;from pathlib import Path;p=Path("+repr(folder)+");print(json.dumps({n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in "+repr(list(expected))+"}))"
            require(remote.json(['sudo','python3','-c',script])==expected,'Mounted continuation source changed')
        catalogs=manifest.get('fixtureCatalogs',{})
        if tag in ('workflows-c2','workflows-c3'):
            require({'coordinator-1','owner-1','owner-2','owner-3','owner-4'}<=set(catalogs),
                'Missing bound full-case catalog')
            for host,remote in worker.remotes.items():
                subset={n:h for n,h in catalogs.items() if worker.nodes[n]['host']==host}
                if not subset:continue
                paths={n:worker.root(n)+'/fixtures' for n in subset}
                script="import json,hashlib;from pathlib import Path;paths="+repr(paths)+";full="+repr(manifest['fullCases'])+";out={}\nfor n,v in paths.items():\n p=Path(v);b=(p/'prepared.json').read_bytes();d=json.loads(b);assert [c['name'] for c in d['cases']]==full;assert all((p/c).is_dir() for c in full);out[n]=hashlib.sha256(b).hexdigest()\nprint(json.dumps(out))"
                require(remote.json(['sudo','python3','-c',script])==subset,
                    'Advertised full-case inputs differ from retained directories')
        path=prepared['newBase']+'/coordinator-1/config/budget-runtime.json'
        code="import hashlib;from pathlib import Path;print(hashlib.sha256(Path("+repr(path)+").read_bytes()).hexdigest())"
        require(worker.remote('coordinator-1').text(['sudo','python3','-c',code])==manifest['admissionControl']['runtimeSha256'],
            'Completion authority or original cost accounting changed')
    # A distinct source checkpoint records every continuation addition. It does
    # not replace the original image/source seal or its failed predecessor.
    import tarfile
    source_archive=continuation/'continuation-sources.tar'
    from continuation_storage import capacity_preflight
    capacity_preflight(worker)
    with tarfile.open(source_archive,'x') as archive:
        for name,expected_sha in sorted(manifest['maintenanceSources'].items()):
            require(Path(name).name==name,'Unexpected continuation source path')
            file=Path(__file__).resolve().parent/name
            require(sha(file)==expected_sha,'Continuation maintenance source changed')
            archive.add(file,arcname='driver/'+name,recursive=False)
        for name in ['owner.mjs','evaluate.mjs','admission.mjs','budget-runtime.json','manifest.json','config.json','retention.py']:
            archive.add(continuation/name,arcname='execution/'+name,recursive=False)
    source_receipt=store.upload(source_archive,'runs/'+job['jobId']+'/continuation-sources.tar')
    store.download(source_receipt,continuation/'continuation-sources.readback.tar',maximum=8*1024**2)
    write(continuation/'source-checkpoint.json',source_receipt,new=True)
    check_execution_sources()
    write(continuation/'start-intent.json',{'requestedAt':now(),'protocolSetupRepeated':False,'comparisonsRepeated':False,
          'originalDeadlineMaintained':True,'fullWorkflows':27},new=True)
    worker.state['status']='running';write(segment/'launch-state.json',worker.state)
    thread=None
    try:
        worker.stage('Retained participant backends and workflow-only processes',lambda:list(ThreadPoolExecutor(max_workers=4).map(prepare_host,worker.plan['hosts'])))
        for i in range(1,5):open_gate('owner-'+str(i))
        wait_until=time.monotonic()+900
        for i in range(1,5):
            node='owner-'+str(i);remote=worker.remote(node);path=worker.root(node)+'/owner-rpc/recovery-ready.json'
            while True:
                try:
                    remote.run(['sudo','test','-f',path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                    break
                except subprocess.CalledProcessError as error:
                    if error.returncode!=1:raise
                if time.monotonic()>wait_until:raise TimeoutError('Owner restore deadline exceeded')
                time.sleep(3)
        # Keep the native client out of the completed paired phase. In C3 it
        # starts only when the first encrypted output candidate exists.
        if tag!='workflows-c3':open_gate('recipient-1')
        open_gate('coordinator-1')
        thread=threading.Thread(target=monitor_checkpoints,daemon=True);thread.start()
        if tag=='workflows-c3':
            require(manifest.get('recipientStartOrder')=='first-release-candidate',
                'Unbound recipient startup order')
            def start_recipient_at_candidate():
                remote=worker.remote('coordinator-1');root=worker.root('coordinator-1')
                while time.monotonic()<deadline:
                    script="import json;from pathlib import Path;p=Path("+repr(root)+");e=p/'reports/participant-exit.json';print(json.dumps({'candidate':(p/'exchange/request-0.json').is_file(),'exit':json.loads(e.read_text()) if e.is_file() else None}))"
                    observed=remote.json(['sudo','python3','-c',script])
                    if observed['exit'] is not None:
                        require(observed['exit']['exitCode']==0,'Coordinator failed before recipient startup')
                    if observed['candidate']:
                        open_gate('recipient-1')
                        write(continuation/'recipient-start.json',{'startedAt':now(),
                            'order':'first-release-candidate','requestsReplayed':False},new=True)
                        return
                    time.sleep(5)
                raise TimeoutError('First release candidate exceeded the technical duration')
            worker.stage('Recipient startup at first encrypted output candidate',start_recipient_at_candidate)
        worker.stage('Full workflow continuation',worker.wait)
        check_execution_sources()
        checkpoint();stop_checkpoints.set();thread.join(timeout=60)
        # Preserve both sampling segments, then present their exact concatenation.
        for host,remote in worker.remotes.items():remote.run(['sudo','touch',worker.base+'/'+host+'/stop-sampler'])
        time.sleep(12)
        for host,remote in worker.remotes.items():
            script="from pathlib import Path;import shutil;p=Path("+repr(worker.base+'/'+host)+");a=p/'host-observations.jsonl';b=p/'host-observations-pre-workflows.jsonl';assert not b.exists();shutil.copy2(a,b);data=b.read_bytes()+(p/"+repr('host-observations-'+tag+'.jsonl')+").read_bytes();t=p/'host-observations-combined.pending';t.write_bytes(data);t.replace(a)"
            remote.run(['sudo','python3','-c',script])
        worker.stage('Collect and validate continued evidence',worker.collect)
        worker.state.update(status='completed',resultsStatus='pending-analysis')
        write(segment/'launch-state.json',worker.state)
        worker.stop()
        result=worker.stage('Derive validated continued cloud results',lambda:derive(segment))
        require(result['status']=='results-ready','Result analysis did not complete')
        base=root/'threshold-kms/composites'/(segment.name+'-distributed')
        meta=store.metadata('runs/'+read(input_root/'source-manifest.json')['jobId']+'/controller-source.tar.gz')
        job['sourceObject']={'bucket':store.bucket,'object':meta['name'],'generation':meta['generation'],
            'bytes':int(meta['size']),'md5Hash':meta['md5Hash'],'sha256':meta['metadata']['vcfhe-sha256']}
        store.verify(job['sourceObject'])
        preservation=retention.archive_controller(segment,base,job,worker.private_preservation)
        delivery=continuation/'evaluation-delivery'
        exported=package.build_results(segment,base,delivery,compact_preservation(preservation))
        obj=store.upload(Path(exported['archive']),'runs/'+job['jobId']+'/evaluation-results.tar')
        store.download(obj,delivery/'evaluation-results.readback.tar',maximum=package.MAX_PACKAGE_BYTES)
        control={'schema':'cloud-full-control-v1','config':cfg,'protocolTerraform':read(segment/'terraform/terraform.tfstate'),
          'protocolDeclarations':read(segment/'terraform/main.tf.json'),'actorAccounts':read(input_root/'job/actor-accounts.local.json'),
          'ownershipPlan':read(segment/'preservation/ownership.local.json'),'privatePreservation':compact_hosts(worker.private_preservation),
          'rawPreservation':compact_preservation(preservation),'sourceManifestSha256':job['sourceManifestSha256']}
        write(continuation/'control.json',control,new=True)
        terminal={'schema':VERSION,'status':'awaiting-verified-local-delivery','createdAt':now(),
          'evaluation':{**obj,'manifestSha256':exported['manifestSha256']},
          'control':store.upload(continuation/'control.json','runs/'+job['jobId']+'/control.json'),
          'rawPreservation':compact_preservation(preservation),'protocolOperationsCompleted':True,'computeStopped':True,
          'teardownPermitted':False,'fullCampaignCompleted':True,'continuationProfile':manifest['profile'],
          'parentFailurePreserved':True,'comparisonsReused':480,'warmupsReused':18,
          'continuationSources':source_receipt,
          'continuationManifest':store.upload(continuation/'manifest.json','runs/'+job['jobId']+'/continuation-manifest.json')}
        write(continuation/'terminal.json',terminal,new=True)
        receipt=store.upload(continuation/'terminal.json','runs/'+job['jobId']+'/terminal.json')
        write(continuation/'terminal-object.json',receipt,new=True)
        worker.state.update(status='awaiting-verified-local-delivery',resultsStatus='results-ready')
        write(segment/'launch-state.json',worker.state)
    except BaseException as error:
        stop_checkpoints.set()
        if thread is not None:thread.join(timeout=60)
        worker.state.update(status='failed-preserved',error=str(error),errorType=type(error).__name__)
        write(segment/'launch-state.json',worker.state);traceback.print_exc()
        try:checkpoint()
        except Exception:pass
        failure=continuation/'failure-summary.json'
        write(failure,{'status':'failed-preserved','errorType':type(error).__name__,
            'continuationProfile':manifest['profile'],'dataDeleted':False,'protocolReplayed':False,
            'inspectionRequired':True,'comparisonsPreserved':480,'warmupsPreserved':18})
        try:store.upload(failure,'runs/'+job['jobId']+'/failure.json')
        except Exception:pass
        worker.stop()
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True);parser.add_argument('--segment',type=Path,required=True)
    parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    if not args.execute:raise SystemExit('Explicit --execute required. No operation was performed.')
    os.umask(0o077);main(args.input,args.segment)
