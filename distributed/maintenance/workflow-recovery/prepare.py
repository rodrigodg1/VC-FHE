#!/usr/bin/env python3
"""Prepare an explicit, unused-prefix continuation without starting applications.

Requires separately verified private diagnostic and snapshot receipts beside the
original controller root. It refuses an existing continuation directory.
"""
from pathlib import Path
import argparse,json,os,sys


def prepare(input_root):
    input_root=Path(input_root).resolve()
    REMOTE_ROOT=str(input_root.parent)
    REPO=str(input_root/'repository/VC-FHE')
    sys.path.insert(0,str(Path(REPO)/'distributed'))
    os.environ['CLOUDSDK_PYTHON']=sys.executable
    os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
    from cloud_tools import ensure
    ensure()
    from cloud_results.common import read,write,sha,require,now
    from remote import Remote
    import topology
    cfg=read(input_root/'job/config.local.json')
    import shutil,copy,time,hashlib,types
    from concurrent.futures import ThreadPoolExecutor
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from transforms import PROFILE,owner_overlay,evaluator_overlay,verify_configuration,verify_prefix
    from cloud_results.worker import CloudCampaign
    from cloud_results.completion_budget import original_admission
    from experiment_plan import evidence_module
    import deployment
    source_manifest=read(Path(REMOTE_ROOT)/'input/source-manifest.json')
    parent=Path(REPO)/'threshold-kms/runs'/source_manifest['runName']
    segment=parent.with_name(parent.name+'-workflows-c1')
    require(not segment.exists(),'Continuation already prepared; inspect instead of recreating')
    old_base='/srv/vcfhe/'+cfg['campaign'];new_base=old_base+'/workflows-c1'
    hosts=topology.hosts(cfg);remotes={h['id']:Remote(cfg,h) for h in hosts}
    first=remotes['host-1']
    oldcfg=first.json(['sudo','cat',old_base+'/coordinator-1/config/campaign.json'])
    oldapp=first.json(['sudo','cat',old_base+'/coordinator-1/reports/application.json'])
    paired_text=first.text(['sudo','cat',old_base+'/coordinator-1/reports/paired.json'])
    paired=json.loads(paired_text);evidence_module(oldcfg).validate_pairs(oldcfg,paired)
    # This diagnostic receipt came from all four validators and all four KMS cores.
    probe=read(Path(REMOTE_ROOT)/'workflow-recovery-diagnostics/unreserved-request-diagnostic-combined.local.json')
    backup=read(Path(REMOTE_ROOT)/'workflow-recovery-diagnostics/workflow-recovery-snapshots.local.json')
    require(backup['status']=='all-ready-source-identity-verified' and len(backup['snapshots'])==5,'Recovery snapshots incomplete')
    verify_prefix(paired,oldapp,probe)
    prepared=first.json(['sudo','cat',old_base+'/coordinator-1/fixtures/prepared.json'])
    full=[c['name'] for c in prepared['cases'] if c['fullCase']];require(len(full)==27,'Wrong full-case grid')
    newcfg={**oldcfg,'runId':segment.name,'workflowContinuation':{'profile':PROFILE,'fullCases':full,'parentRunId':oldcfg['runId']}}
    verify_configuration(oldcfg,newcfg,full)
    # Extract only original public source files from a stopped existing container.
    extract="""import json,subprocess\nprefix=BASE\nids=subprocess.check_output(['sudo','docker','ps','-aq','--filter','label=com.docker.compose.service=coordinator-1'],text=True).split();assert len(ids)==1\ndef content(name):return subprocess.check_output(['sudo','docker','cp',ids[0]+':/app/threshold-kms/campaign/'+name,'-'])\nimport tarfile,io\nout={}\nfor name in ['owner.mjs','evaluate.mjs']:\n with tarfile.open(fileobj=io.BytesIO(content(name))) as t:out[name]=t.extractfile(t.getmembers()[0]).read().decode()\nprint(json.dumps(out))""".replace('BASE',repr(old_base))
    source=first.json(['sudo','python3','-c',extract])
    restore=(Path(REPO)/'threshold-kms/recovery/owner-restore-v3.mjs').read_text()
    overlays={'owner.mjs':owner_overlay(source['owner.mjs'],restore),'evaluate.mjs':evaluator_overlay(source['evaluate.mjs'])}
    repeatability=first.text(['sudo','cat',old_base+'/coordinator-1/reports/distributed/byte-repeatability.json'])
    require(json.loads(repeatability)['status']=='passed','Missing original determinism admission')
    # Byte hashes are measured on each original file, without newline normalization.
    original_hashes=first.json(['sudo','python3','-c',"import json,hashlib;from pathlib import Path;p=Path("+repr(old_base+'/coordinator-1')+");print(json.dumps({n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ['reports/paired.json','reports/distributed/byte-repeatability.json']}))"])
    manifest={'profile':PROFILE,'parentRun':parent.name,'parentConfiguration':oldcfg,'keyset':prepared['keys'],
     'pairedSha256':original_hashes['reports/paired.json'],'repeatabilitySha256':original_hashes['reports/distributed/byte-repeatability.json'],
     'fullCases':full,'overlays':{n:{'sourceSha256':hashlib.sha256(source[n].encode()).hexdigest(),'overlaySha256':hashlib.sha256(s.encode()).hexdigest()} for n,s in overlays.items()},
     'transactionsReplayed':False,'releasesReplayed':False,'setupRepeated':False,'predecessorFailurePreserved':True,
     'originalRecipientFailure':'unreserved user decrypt admitted','originalStatusCodeUnavailable':True,'freshDiagnosticAllCoresDenied':True}
    shutil.copytree(parent,segment)
    # The predecessor directory, launch failure and source archive stay untouched.
    write(segment/'distributed/workflow-continuation.json',manifest,new=True)
    continuation=segment/'distributed/workflow-continuation';continuation.mkdir(mode=0o700)
    write(continuation/'manifest.json',manifest,new=True)
    for n,s in overlays.items():(continuation/n).write_text(s)
    shutil.copy2(Path(__file__).resolve().parent/'guard.mjs',continuation/'guard.mjs')
    write(continuation/'config.json',newcfg,new=True)
    node_plan=topology.inventory(cfg)
    # Copy public/encrypted fixtures and owner state only on their original host.
    # No owner identity or KMS private vault is transferred between hosts.
    node_prepare=r'''import json,sys,shutil,subprocess,os,re
    from pathlib import Path
    v=json.loads(sys.argv[1]);base=Path(v['old']);target=Path(v['new']);assert not target.exists()
    node=v['node'];cfg=v['config'];target.mkdir(mode=0o700,parents=True)
    for name in ['config','reports','fixtures','owner','transport','worker-rpc','keyset','owner-rpc','release-evidence','exchange','recipient','datasets']:
     old=base/name;new=target/name
     if name in ['exchange','recipient','owner-rpc']:
      new.mkdir(mode=0o700);continue
     if old.exists():
      subprocess.run(['cp','-a','--reflink=auto',str(old),str(new)],check=True)
     else:new.mkdir(mode=0o700)
    for name in ['application.json','participant-exit.json','progress-evaluation.jsonl','workflow-continuation-gate.json']:
     (target/'reports'/name).unlink(missing_ok=True)
    (target/'config/start-role.json').unlink(missing_ok=True)
    (target/'config/campaign.json').write_text(json.dumps(cfg,indent=2)+'\n')
    # Only unfinished first-case products in the new copy are removed.
    for case in v['full']:
     p=target/'fixtures'/case
     for name in ['aggregate.bin','output.bin','full-admissions.json']:
      (p/name).unlink(missing_ok=True)
     for f in p.glob('verified-*.bin'):f.unlink()
    subprocess.run(['chown','-R','10001:10001',str(target)],check=True)
    print(json.dumps({'node':node,'stateCopiedOnSameHost':True,'reencrypted':False,'newRoot':str(target)}))'''
    def prepare_host(h):
     r=remotes[h['id']];out=[]
     require(r.text(['sudo','cat','/srv/vcfhe/scope.txt'])==cfg['campaign']+'/'+h['id'],'Wrong retained state mount')
     used=int(r.text(['sudo','du','-sb',old_base]).split()[0]);free=int(r.text(['df','-B1','--output=avail','/srv/vcfhe']).splitlines()[-1])
     require(free>used+10*1024**3,'Insufficient cloud space for a preserved continuation copy')
     for node in node_plan:
      if node['host']!=h['id'] or node['role']=='validator':continue
      info={'old':old_base+'/'+node['id'],'new':new_base+'/'+node['id'],'node':node['id'],'config':newcfg,'full':full}
      out.append(r.json(['sudo','python3','-c',node_prepare,json.dumps(info)]))
     r.upload(continuation,new_base+'/'+h['id']+'/continuation')
     return {'host':h['id'],'nodes':out}
    rows=list(ThreadPoolExecutor(max_workers=4).map(prepare_host,hosts))
    # Build a new execution record around the same VMs, validators, identities and keyset.
    job={'work':str(Path(REMOTE_ROOT)/'input'),'config':cfg,'jobId':source_manifest['jobId']+'-workflows-c1',
     'bucket':__import__('cloud_results.infra',fromlist=['names']).names(cfg)['bucket'],
     'sourceManifestSha256':sha(Path(REMOTE_ROOT)/'input/source-manifest.json'),'controllerSources':source_manifest['controllerSources']}
    worker=CloudCampaign(cfg,read(Path(REMOTE_ROOT)/'input/job/quote.local.json'),Path(REMOTE_ROOT)/'input/build',segment.with_name(segment.name+'-unallocated'),job=job)
    worker.run=segment;worker.identities=read(segment/'distributed/public-identities.json');worker.provisioned=True
    worker.datasets=read(segment/'distributed/controller-inputs.json')['datasets']
    worker.state={'schema':'vcfhe-distributed-launch-v1','status':'workflow-continuation-prepared','createdAt':now(),
     'config':cfg,'stages':[],'continuationProfile':PROFILE,'predecessor':parent.name}
    worker.plan=topology.plan(cfg);worker.nodes={n['id']:n for n in worker.plan['nodes']}
    for n in worker.nodes.values():
     if n['role']!='validator':n['state_directory']=new_base+'/'+n['id']
    worker.compose=deployment.manifests(cfg,segment.name)
    for h,compose in worker.compose.items():
     for name,service in compose['services'].items():
      for mount in service.get('volumes',[]):
       old=mount['source']
       # Keep identities, KMS private vaults and public signing keys in place.
       if mount['target'] in ['/identity','/recipient-identity','/private','/public','/release-keyset'] or name.startswith('validator-'):continue
       if old.startswith(old_base+'/'):mount['source']=new_base+'/'+old[len(old_base)+1:]
      if name=='coordinator-1' or name.startswith('owner-'):
       file='evaluate.mjs' if name=='coordinator-1' else 'owner.mjs'
       service['volumes'].append({'type':'bind','source':new_base+'/'+h+'/continuation/'+file,'target':'/app/threshold-kms/campaign/'+file,'read_only':True})
      if name=='coordinator-1':service['volumes'].append({'type':'bind','source':new_base+'/'+h+'/continuation','target':'/continuation','read_only':True})
      if name in ['init','setup','policy-init']:
       service['profiles']=['never-in-continuation']
     compose_dir=segment/'compose'/h;write(compose_dir/'compose.json',compose)
     worker.remotes[h].upload(compose_dir,old_base+'/'+h+'/workflow-continuation-compose')
    write(segment/'launch-state.json',worker.state)
    write(continuation/'prepared.json',{'status':'prepared-not-started','newRun':str(segment),'parentRun':str(parent),
     'newBase':new_base,'createdAt':now(),'nodes':rows,'manifestSha256':sha(continuation/'manifest.json'),
     'newCampaignConfigSha256':sha(continuation/'config.json'),'job':job},new=True)
    print(json.dumps({'status':'prepared-not-started','segment':str(segment),'newBase':new_base,'manifest':manifest,'nodeCount':sum(len(r['nodes']) for r in rows)}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--execute',action='store_true')
    a=p.parse_args()
    if not a.execute:raise SystemExit('Explicit --execute required. No preparation occurred.')
    os.umask(0o077)
    prepare(a.input)
