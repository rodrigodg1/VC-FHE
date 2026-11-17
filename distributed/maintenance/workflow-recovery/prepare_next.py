#!/usr/bin/env python3
"""Prepare C2 after the specific catalog failure, without starting applications."""
from pathlib import Path
import argparse,json,os,sys

def prepare(input_root, *, resume_unstarted=False):
    input_root=Path(input_root).resolve();REMOTE_ROOT=str(input_root.parent);REPO=str(input_root/'repository/VC-FHE')
    sys.path.insert(0,REPO+'/distributed');os.environ['CLOUDSDK_PYTHON']=sys.executable;os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
    from cloud_tools import ensure
    ensure()
    from cloud_results.common import read,write,sha,require,now
    from remote import Remote
    import topology
    cfg=read(input_root/'job/config.local.json')
    import shutil,copy,time,hashlib,types
    from concurrent.futures import ThreadPoolExecutor
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from catalog import select_full_catalog
    from cloud_results.common import digest
    from transforms import PROFILE,owner_overlay,evaluator_overlay,verify_configuration,verify_prefix
    from cloud_results.worker import CloudCampaign
    from cloud_results.completion_budget import original_admission
    from experiment_plan import evidence_module
    import deployment
    source_manifest=read(Path(REMOTE_ROOT)/'input/source-manifest.json')
    parent=Path(REPO)/'threshold-kms/runs'/source_manifest['runName']
    previous=parent.with_name(parent.name+'-workflows-c1')
    require(read(previous/'launch-state.json')['status']=='failed-preserved','Previous attempt must stay failed')
    segment=parent.with_name(parent.name+'-workflows-c2')
    resuming=segment.exists()
    require(not resuming or resume_unstarted,'Continuation already exists. Explicit unstarted-preparation inspection required')
    if resuming:
        c=segment/'distributed/workflow-continuation'
        require(not (c/'start-intent.json').exists() and not (c/'prepared.json').exists(),
            'Cannot resume an execution or completed preparation')
        require(read(c/'manifest.json')['continuationTag']=='workflows-c2','Unexpected partial preparation')
    original_base='/srv/vcfhe/'+cfg['campaign'];old_base=original_base+'/workflows-c1';new_base=original_base+'/workflows-c2'
    hosts=topology.hosts(cfg);remotes={h['id']:Remote(cfg,h) for h in hosts}
    first=remotes['host-1']
    prior_manifest=read(previous/'distributed/workflow-continuation/manifest.json')
    oldcfg=prior_manifest['parentConfiguration']
    failure=read(Path(__file__).resolve().parent/'c1-native-failure-detail.local.json')
    require(failure['evidence']=={'appExists':False,'gate':None,'exit':{'node':'coordinator-1','role':'coordinator','exitCode':1},'exchangeFiles':[]},'Unexpected previous workflow prefix')
    require('assert.ok(r.ready)' in failure['logs'],'Different failure requires separate diagnosis')
    oldapp={'cases':[],'kmsCalls':0}
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
    # Reuse the already tested execution overlays. The repair changes the input
    # catalog and the administrative continuation identity, not protocol code.
    prior=previous/'distributed/workflow-continuation'
    overlays={n:(prior/n).read_text() for n in prior_manifest['overlays']}
    manifest=copy.deepcopy(prior_manifest)
    manifest.update(continuationTag='workflows-c2',priorFailedContinuation=previous.name,
     failureRepair='Advertise only retained preselected full cases',fixtureCatalogs={})
    manifest['maintenanceSources']={x.name:sha(x) for x in Path(__file__).resolve().parent.iterdir()
     if x.is_file() and x.suffix in ['.py','.mjs'] and not x.name.endswith('.local.py')}
    if not resuming:
        shutil.copytree(previous,segment)
        (segment/'distributed/workflow-continuation').rename(segment/'distributed/predecessor-c1-evidence')
    # The predecessor directory, launch failure and source archive stay untouched.
    write(segment/'distributed/workflow-continuation.json',manifest)
    continuation=segment/'distributed/workflow-continuation';continuation.mkdir(mode=0o700,exist_ok=resuming)
    if resuming:
        require(read(continuation/'config.json')==newcfg,'Partial preparation configuration changed')
    write(continuation/'manifest.json',manifest)
    for n,s in overlays.items():(continuation/n).write_text(s)
    shutil.copy2(prior/'guard.mjs',continuation/'guard.mjs')
    shutil.copy2(prior/'budget-runtime.json',continuation/'budget-runtime.json')
    write(continuation/'config.json',newcfg)
    node_plan=topology.inventory(cfg)
    # Copy public/encrypted fixtures and owner state only on their original host.
    # No owner identity or KMS private vault is transferred between hosts.
    import inspect
    from textwrap import dedent
    node_prepare=inspect.getsource(select_full_catalog)+dedent(r'''
    import json,sys,shutil,subprocess,os,re
    from pathlib import Path
    v=json.loads(Path(sys.argv[1]).read_text());base=Path(v['old']);target=Path(v['new'])
    assert not target.exists(),'Partial node copy requires inspection before any retry'
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
    catalog=target/'fixtures/prepared.json';catalogSha=None
    if catalog.exists():
     document=json.loads(catalog.read_text());document=select_full_catalog(document,v['full'],[x.name for x in (target/'fixtures').iterdir() if x.is_dir()]);catalog.write_text(json.dumps(document,indent=2)+'\n');catalogSha=__import__('hashlib').sha256(catalog.read_bytes()).hexdigest()
    # Only unfinished first-case products in the new copy are removed.
    for case in v['full']:
     p=target/'fixtures'/case
     for name in ['aggregate.bin','output.bin','full-admissions.json']:
      (p/name).unlink(missing_ok=True)
     for f in p.glob('verified-*.bin'):f.unlink()
    subprocess.run(['chown','-R','10001:10001',str(target)],check=True)
    print(json.dumps({'node':node,'stateCopiedOnSameHost':True,'reencrypted':False,'newRoot':str(target),'catalogSha256':catalogSha}))''')
    def prepare_host(h):
     r=remotes[h['id']];out=[]
     require(r.text(['sudo','cat','/srv/vcfhe/scope.txt'])==cfg['campaign']+'/'+h['id'],'Wrong retained state mount')
     used=int(r.text(['sudo','du','-sb',old_base]).split()[0]);free=int(r.text(['df','-B1','--output=avail','/srv/vcfhe']).splitlines()[-1])
     require(free>used+10*1024**3,'Insufficient cloud space for a preserved continuation copy')
     logs=r.text(['sudo','docker','compose','-f',original_base+'/'+h['id']+'/workflow-continuation-compose/compose.json','logs','--no-color'])
     logdir=segment/'distributed/predecessor-c1-container-logs';logdir.mkdir(mode=0o700,exist_ok=True)
     logfile=logdir/(h['id']+'.log');logfile.write_text(logs);logfile.chmod(0o600)
     inputs=segment/'preparation-inputs'/h['id'];inputs.mkdir(mode=0o700,parents=True,exist_ok=True)
     (inputs/'prepare-node.py').write_text(node_prepare)
     selected=[n for n in node_plan if n['host']==h['id'] and n['role']!='validator']
     for node in selected:
      write(inputs/(node['id']+'.json'),{'old':old_base+'/'+node['id'],'new':new_base+'/'+node['id'],
          'node':node['id'],'config':newcfg,'full':full})
     remote_inputs=original_base+'/'+h['id']+'/c2-preparation-inputs'
     r.upload(inputs,remote_inputs)
     for node in node_plan:
      if node['host']!=h['id'] or node['role']=='validator':continue
      info={'old':old_base+'/'+node['id'],'new':new_base+'/'+node['id'],'node':node['id'],'config':newcfg,'full':full}
      out.append(r.json(['sudo','python3',remote_inputs+'/prepare-node.py',remote_inputs+'/'+node['id']+'.json']))
     r.upload(continuation,new_base+'/'+h['id']+'/continuation')
     return {'host':h['id'],'nodes':out,'predecessorLogSha256':sha(logfile)}
    rows=list(ThreadPoolExecutor(max_workers=4).map(prepare_host,hosts))
    # Build a new execution record around the same VMs, validators, identities and keyset.
    job={'work':str(Path(REMOTE_ROOT)/'input'),'config':cfg,'jobId':source_manifest['jobId']+'-workflows-c2',
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
    worker.compose={h['id']:read(previous/'compose'/h['id']/'compose.json') for h in hosts}
    for h,compose in worker.compose.items():
     for name,service in compose['services'].items():
      for mount in service.get('volumes',[]):
       old=mount['source']
       # Keep identities, KMS private vaults and public signing keys in place.
       if mount['target'] in ['/identity','/recipient-identity','/private','/public','/release-keyset'] or name.startswith('validator-'):continue
       if old.startswith(old_base+'/'):mount['source']=new_base+'/'+old[len(old_base)+1:]
      if name in ['init','setup','policy-init']:
       service['profiles']=['never-in-continuation']
     compose_dir=segment/'compose'/h;write(compose_dir/'compose.json',compose)
     worker.remotes[h].upload(compose_dir,original_base+'/'+h+'/workflow-continuation-compose')
    manifest['fixtureCatalogs']={n['node']:n['catalogSha256'] for h in rows for n in h['nodes'] if n['catalogSha256']}
    scratch=copy.deepcopy(prior_manifest['archiveScratch']['host-1'])
    scratch['previousMountpoint']=scratch['mountpoint']
    scratch['mountpoint']='/var/tmp/vcfhe-private-archive-'+digest({'run':str(segment),'config':digest(cfg)})[:32]
    move_scratch=dedent(r"""
    import json,subprocess;from pathlib import Path
    s=json.loads(__import__('sys').argv[1]);old=Path(s['previousMountpoint']);new=Path(s['mountpoint'])
    assert subprocess.check_output(['findmnt','-n','-o','UUID','--target',str(old)],text=True).strip()==s['filesystemUuid']
    assert set(p.name for p in old.iterdir())<= {'lost+found'},'Archive scratch contains evidence'
    assert not new.exists();new.mkdir(mode=0o700)
    subprocess.run(['umount',str(old)],check=True)
    f=Path('/etc/fstab');text=f.read_text();oldline='UUID='+s['filesystemUuid']+' '+str(old)+' ext4 defaults,nofail 0 2';newline=oldline.replace(str(old),str(new));assert text.count(oldline)==1;f.write_text(text.replace(oldline,newline))
    subprocess.run(['mount',str(new)],check=True)
    assert subprocess.check_output(['findmnt','-n','-o','UUID','--target',str(new)],text=True).strip()==s['filesystemUuid']
    print(json.dumps({'sameDiskAndFilesystem':True}))""")
    first.json(['sudo','python3','-c',move_scratch,json.dumps(scratch)])
    manifest['archiveScratch']={'host-1':scratch}
    write(continuation/'manifest.json',manifest);write(segment/'distributed/workflow-continuation.json',manifest)
    for h in hosts:remotes[h['id']].upload(continuation,new_base+'/'+h['id']+'/continuation')
    write(segment/'launch-state.json',worker.state)
    write(continuation/'prepared.json',{'status':'prepared-not-started','newRun':str(segment),'parentRun':str(parent),
     'newBase':new_base,'createdAt':now(),'nodes':rows,'manifestSha256':sha(continuation/'manifest.json'),
     'newCampaignConfigSha256':sha(continuation/'config.json'),'job':job},new=True)
    print(json.dumps({'status':'prepared-not-started','segment':str(segment),'newBase':new_base,'manifest':manifest,'nodeCount':sum(len(r['nodes']) for r in rows)}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--execute',action='store_true');p.add_argument('--resume-unstarted',action='store_true');a=p.parse_args()
    if not a.execute:raise SystemExit('Explicit --execute required. No preparation occurred.')
    os.umask(0o077);prepare(a.input,resume_unstarted=a.resume_unstarted)
