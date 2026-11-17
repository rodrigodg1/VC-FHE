#!/usr/bin/env python3
"""Prepare a fresh 17-case segment after read-only completed-prefix validation."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse,copy,hashlib,json,os,shutil,sys,subprocess
from selection import select,configuration,verify_config
from window import PROFILE,renewal,overlay

def main(input_root,preflight):
    input_root=Path(input_root).resolve();preflight=Path(preflight).resolve();root=input_root/'repository/VC-FHE'
    sys.path.insert(0,str(root/'distributed'));os.environ['CLOUDSDK_PYTHON']=sys.executable;os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
    from cloud_tools import ensure
    ensure()
    from cloud_results.common import read,write,sha,require,now
    from remote import Remote
    import topology
    source=read(input_root/'source-manifest.json');infra=read(input_root/'job/config.local.json')
    parent=root/'threshold-kms/runs'/(source['runName']+'-workflows-c3')
    segment=parent.with_name(source['runName']+'-workflows-c4')
    require(not segment.exists(),'Continuation already exists. Inspect instead of repeating preparation')
    proof=read(preflight/'prefix-validation.json');frontier=read(preflight/'frontier.json')
    require(proof['status']=='validated-completed-prefix-only','Unvalidated prefix')
    require(proof['applicationSha256']==sha(preflight/'prefix/reports/application.json')
        and proof['reconciliationSha256']==sha(preflight/'reconciliation.json'),'Prefix evidence changed')
    old=parent/'distributed/workflow-continuation';m=read(old/'manifest.json');p=read(old/'prepared.json')
    require(sha(old/'manifest.json')==p['manifestSha256'],'Predecessor manifest changed')
    oldcfg=read(preflight/'prefix/config/campaign.json');full=read(preflight/'prefix/fixtures/prepared.json')
    done,todo=frontier['completedCases'],frontier['remainingCases'];selected=select(full,done,todo)
    cfg=configuration(oldcfg,segment.name,done,todo);verify_config(oldcfg,cfg,done,todo)
    oldbase=p['newBase'];newbase='/srv/vcfhe/'+infra['campaign']+'/workflows-c4'
    # Copy only small management evidence. The large raw prefix remains immutable.
    segment.mkdir(mode=0o700)
    for name in ['distributed','terraform','network','validator-config']:
        if (parent/name).exists():shutil.copytree(parent/name,segment/name)
    (segment/'distributed/workflow-continuation').rename(segment/'distributed/predecessor-c3-management')
    c=segment/'distributed/workflow-continuation';c.mkdir(mode=0o700)
    scripts={}
    for name in ['owner.mjs','evaluate.mjs','admission.mjs']:
        require(sha(old/name)==m['overlays'][name]['overlaySha256'],'Measured predecessor overlay changed')
        scripts[name]=(old/name).read_text()
    oldprofile='distributed-same-keyset-workflows-only-v1'
    require(scripts['owner.mjs'].count(oldprofile)==1,'Owner restore profile anchor changed')
    scripts['owner.mjs']=scripts['owner.mjs'].replace(oldprofile,PROFILE)
    scripts['admission.mjs']=overlay(scripts['admission.mjs'])
    for name,text in scripts.items():(c/name).write_text(text)
    shutil.copy2(Path(__file__).with_name('guard.mjs'),c/'guard.mjs')
    shutil.copy2(preflight/'prefix-validation.json',c/'prefix-validation.json')
    budget=renewal(read(old/'budget-runtime.json'),now())
    write(c/'budget-runtime.json',budget,new=True);write(c/'config.json',cfg,new=True)
    manifest={**m,'profile':PROFILE,'continuationTag':'workflows-c4','parentRun':parent.name,
        'parentConfiguration':oldcfg,'completedCases':done,'fullCases':todo,
        'completedPrefixPath':str(preflight),'prefixValidationSha256':sha(c/'prefix-validation.json'),
        'overlays':{n:{'sourceSha256':sha(old/n),'overlaySha256':sha(c/n)} for n in scripts},
        'maintenanceSources':{f.name:sha(f) for f in Path(__file__).parent.iterdir() if f.is_file() and f.suffix in ('.py','.mjs')},
        'admissionControl':{**m.get('admissionControl',{}),'runtimeSha256':sha(c/'budget-runtime.json'),
            'renewedWindowHours':22,'originalCostClockPreserved':True},
        'recipientStartOrder':'first-release-candidate','fixtureCatalogs':{},'publicKeysetCopies':{},
        'publicationScope':'separate-segments-require-composite-validation'}
    write(c/'manifest.json',manifest,new=True)
    hosts=topology.hosts(infra);remotes={h['id']:Remote(infra,h) for h in hosts};nodes=topology.inventory(infra)
    # A new node view copies only pending ciphertexts and own owner state.
    # Old RPC journals, release evidence and exchange files remain only in C3.
    node_script=r'''
import json,sys,subprocess,shutil,hashlib
from pathlib import Path
v=json.loads(Path(sys.argv[1]).read_text());old=Path(v['old']);new=Path(v['new']);assert not new.exists()
new.mkdir(mode=0o700,parents=True)
for name in ['config','keyset','datasets']:
 if (old/name).exists():subprocess.run(['cp','-a','--reflink=auto',str(old/name),str(new/name)],check=True)
 else:(new/name).mkdir(mode=0o700)
for name in ['reports','fixtures','owner','transport','worker-rpc','owner-rpc','release-evidence','exchange','recipient']:(new/name).mkdir(mode=0o700)
for case in v['remaining']:
 for folder in ['fixtures','owner']:
  source=old/folder/case
  if source.exists():subprocess.run(['cp','-a','--reflink=auto',str(source),str(new/folder/case)],check=True)
if (old/'owner/expected.json').exists():shutil.copy2(old/'owner/expected.json',new/'owner/expected.json')
catalog=old/'fixtures/prepared.json'
if catalog.exists():
 data=json.loads(catalog.read_text());assert [c['name'] for c in data['cases']]==v['allCases']
 data['cases']=[c for c in data['cases'] if c['name'] in v['remaining']]
 assert [c['name'] for c in data['cases']]==v['remaining']
 assert all((new/'fixtures'/c['name']).is_dir() for c in data['cases'])
 (new/'fixtures/prepared.json').write_text(json.dumps(data,indent=2)+'\n')
for name in ['paired.json','distributed/byte-repeatability.json']:
 source=old/'reports'/name
 if source.exists():
  dest=new/'reports'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
(new/'config/start-role.json').unlink(missing_ok=True)
(new/'config/campaign.json').write_text(json.dumps(v['config'],indent=2)+'\n')
(new/'config/budget-runtime.json').write_text(json.dumps(v['budget'],indent=2)+'\n')
assert not list((new/'exchange').iterdir()) and not list((new/'recipient').iterdir())
subprocess.run(['chown','-R','10001:10001',str(new)],check=True)
f=new/'fixtures/prepared.json'
print(json.dumps({'node':v['node'],'catalogSha256':hashlib.sha256(f.read_bytes()).hexdigest() if f.exists() else None,'freshExchange':True,'reencrypted':False}))
'''
    inputs=c/'node-inputs';inputs.mkdir(mode=0o700)
    (inputs/'copy-node.py').write_text(node_script)
    for node in nodes:
        if node['role']=='validator':continue
        write(inputs/(node['id']+'.json'),{'node':node['id'],'old':oldbase+'/'+node['id'],
            'new':newbase+'/'+node['id'],'remaining':todo,'allCases':done+todo,'config':cfg,'budget':budget},new=True)
    def host_prepare(host):
        r=remotes[host['id']];free=int(r.text(['df','-B1','--output=avail','/srv/vcfhe']).splitlines()[-1])
        require(free>32*1024**3,'Insufficient data space for pending-case copy plus growth')
        dest=newbase+'/'+host['id']+'/preparation';r.upload(inputs,dest);rows=[]
        for node in nodes:
            if node['host']!=host['id'] or node['role']=='validator':continue
            rows.append(r.json(['sudo','python3',dest+'/copy-node.py',dest+'/'+node['id']+'.json']))
        return rows
    copied=list(ThreadPoolExecutor(max_workers=4).map(host_prepare,hosts))
    manifest['fixtureCatalogs']={v['node']:v['catalogSha256'] for rows in copied for v in rows if v['catalogSha256']}
    require({'coordinator-1','owner-1','owner-2','owner-3','owner-4'}<=set(manifest['fixtureCatalogs']),'Missing catalog')
    for host in hosts:
        compose=read(parent/'compose'/host['id']/'compose.json')
        for name,service in compose['services'].items():
            if name in ('init','setup','policy-init'):service['profiles']=['never-in-continuation']
            for mount in service.get('volumes',[]):
                if mount['target'] in ('/identity','/recipient-identity','/private','/public','/release-keyset') or name.startswith('validator-'):continue
                if mount['source'].startswith(oldbase+'/'):mount['source']=newbase+'/'+mount['source'][len(oldbase)+1:]
        dest=segment/'compose'/host['id'];write(dest/'compose.json',compose,new=True)
        remotes[host['id']].upload(dest,'/srv/vcfhe/'+infra['campaign']+'/'+host['id']+'/completed-prefix-compose')
    # Retain the existing scratch disk and path. A versioned collector checks
    # its exact disk ID and filesystem instead of deriving a different path.
    write(c/'manifest.json',manifest);write(segment/'distributed/workflow-continuation.json',manifest)
    for host in hosts:remotes[host['id']].upload(c,newbase+'/'+host['id']+'/continuation')
    write(segment/'launch-state.json',{'schema':'vcfhe-distributed-launch-v1','status':'workflow-continuation-prepared',
        'createdAt':now(),'config':infra,'stages':[],'completedPrefixCount':10,'pendingCount':17},new=True)
    job={**p['job'],'jobId':source['jobId']+'-workflows-c4'}
    receipt={'status':'prepared-not-started','newRun':str(segment),'parentRun':str(parent),'newBase':newbase,
        'manifestSha256':sha(c/'manifest.json'),'newCampaignConfigSha256':sha(c/'config.json'),
        'createdAt':now(),'job':job,'prefixValidationSha256':sha(c/'prefix-validation.json')}
    write(c/'prepared.json',receipt,new=True)
    print(json.dumps(receipt))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--preflight',required=True)
    a=p.parse_args();os.umask(0o077);main(a.input,a.preflight)
