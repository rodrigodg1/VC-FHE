#!/usr/bin/env python3
"""Explicit same-keyset continuation; the interrupted run is always read-only.

No setup, key generation, old exchange directory, pair replay or automatic resume.
An incomplete release/dispute in the completed prefix prevents this narrow recovery.
The original 197-source closure and image remain unchanged; overlays are inventoried.
"""
import argparse
import collections
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from docker_read import docker_read, require_running

HERE=Path(__file__).resolve().parent
MODULE=HERE.parent
ROOT=MODULE.parent
sys.path.insert(0,str(MODULE/'campaign'))
from poc_evidence import validate_pairs, validate_full_cases
from run import sha, write, resource_samples, stop_campaign_services, stop_oneshots
PROFILE='same-keyset-full-case-continuation-v1'

def read(path):return json.loads(Path(path).read_text())
def require(value,message):
    if not value:raise ValueError(message)

def ids(texts):
    # Ethereum Keccak, not hashlib SHA3. Inputs are public slot labels only.
    code='const {id}=require(process.argv[1]);let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>console.log(JSON.stringify(JSON.parse(s).map(id))));'
    return json.loads(subprocess.check_output(['node','-e',code,str(ROOT/'fhe-pod/node_modules/ethers')],input=json.dumps(texts),text=True))

def prefix_cases(cfg, app, prepared):
    wanted=[j for j in cfg['pocPlan']['jobs'] if j['fullCase']]
    count=len(app['cases'])
    require(0<count<len(wanted),'requires an incomplete, nonempty full-case prefix')
    require(app['kmsCalls']==count,'ambiguous/in-flight release count')
    for case,job in zip(app['cases'],wanted):
        require(all(case.get(k)==v for k,v in job.items()),'not the preselected completed prefix')
        require(case['finalOutputKmsCalls']==1,'incorrect per-case release count')
        if case['half']=='nonlinear':
            ds=case['metrics']['disputes'];terminal=case['metrics']['leaves']-1
            index={'early':0,'middle':terminal//2,'terminal':terminal}[job['faultPosition']]
            require(len(ds)==1 and ds[0]['faultIndex']==index and ds[0]['settlement']['state'][:3]==[3,2,True]
                    and ds[0]['settlement']['index']==index and case['metrics'].get('disputeCosts'),
                    'release completed without a complete dispute; cannot replay this case')
            certs=ds[0]['settlement']['certificates']
            require(len(certs)==2 and all(c['plaintextOpenings']==0 for c in certs),'invalid leaf evidence')
    byname={c['name']:c for c in prepared['cases']}
    require(len(byname)==len(prepared['cases']),'duplicate prepared case')
    remaining=[byname[j['name']] for j in wanted[count:]]
    require(all(c['half']=='nonlinear' for c in remaining),'recovery currently supports only a nonlinear suffix')
    return remaining

def capacity(remaining,ledger,limit):
    charges=collections.Counter(r for c in remaining for r in c['recordIds'])
    require(all(v['state']=='released' for v in ledger['slots'].values()),'reserved/uncertain release exists')
    for case in remaining:
        require(len(set(case['recordIds']))==case['n'],'duplicate/missing protected record')
        for rid,owner in zip(case['recordIds'],case['owners'],strict=True):
            old=ledger['records'].get(rid)
            if old:require(old['owner']==owner.lower() and old['limit']==limit,'changed record ownership/limit')
    left=[]
    for rid,charge in charges.items():
        old=ledger['records'].get(rid,{'spent':0,'limit':limit})
        require(type(old['spent']) is int and 0<=old['spent']<=old['limit'],'invalid ledger counter')
        left.append(old['limit']-old['spent']-charge)
    require(min(left)>=0,'remaining-case budget exhausted; never reset or increase counters')
    return {'releases':len(remaining),'records':len(charges),'maxAdditionalCharge':max(charges.values()),'minimumProjectedRemaining':min(left)}

def inspect(original):
    require(original.parent==MODULE/'runs','original must be a direct child of the campaign runs directory')
    state=read(original/'state.json');cfg=state['config'];app=read(original/'reports/application.json')
    require(state['status']=='failed' and app['status']=='failed' and not (original/'seal.json').exists(),'expected preserved failed run without completion seal')
    paired=read(original/'reports/paired.json');validate_pairs(cfg,paired)
    keys=read(original/'keyset/ready.json');prepared=read(original/'fixtures/prepared.json')
    require(keys==prepared['keys']==app['keys'] and keys['status']=='passed' and keys['fullPreprocessing']
            and not keys['preloadedFheKey'] and keys['parameters']=='Test','invalid original generated keyset')
    require(cfg==read(original/'config/campaign.json')==app['config'],'config divergence')
    require(app['plaintextInGateway'] is False,'plaintext boundary failure')
    cachekey=hashlib.sha256(json.dumps(state['source'],sort_keys=True).encode()).hexdigest()
    cache=MODULE/'.cache'/cachekey
    saved=read(cache/'complete.json')
    require(saved['source']==state['source'] and saved['upstream']==state['upstream'],'wrong source cache')
    for name,h in state['source'].items():
        require(sha(cache/'app'/name)==h and sha(ROOT/name)==h,'measured source changed: '+name)
    for name,h in state['datasets'].items():require(sha(ROOT/name)==h['sha256'],'source dataset changed')
    remaining=prefix_cases(cfg,app,prepared)
    expected=read(original/'owner/expected.json');count=len(app['cases'])
    for i,case in enumerate(app['cases']):
        r=read(original/f'recipient/result-{i}.json')
        require(r['name']==case['name'] and r['actual']==expected[case['name']] and r['outputDigest']==case['outputDigest'],'recipient mismatch')
        require([r[k] for k in ['responses','directUserAndPublicDenied','directAdministrativeDenied','changedSignedWireDenied','negativeResponseChecks']]==[3,4,28,4,4],'missing recipient security checks')
    for prefix in ['request','wire','approved','responses']:
        require({p.name for p in (original/'exchange').glob(prefix+'-*.json')}=={f'{prefix}-{i}.json' for i in range(count)},'uncertain exchange evidence: '+prefix)
    require({p.name for p in (original/'recipient').glob('result-*.json')}=={f'result-{i}.json' for i in range(count)},'unexpected recipient result')
    ledger_path=MODULE/'.policy-state/gateway/ledger.json'
    require(not ledger_path.with_suffix('.json.lock').exists(),'policy lock exists; manual diagnosis required')
    ledger=read(ledger_path);budget=capacity(remaining,ledger,cfg['ownerReleaseLimit'])
    slots=ids([f'{cfg["runId"]}:{c["name"]}:final' for c in remaining])
    require(not any(s in ledger['slots'] for s in slots),'remaining slot already consumed')
    for i in range(count):
        request=read(original/f'exchange/wire-{i}.json')['request']
        slot=ledger['slots'].get(request['slot'],{})
        require(slot.get('state')=='released' and slot.get('requestId')==request['requestId']
                and slot.get('kmsRequestDigest')==request['kmsRequestDigest'],'completed release missing in cumulative ledger')
    return state,prepared,remaining,cache,{'profile':PROFILE,'originalRun':str(original),
        'sourceCount':len(state['source']),'imageId':state['imageId'],'designSha256':paired['designSha256'],
        'completedCases':count,'remainingCases':[c['name'] for c in remaining],'remainingSlots':slots,
        'budget':budget,'ledgerSha256Before':sha(ledger_path),'analysisComplete':False}

def check_contexts(original,state,plan):
    args=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
          '--security-opt','no-new-privileges:true','--entrypoint','node',
          '-e','VCFHE_RECOVERY_NAMES='+json.dumps(plan['remainingCases'])]
    for source,target in [(original/d,'/'+d) for d in ['config','fixtures','owner','reports','keyset']]+[
        (original/'bin','/preserved-bin'),(HERE/'check-contexts.mjs','/app/threshold-kms/campaign/recovery-check.mjs')]:
        args+=['--mount',f'type=bind,source={source},target={target},readonly']
    return json.loads(subprocess.check_output(args+[state['imageId'],'/app/threshold-kms/campaign/recovery-check.mjs'],text=True,timeout=90))

def inventory(root):
    result={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink():result[str(p.relative_to(root))]={'symlink':os.readlink(p)}
        elif p.is_file():result[str(p.relative_to(root))]=sha(p)
    return result

def verify_inventory(root,files):
    for name,digest in files.items():
        p=root/name
        if isinstance(digest,dict):require(p.is_symlink() and os.readlink(p)==digest['symlink'],'changed original link: '+name)
        else:require(not p.is_symlink() and sha(p)==digest,'changed original evidence: '+name)

def overlay(source,needle,replacement):
    require(source.count(needle)==1,'overlay anchor changed')
    return source.replace(needle,replacement)

def validate_compose(compose,original,segment,image):
    require(set(compose['services'])=={'kms1','kms2','kms3','kms4','public-store','owner','evaluate','worker','recipient'},'unexpected recovery role/setup')
    for role,s in compose['services'].items():
        require(s['image']==image and s['read_only'] and s['cap_drop']==['ALL'] and not s.get('ports'),'weakened container boundary')
        for m in s['volumes']:
            if Path(m['source']).is_relative_to(original):require(m['read_only'],'original run mounted writable')
            if m['target']=='/private':
                require(role in ['kms1','kms2','kms3','kms4'] and m['source']==str(segment/('private-'+role[-1])),'cross-party vault mount')
            require(m['target']!='/setup-identity','setup identity forbidden during recovery')
            if role in ['evaluate','worker']:
                require(not m['target'].startswith(('/owner-identity','/recipient-identity','/private','/datasets','/owner/')) and m['target']!='/owner','private role leakage')
    require(compose['services']['worker']['network_mode']=='none','worker network enabled')
    for role in ['owner','evaluate']:require(compose['services'][role]['networks']==['besu'],'application gained KMS network')
    require(compose['services']['recipient']['networks']==['kms'] and compose['networks']['kms']['internal'],'recipient/core ingress changed')

def prepare_segment(original,segment,state,prepared,remaining,cache,plan):
    segment.mkdir(mode=0o700)
    # This inventory is a preservation checkpoint, NOT a passing campaign seal.
    write(segment/'original-preservation.json',{'classification':'failed-run-preservation-only','files':inventory(original)})
    for folder in ['config','public',*[f'private-{i}' for i in range(1,5)]]:
        shutil.copytree(original/folder,segment/folder)
    for folder in ['fixtures','reports','recipient','exchange','owner-rpc','worker-rpc','overlays']:(segment/folder).mkdir(mode=0o700)
    for case in remaining:
        # Only the originally encrypted public input closure; all evaluations are fresh.
        target=segment/'fixtures'/case['name'];target.mkdir()
        shutil.copytree(original/'fixtures'/case['name']/'public',target/'public')
    write(segment/'fixtures/prepared.json',{**prepared,'cases':remaining})
    write(segment/'reports/ledger-before.json',read(MODULE/'.policy-state/gateway/ledger.json'))
    # The aborted case may already have immutable consent for its old deployment.
    # New deployments receive NEW all-owner consents/slots; the original consent
    # is preserved, never overwritten. Cumulative protected-record counters stay.
    cfg={**state['config'],'runId':segment.name,'recovery':plan}
    write(segment/'config/campaign.json',cfg)
    owner=(cache/'app/threshold-kms/campaign/owner.mjs').read_text()
    evaluator=(cache/'app/threshold-kms/campaign/evaluate.mjs').read_text()
    (segment/'overlays/owner.mjs').write_text(overlay(owner,'await prepare();',(HERE/'owner-restore.mjs').read_text()))
    guard="assert.equal(cfg.recovery.profile, '"+PROFILE+"');\n assert.deepEqual(prepared.cases.map(c=>c.name),cfg.recovery.remainingCases);\n await waitFile('/owner-rpc/recovery-ready.json',60);"
    (segment/'overlays/evaluate.mjs').write_text(overlay(evaluator,'if(cfg.pocPlan)await runPairs(cfg,prepared);',guard))
    compose=read(original/'compose.json')
    compose['name']='vcfhe-recovery-'+segment.name[-12:].lower()
    compose['services']={k:v for k,v in compose['services'].items() if k not in ['identities','init','setup']}
    for role,service in compose['services'].items():
        service['image']=state['imageId']
        for m in service['volumes']:
            src=Path(m['source'])
            if src.is_relative_to(original):
                rel=src.relative_to(original)
                if rel.parts[0] in ['keyset','owner']:
                    m['read_only']=True
                else:m['source']=str(segment/rel)
        if role=='owner':
            service['volumes']=[m for m in service['volumes'] if not m['target'].startswith('/datasets')]
            for m in service['volumes']:
                if m['target']=='/fixtures':m['read_only']=True
        if role in ['owner','evaluate']:
            service['volumes'].append({'type':'bind','source':str(segment/'overlays'/f'{role}.mjs'),
                'target':f'/app/threshold-kms/campaign/{role}.mjs','read_only':True})
    validate_compose(compose,original,segment,state['imageId'])
    write(segment/'compose.json',compose)
    closure={p.name:sha(p) for p in HERE.iterdir() if p.is_file() and p.suffix in ['.py','.mjs']}
    plan={**plan,'recoverySource':closure,'overlays':inventory(segment/'overlays'),
          'preservationSha256':sha(segment/'original-preservation.json'),'configSha256':sha(segment/'config/campaign.json'),
          'composeSha256':sha(segment/'compose.json'),'preparedSha256':sha(segment/'fixtures/prepared.json')}
    write(segment/'plan.json',plan)
    return compose,plan

def no_live_kms():
    running=json.loads('['+','.join(docker_read(['docker','ps','--format','{{json .}}']).splitlines())+']')
    require(not any('vcfhe-kms-' in r['Names'] or 'vcfhe-recovery-' in r['Names'] for r in running),'another KMS/application deployment is live')

def execute(original,segment,state,prepared,remaining,cache,plan,retry_preparation=False):
    require(shutil.disk_usage(original).free>20*2**30,'insufficient disk reserve')
    no_live_kms()
    require(docker_read(['docker','image','inspect',state['imageId'],'--format','{{.Id}}'])==state['imageId'],'original image absent')
    claims=MODULE/'.policy-state/recovery-claims';claims.mkdir(exist_ok=True,mode=0o700)
    claim=claims/(original.name+'.json')
    attempts=[]
    if claim.exists():
        require(retry_preparation,'a continuation was already claimed; inspect it, never automatically replay')
        prior=read(claim);prior_segment=Path(prior['segment'])
        # Only an EMPTY directory left by the failed initial inventory is eligible.
        # No prepared fixture, state, compose, exchange or startup can have existed.
        require(prior_segment.parent==MODULE/'runs' and prior_segment.is_dir() and not list(prior_segment.iterdir()),'prior preparation is not empty; no automatic retry')
        require(prior.get('phase','preparing')=='preparing','prior continuation may have started')
        require(not docker_read(['docker','ps','-a','-q','--filter','label=com.docker.compose.project=vcfhe-recovery-'+prior_segment.name[-12:].lower()]),'prior containers exist')
        attempts=prior.get('preparationAttempts',[])+[prior]
        write(claim,{'original':str(original),'segment':str(segment),'profile':PROFILE,'phase':'preparing','preparationAttempts':attempts})
    else:
        require(not retry_preparation,'no prior preparation to retry')
        with claim.open('x') as f:
            json.dump({'original':str(original),'segment':str(segment),'profile':PROFILE,'phase':'preparing'},f);f.flush();os.fsync(f.fileno())
    compose,plan=prepare_segment(original,segment,state,prepared,remaining,cache,plan)
    cmd=['docker','compose','-f',str(segment/'compose.json')]
    status={'profile':PROFILE,'status':'preparing','originalRun':str(original),'planSha256':sha(segment/'plan.json')}
    write(segment/'state.json',status)
    print('RECOVERY_DIRECTORY '+str(segment),flush=True)
    # Copying vaults is safe only with the global lock, no live predecessor, and no
    # consumed remaining slots. Original vaults are never run or rolled back here.
    require(sha(MODULE/'.policy-state/gateway/ledger.json')==plan['ledgerSha256Before'],'ledger changed during preparation')
    proc=None
    try:
        # Parse both exact overlays in the original image before starting roles.
        for role in ['owner','evaluate']:
            subprocess.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
                '--mount',f'type=bind,source={segment/"overlays"},target=/overlays,readonly',
                '--entrypoint','node',state['imageId'],'--check',f'/overlays/{role}.mjs'],check=True,timeout=30)
        write(claim,{**read(claim),'phase':'startup-armed'})
        subprocess.run(cmd+['up','-d','--wait','--wait-timeout','120','kms1','kms2','kms3','kms4','public-store'],check=True)
        subprocess.run(cmd+['up','-d','owner','worker','recipient'],check=True)
        status['status']='running';write(segment/'state.json',status)
        with (segment/'evaluation.log').open('x') as log,resource_samples(segment,cmd,'recovery-evaluation'):
            proc=subprocess.Popen(cmd+['run','--rm','evaluate'],stdout=log,stderr=subprocess.STDOUT)
            start=time.monotonic();next_check=start
            while proc.poll() is None:
                if time.monotonic()-start>state['config']['timeoutSeconds']:raise TimeoutError('continuation deadline reached')
                require(shutil.disk_usage(segment).free>5*2**30,'disk reserve reached')
                if time.monotonic()>=next_check:
                    require_running(cmd,['kms1','kms2','kms3','kms4','owner','worker','recipient'],(segment/'exchange/complete.json').exists())
                    next_check=time.monotonic()+15
                time.sleep(1)
            require(proc.returncode==0,'continuation application failed; preserve and inspect, never replay')
        app=read(segment/'reports/application.json');require(app['status']=='passed','missing continuation completion')
        require([c['name'] for c in app['cases']]==plan['remainingCases'] and app['kmsCalls']==len(remaining),'wrong continuation coverage')
        prior=read(original/'reports/application.json')
        combined={**app,'cases':prior['cases']+app['cases'],'kmsCalls':prior['kmsCalls']+app['kmsCalls']}
        # Uses the original full-grid validator; not a weakened partial-analysis validation.
        validate_full_cases(state['config'],combined,read(original/'reports/paired.json'))
        expected=read(original/'owner/expected.json')
        for i,c in enumerate(app['cases']):
            r=read(segment/f'recipient/result-{i}.json')
            require(r['name']==c['name'] and r['actual']==expected[c['name']] and r['outputDigest']==c['outputDigest'],'recovered output mismatch')
            require([r[k] for k in ['responses','directUserAndPublicDenied','directAdministrativeDenied','changedSignedWireDenied','negativeResponseChecks']]==[3,4,28,4,4],'missing recipient checks')
        before=read(segment/'reports/ledger-before.json');after=read(MODULE/'.policy-state/gateway/ledger.json')
        require(all(after['slots'].get(k)==v for k,v in before['slots'].items()),'prior policy slots changed')
        new_slots=set(after['slots'])-set(before['slots'])
        expected_slots=set(ids([f'{segment.name}:{c["name"]}:final' for c in remaining]))
        require(new_slots==expected_slots and all(after['slots'][s]['state']=='released' for s in new_slots),'unexpected continuation release slots')
        charges=collections.Counter(r for c in remaining for r in c['recordIds'])
        for rid,record in after['records'].items():
            require(record['spent']==before['records'].get(rid,{'spent':0})['spent']+charges[rid], 'unexpected cumulative ledger delta')
        verify_inventory(original,read(segment/'original-preservation.json')['files'])
        require(all(sha(HERE/n)==h for n,h in plan['recoverySource'].items()),'recovery code changed while measuring')
        status['status']='passed';status['analysisComplete']=False
        status['pending']='Composite provenance verification, workflow-stage export, diagnostic review and implementation gate remain required.'
        write(segment/'state.json',status)
        public_files={str(p.relative_to(segment)):sha(p) for folder in ['reports','fixtures','config','overlays'] for p in (segment/folder).rglob('*') if p.is_file()}
        public_files.update({str(p.relative_to(segment)):sha(p) for p in (segment/'recipient').glob('result-*.json')})
        for n in ['plan.json','state.json','compose.json','original-preservation.json']:public_files[n]=sha(segment/n)
        write(segment/'segment-seal.json',{'profile':PROFILE,'classification':'continuation-not-standalone-evaluation','files':public_files})
        print('CONTINUATION_PASSED; composite analysis validation still required',flush=True)
    except BaseException as e:
        status.update(status='failed',error=str(e));write(segment/'state.json',status);raise
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        try:stop_campaign_services(cmd);stop_oneshots(segment/'compose.json')
        except subprocess.SubprocessError as e:print('CLEANUP_REQUIRES_ATTENTION '+str(e),flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--original',type=Path,required=True)
    p.add_argument('--execute',action='store_true');p.add_argument('--segment',type=Path)
    p.add_argument('--check-contexts',action='store_true',help='read-only original-image/context/binary check; no KMS or transactions')
    p.add_argument('--retry-empty-preparation',action='store_true',help='explicitly recover only an empty pre-inventory directory; never a started continuation')
    a=p.parse_args();original=a.original.resolve()
    with (MODULE/'.cache/campaign.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        result=inspect(original);print(json.dumps(result[-1],indent=2),flush=True)
        if a.check_contexts or a.execute:
            print('CONTEXT_CHECK '+json.dumps(check_contexts(original,result[0],result[-1])),flush=True)
        if a.execute:
            segment=a.segment.resolve() if a.segment else MODULE/'runs'/('recovery-'+time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8])
            require(not segment.exists() and segment.parent==MODULE/'runs','new direct child of runs required; automatic recovery replay is forbidden')
            execute(original,segment,*result,retry_preparation=a.retry_empty_preparation)

if __name__=='__main__':main()
