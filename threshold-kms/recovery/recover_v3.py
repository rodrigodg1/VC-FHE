#!/usr/bin/env python3
"""Explicit same-keyset continuation for an interrupted V3 (on-chain policy) run.

Operator-invoked, never automatic. The predecessor run is read-only. Its fully
settled cases are kept; the remaining preselected cases run in a fresh segment
with fresh deployments, consents and release slots under the same policy lineage,
keyset, PRSS/threshold vaults, owner identities and paired measurements. No request,
transaction or release that reached the chain or the KMS is replayed. A case whose
release completed but whose dispute did not settle is re-run in full; its first
reservation stays consumed and is reported. A failed continuation is continued
from that failed segment, never retried in place.
"""
import argparse
import collections
import fcntl
import hashlib
import json
import os
import re
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
from onchain_evidence import validate_run
from run import VERSION, sha, write, resource_samples, stop_campaign_services, stop_oneshots
PROFILE='same-keyset-full-case-continuation-v3'
RESULT_CHECKS={'responses':3,'directUserAndPublicDenied':4,'directAdministrativeDenied':28,
               'changedReservedWireDenied':4,'negativeResponseChecks':4}
SETUP_ROLES={'identities','init','setup','policy-init'}
LIVE_ROLES=['kms1','kms2','kms3','kms4','owner','worker','recipient']

def read(path):return json.loads(Path(path).read_text())
def require(value,message):
    if not value:raise ValueError(message)
def slot_label(run_id,name):return f'{run_id}:{name}:final:onchain-v3'

def planned_names(cfg,prepared):
    """Preselected full cases in execution order."""
    plan=cfg.get('pocPlan')
    if plan:return [j['name'] for j in plan['jobs'] if j['fullCase']]
    return [c['name'] for c in prepared['cases']]

def settled(case,cfg):
    """True when the case's single release and (nonlinear) dispute are complete."""
    if case.get('finalOutputKmsCalls')!=1:return False
    if case['half']=='linear':return True
    ds=case.get('metrics',{}).get('disputes',[])
    if len(ds)!=1 or not case['metrics'].get('disputeCosts'):return False
    d=ds[0];terminal=case['metrics']['leaves']-1
    position=case.get('faultPosition')
    index=(terminal if cfg.get('readinessOnly') else
           {'early':0,'middle':terminal//2,'terminal':terminal}[position] if position else d['faultIndex'])
    certs=d['settlement'].get('certificates',[])
    return (d['faultIndex']==index and d['settlement']['state'][:3]==[3,2,True]
            and d['settlement']['index']==index and len(certs)==2
            and all(c['plaintextOpenings']==0 for c in certs))

def check_result(result,case,expected):
    require(result['name']==case['name'] and result['actual']==expected[case['name']]
            and result['outputDigest']==case['outputDigest'],'recipient correctness/output binding failure: '+case['name'])
    require(all(result[k]==v for k,v in RESULT_CHECKS.items()),'missing threshold/ingress validation: '+case['name'])

def split_prefix(cases,remaining,cfg,results,expected):
    """Return (settled rows, re-run names). Only the last row may be unsettled."""
    require(len(cases)<=len(remaining),'more cases than planned')
    kept,redo=[],[]
    for i,case in enumerate(cases):
        require(case['name']==remaining[i],'cases are not the preselected order')
        require(i in results,'released case without recipient result: '+case['name'])
        check_result(results[i],case,expected)
        if settled(case,cfg):
            require(not redo,'settled case after an unsettled case')
            kept.append((i,case))
        else:
            require(i==len(cases)-1,'unsettled case before the last completed release')
            redo.append(case['name'])
    return kept,redo

# A defect is diagnosed and fixed with a fresh run, never continued. Only an
# interruption of the normal runner (operator SIGINT, host/runner death, Docker
# daemon loss, killed container, infrastructure timeout) is eligible.
LOGIC_FAILURE=re.compile(r'\b(AssertionError|ERR_ASSERTION|TypeError|ReferenceError|SyntaxError|RangeError)\b'
                         r'|correctness|binding failure|one response accepted|signature fallback|decrypt admitted'
                         r'|decrypt enabled|unguarded administrative|wire admitted|panicked')
INFRASTRUCTURE=re.compile(r'docker daemon|cannot connect to the docker|docker control-plane|timed? ?out|timeout'
                          r'|disk reserve|econnrefused|econnreset|socket hang up|could not detect network'
                          r'|campaign interrupted|failed service',re.I)

def interruption_cause(run,state,app):
    """Classify why the predecessor stopped; refuse anything that is not an interruption."""
    log=(run/'evaluation.log').read_text(errors='replace')[-50000:] if (run/'evaluation.log').exists() else ''
    error=str(state.get('error',''));app_error=str(app.get('error',''))
    signal='campaign interrupted: SIG' in app_error
    if LOGIC_FAILURE.search(log+'\n'+app_error) and not signal:
        raise ValueError('predecessor stopped on a correctness/security or code failure; diagnose and use a fresh run')
    if state['status']=='interrupted':return 'operator interrupt'
    if state['status'] in ('running','preparing'):return 'runner or host terminated abruptly'
    killed=re.search(r'exited \(code (\d+), OOM=(True|False)\)',error)
    if killed:
        require(killed.group(2)=='True' or int(killed.group(1)) in (137,143),
                'a service exited on its own checks; diagnose and use a fresh run')
        return 'service killed'
    require(INFRASTRUCTURE.search(error+'\n'+log[-4000:]+'\n'+app_error),
            'unclassified failure; diagnose before any continuation')
    return 'infrastructure interruption'

def run_chain_read(image,config_dir,records,slots):
    args=['docker','run','--rm','--network','vcfhe-besu_default','--read-only','--cap-drop','ALL',
          '--security-opt','no-new-privileges:true','--tmpfs','/tmp','--entrypoint','node',
          '-e','VCFHE_RECOVERY_READ='+json.dumps({'records':sorted(set(records)),'slots':sorted(set(slots))}),
          '--mount',f'type=bind,source={config_dir},target=/config,readonly',
          '--mount',f'type=bind,source={HERE/"v3-chain-read.mjs"},target=/app/threshold-kms/campaign/recovery-v3-read.mjs,readonly',
          image,'/app/threshold-kms/campaign/recovery-v3-read.mjs']
    return json.loads(subprocess.check_output(args,text=True,timeout=180).strip().splitlines()[-1])

def inspect(original):
    require(original.parent==MODULE/'runs','predecessor must be a direct child of the campaign runs directory')
    require(not (original/'seal.json').exists() and not (original/'segment-seal.json').exists(),
            'predecessor completed; nothing to continue')
    state=read(original/'state.json')
    # 'running' is accepted only because main() holds the campaign lock: no runner is alive.
    require(state['status'] in ('failed','interrupted','running','preparing'),'predecessor is not an interrupted run')
    cfg=state['config'];recovery=cfg.get('recovery')
    require(cfg['version']==VERSION,'not a V3 campaign run')
    require(not cfg.get('policyRefreshPlan'),'V3 policy refresh has its own recovery rule')
    require(cfg['parameters']=='Test','continuation is defined only for insecure Test evidence')
    base=Path(recovery['baseRun']) if recovery else original
    base_state=read(base/'state.json');base_cfg=base_state['config']
    require({k:v for k,v in cfg.items() if k not in ('runId','recovery')}==
            {k:v for k,v in base_cfg.items() if k not in ('runId','recovery')},'configuration differs from the base run')
    keys=read(base/'keyset/ready.json');base_prepared=read(base/'fixtures/prepared.json')
    require(keys==base_prepared['keys'] and keys['status']=='passed' and keys['fullPreprocessing']
            and not keys['preloadedFheKey'] and keys['parameters']=='Test','invalid generated keyset')
    paired=None
    if base_cfg.get('pocPlan'):
        require((base/'reports/paired.json').exists(),'paired phase incomplete; a fresh run consumes no release budget')
        paired=read(base/'reports/paired.json');validate_pairs(base_cfg,paired)
    # The overlays and measured code must be exactly the base run's source closure.
    cache=MODULE/'.cache'/hashlib.sha256(json.dumps(base_state['source'],sort_keys=True).encode()).hexdigest()
    saved=read(cache/'complete.json')
    require(saved['source']==base_state['source'] and saved['upstream']==base_state['upstream'],'wrong source cache')
    for name,h in base_state['source'].items():
        require(sha(cache/'app'/name)==h and sha(ROOT/name)==h,'measured source changed: '+name)
    for name,h in base_state['datasets'].items():require(sha(ROOT/name)==h['sha256'],'source dataset changed')
    expected=read(base/'owner/expected.json')
    remaining=recovery['remainingCases'] if recovery else planned_names(base_cfg,base_prepared)
    app_path=original/'reports/application.json'
    if app_path.exists():
        app=read(app_path)
        require(app['config']==cfg and app['keys']==keys,'application evidence differs from its configuration')
        require(app['status'] in ('failed','running'),'predecessor application passed; use export, not continuation')
        cases=app['cases']
    else:
        # Only a continuation that stopped before its evaluator started.
        require(recovery is not None and not list((original/'exchange').glob('request-*.json')),
                'missing application evidence after release requests')
        app,cases={'kmsCalls':0},[]
    cause=interruption_cause(original,state,app)
    results={int(p.stem.split('-')[1]):read(p) for p in (original/'recipient').glob('result-*.json')}
    kept,redo=split_prefix(cases,remaining,cfg,results,expected)
    left=remaining[len(kept):]
    require(left,'no remaining cases')
    # Releases decrypted beyond the saved rows are abandoned, never replayed.
    abandoned_results=sorted(i for i in results if i>=len(kept))
    completed=(recovery['completed'] if recovery else [])+[{'run':str(original),'index':i,'name':c['name']} for i,c in kept]
    byname={c['name']:c for c in base_prepared['cases']}
    return {'original':original,'base':base,'state':base_state,'cfg':cfg,'baseCfg':base_cfg,'keys':keys,
            'prepared':base_prepared,'paired':paired,'cache':cache,'expected':expected,
            'remaining':[byname[n] for n in left],'plan':{
                'profile':PROFILE,'baseRun':str(base),'predecessor':str(original),'predecessorRunId':cfg['runId'],
                'interruption':cause,
                'completed':completed,'remainingCases':left,'rerunUnsettled':redo,
                'predecessorKmsCalls':app['kmsCalls'],'predecessorSavedCases':len(cases),
                'abandonedRecipientResults':abandoned_results,
                'abandonedSlots':[slot_label(cfg['runId'],n) for n in left],
                'priorAbandoned':recovery.get('abandoned',[]) if recovery else [],
                'imageId':base_state['imageId'],'designSha256':paired['designSha256'] if paired else None,
                'analysisComplete':False}}

def validate_compose(compose,info,segment):
    require(set(compose['services'])=={'kms1','kms2','kms3','kms4','public-store','owner','evaluate','worker','recipient'},
            'unexpected continuation role/setup')
    for role,s in compose['services'].items():
        require(s['image']==info['state']['imageId'] and s['read_only'] and s['cap_drop']==['ALL'] and not s.get('ports'),
                'weakened container boundary')
        for m in s['volumes']:
            src=Path(m['source'])
            for old in {info['base'],info['original']}:
                if src.is_relative_to(old):require(m['read_only'],'predecessor evidence mounted writable')
            if m['target']=='/private':
                require(role in ['kms1','kms2','kms3','kms4'] and m['source']==str(segment/('private-'+role[-1])),'cross-party vault mount')
            require(m['target']!='/setup-identity' and not m['target'].startswith('/datasets'),'setup identity or dataset mounted')
            if role in ['evaluate','worker']:
                require(not m['target'].startswith(('/owner-identity','/recipient-identity','/private','/owner/'))
                        and m['target']!='/owner','private role leakage')
    require(compose['services']['worker']['network_mode']=='none','worker network enabled')
    for role in ['owner','evaluate']:require(compose['services'][role]['networks']==['besu'],'application gained KMS network')
    require(compose['services']['recipient']['networks']==['kms'] and compose['networks']['kms']['internal'],
            'recipient/core ingress changed')

def overlay(source,needle,replacement):
    require(source.count(needle)==1,'overlay anchor changed')
    return source.replace(needle,replacement)

def prepare_segment(info,segment):
    original,base=info['original'],info['base']
    segment.mkdir(mode=0o700)
    # Latest state of each party: vaults/public material/owner store from the predecessor.
    for folder in ['config','public','owner',*[f'private-{i}' for i in range(1,5)]]:
        shutil.copytree(original/folder,segment/folder,symlinks=True)
    for folder in ['fixtures','reports','recipient','exchange','owner-rpc','worker-rpc','release-evidence','overlays']:
        (segment/folder).mkdir(mode=0o700)
    for case in info['remaining']:
        target=segment/'fixtures'/case['name'];target.mkdir(mode=0o700)
        if case['half']=='nonlinear':
            # Only the owner's originally encrypted public closure; every evaluation is fresh.
            shutil.copytree(base/'fixtures'/case['name']/'public',target/'public')
        else:
            # Exactly the files the owner originally published from its private store.
            for p in sorted((base/'owner'/case['name']).iterdir()):
                if p.is_file() and (p.suffix=='.bin' or p.name=='coordinates.json'):shutil.copy2(p,target/p.name)
    write(segment/'fixtures/prepared.json',{**info['prepared'],'cases':info['remaining']})
    cfg={**info['cfg'],'runId':segment.name,'recovery':info['plan']}
    write(segment/'config/campaign.json',cfg)
    src=info['cache']/'app/threshold-kms/campaign'
    (segment/'overlays/owner.mjs').write_text(overlay((src/'owner.mjs').read_text(),'await prepare();',
                                                      (HERE/'owner-restore-v3.mjs').read_text()))
    guard=("assert.equal(cfg.recovery.profile,'"+PROFILE+"');\n"
           " assert.deepEqual(prepared.cases.map(c=>c.name),cfg.recovery.remainingCases);\n"
           " await waitFile('/owner-rpc/recovery-ready.json',cfg.timeoutSeconds);")
    (segment/'overlays/evaluate.mjs').write_text(overlay((src/'evaluate.mjs').read_text(),
                                                         'if(cfg.pocPlan)await runPairs(cfg,prepared);',guard))
    compose=read(base/'compose.json')
    compose['name']='vcfhe-cont-'+segment.name[-12:].lower()
    compose['services']={k:v for k,v in compose['services'].items() if k not in SETUP_ROLES}
    for role,service in compose['services'].items():
        service['image']=info['state']['imageId']
        for m in service['volumes']:
            s=Path(m['source'])
            if s.is_relative_to(base):
                rel=s.relative_to(base)
                if rel.parts[0]=='keyset':m['read_only']=True
                else:m['source']=str(segment/rel)
        if role=='owner':
            service['volumes']=[m for m in service['volumes'] if not m['target'].startswith('/datasets')]
            for m in service['volumes']:
                if m['target']=='/fixtures':m['read_only']=True
        if role in ['owner','evaluate']:
            service['volumes'].append({'type':'bind','source':str(segment/'overlays'/f'{role}.mjs'),
                                       'target':f'/app/threshold-kms/campaign/{role}.mjs','read_only':True})
    validate_compose(compose,info,segment)
    write(segment/'compose.json',compose)
    plan={**info['plan'],'segment':str(segment),
          'recoverySource':{p.name:sha(p) for p in HERE.iterdir() if p.is_file() and p.suffix in ['.py','.mjs']},
          'overlays':{p.name:sha(p) for p in (segment/'overlays').iterdir()},
          'configSha256':sha(segment/'config/campaign.json'),'composeSha256':sha(segment/'compose.json'),
          'preparedSha256':sha(segment/'fixtures/prepared.json')}
    write(segment/'plan.json',plan)
    return cfg,plan

def ensure_besu(base):
    ids=docker_read(['docker','ps','-q','--filter','label=com.docker.compose.project=vcfhe-besu']).split()
    if len(ids)<4:
        # Chain data volumes persist; this only restarts the same four validators.
        subprocess.run(['docker','compose','-p','vcfhe-besu','-f',str(base/'besu.json'),'up','-d','--wait',
                        '--wait-timeout','180','node1','node2','node3','node4'],check=True)

def no_live_campaign():
    running=json.loads('['+','.join(docker_read(['docker','ps','--format','{{json .}}']).splitlines())+']')
    require(not any(n in r['Names'] for r in running for n in ['vcfhe-kms-','vcfhe-recovery-','vcfhe-cont-']),
            'another KMS/application deployment is live')

def charges(cases):return collections.Counter(r for c in cases for r in c['recordIds'])

def budget_gate(info,snapshot):
    need=charges(info['remaining'])
    for c in info['remaining']:
        for rid,limit in zip(c['recordIds'],c['releaseLimits'],strict=True):
            spent=snapshot['records'][rid]['spent']
            require(spent+need[rid]<=limit,'remaining-case budget exhausted; never reset or increase counters')
    left=[c['releaseLimits'][i]-snapshot['records'][rid]['spent']-need[rid]
          for c in info['remaining'] for i,rid in enumerate(c['recordIds'])]
    return {'releases':len(info['remaining']),'records':len(need),'maxAdditionalCharge':max(need.values()),
            'minimumProjectedRemaining':min(left)}

def completed_rows(completed):
    apps={}
    rows=[]
    for entry in completed:
        run=Path(entry['run'])
        apps.setdefault(run,read(run/'reports/application.json'))
        row=apps[run]['cases'][entry['index']];require(row['name']==entry['name'],'completed-case index changed')
        rows.append(row)
    return rows

def execute(info,segment):
    original,base,cfg0=info['original'],info['base'],info['cfg']
    require(shutil.disk_usage(original).free>20*2**30,'insufficient disk reserve')
    no_live_campaign()
    image=info['state']['imageId']
    require(docker_read(['docker','image','inspect',image,'--format','{{.Id}}'])==image,'original image absent')
    ensure_besu(base)
    all_ids=[r for c in info['prepared']['cases'] for r in c['recordIds']]
    before=run_chain_read(image,original/'config',all_ids,info['plan']['abandonedSlots'])
    abandoned=[{'run':str(original),'name':label.split(':')[1],'slot':label,'requestId':row['requestId']}
               for label,row in before['slots'].items() if int(row['requestId'],16)!=0]
    info['plan'].update(budget=budget_gate(info,before),recordSnapshotBefore=before,
                        abandoned=info['plan']['priorAbandoned']+abandoned)
    claims=MODULE/'.policy-state/recovery-claims';claims.mkdir(exist_ok=True,mode=0o700)
    claim=claims/(original.name+'.v3.json')
    with claim.open('x') as f:
        json.dump({'predecessor':str(original),'segment':str(segment),'profile':PROFILE,'phase':'preparing'},f)
        f.flush();os.fsync(f.fileno())
    cfg,plan=prepare_segment(info,segment)
    cmd=['docker','compose','-f',str(segment/'compose.json')]
    status={'version':VERSION,'profile':PROFILE,'status':'preparing','config':cfg,'source':info['state']['source'],
            'upstream':info['state']['upstream'],'datasets':info['state']['datasets'],'imageId':image,
            'predecessor':str(original),'baseRun':str(base),'planSha256':sha(segment/'plan.json')}
    write(segment/'state.json',status)
    print('RECOVERY_DIRECTORY '+str(segment),flush=True)
    print('PLAN '+json.dumps({k:plan[k] for k in ['remainingCases','rerunUnsettled','budget']}),flush=True)
    proc=None
    try:
        for role in ['owner','evaluate']:
            subprocess.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
                '--mount',f'type=bind,source={segment/"overlays"},target=/overlays,readonly',
                '--entrypoint','node',image,'--check',f'/overlays/{role}.mjs'],check=True,timeout=30)
        write(claim,{**read(claim),'phase':'startup-armed'})
        print('STAGE kms-cores',flush=True)
        subprocess.run(cmd+['up','-d','--wait','--wait-timeout','180','kms1','kms2','kms3','kms4','public-store'],check=True)
        print('STAGE services',flush=True)
        subprocess.run(cmd+['up','-d','owner','worker','recipient'],check=True)
        status['status']='running';write(segment/'state.json',status)
        print('STAGE evaluation',flush=True)
        with (segment/'evaluation.log').open('x') as log,resource_samples(segment,cmd,'recovery-evaluation'):
            proc=subprocess.Popen(cmd+['run','--rm','evaluate'],stdout=log,stderr=subprocess.STDOUT)
            start=time.monotonic();next_check=start
            while proc.poll() is None:
                if time.monotonic()-start>cfg['timeoutSeconds']:raise TimeoutError('continuation deadline reached')
                require(shutil.disk_usage(segment).free>5*2**30,'disk reserve reached')
                if time.monotonic()>=next_check:
                    require_running(cmd,LIVE_ROLES,(segment/'exchange/complete.json').exists())
                    next_check=time.monotonic()+15
                time.sleep(1)
            require(proc.returncode==0,'continuation application failed; preserve and continue from this segment')
        print('STAGE verify',flush=True)
        report=verify_segment(info,segment,cfg,plan,image)
        status.update(status='passed',analysisComplete=False,verification=report,
                      pending='Composite export, diagnostic review and implementation gate remain required.')
        write(segment/'state.json',status)
        public={str(p.relative_to(segment)):sha(p) for d in ['reports','fixtures','config','overlays','recipient']
                for p in (segment/d).rglob('*') if p.is_file()}
        for n in ['plan.json','state.json','compose.json']:public[n]=sha(segment/n)
        write(segment/'segment-seal.json',{'version':VERSION,'profile':PROFILE,
              'classification':'continuation-not-standalone-evaluation','files':public})
        print('CONTINUATION_PASSED '+json.dumps(report),flush=True)
    except BaseException as e:
        status.update(status='interrupted' if isinstance(e,KeyboardInterrupt) else 'failed',error=str(e))
        write(segment/'state.json',status);raise
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        try:stop_campaign_services(cmd);stop_oneshots(segment/'compose.json')
        except (OSError,subprocess.SubprocessError) as e:print('CLEANUP_REQUIRES_ATTENTION '+str(e),flush=True)

def verify_segment(info,segment,cfg,plan,image):
    app=read(segment/'reports/application.json')
    require(app['status']=='passed' and app['config']==cfg,'missing continuation completion')
    require([c['name'] for c in app['cases']]==plan['remainingCases'] and app['kmsCalls']==len(plan['remainingCases']),
            'wrong continuation coverage')
    for i,case in enumerate(app['cases']):
        require(settled(case,cfg),'continuation case did not settle: '+case['name'])
        check_result(read(segment/f'recipient/result-{i}.json'),case,info['expected'])
    # Full V3 consent/release/counter evidence for this segment's own cases.
    onchain=validate_run(segment)
    write(segment/'reports/onchain-release-evidence.json',onchain)
    # Complete grid, in plan order, across every segment of this lineage.
    rows=completed_rows(plan['completed'])+app['cases']
    names=planned_names(info['baseCfg'],info['prepared'])
    require([r['name'] for r in rows]==names,'combined segments do not cover the preselected grid exactly once')
    if info['paired']:validate_full_cases(info['baseCfg'],{'cases':rows,'kmsCalls':len(rows)},info['paired'])
    # Every predecessor release is still reserved on chain under its own slot.
    prior=[(Path(e['run']),e['name']) for e in plan['completed']]
    labels=[slot_label(read(run/'config/campaign.json')['runId'],name) for run,name in prior]
    after=run_chain_read(image,segment/'config',[r for c in info['prepared']['cases'] for r in c['recordIds']],labels)
    for row,label in zip(completed_rows(plan['completed']),labels,strict=True):
        require(after['slots'][label]['requestId'].lower()==row['releaseRequestId'].lower(),
                'predecessor release is not the reserved on-chain request: '+row['name'])
    # Exact counter accounting for this segment: before + its own charges.
    need=charges(info['remaining'])
    for rid,rec in after['records'].items():
        require(rec['spent']==plan['recordSnapshotBefore']['records'][rid]['spent']+need.get(rid,0),
                'unexpected cumulative counter delta: '+rid)
    return {'segmentCases':len(app['cases']),'combinedCases':len(rows),'plannedCases':len(names),
            'rerunUnsettled':plan['rerunUnsettled'],'abandonedReservations':len(plan['abandoned']),
            'onchainSummarySha256':sha(segment/'reports/onchain-release-evidence.json')}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original',type=Path,required=True,help='failed/interrupted run or continuation segment')
    p.add_argument('--execute',action='store_true')
    a=p.parse_args();original=a.original.resolve()
    with (MODULE/'.cache/campaign.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise SystemExit('another threshold campaign is running')
        info=inspect(original)
        print(json.dumps({k:v for k,v in info['plan'].items() if k not in ('completed',)},indent=2),flush=True)
        if a.execute:
            segment=MODULE/'runs'/('continuation-'+time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8])
            execute(info,segment)

if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:raise SystemExit(str(error))
