#!/usr/bin/env python3
"""Read the retained prefix and reconcile it. Starts validators only, never actors."""
from pathlib import Path
import argparse,json,os,sys,subprocess,hashlib
from concurrent.futures import ThreadPoolExecutor

def main(input_root,output,reuse=None):
    input_root=Path(input_root).resolve();output=Path(output).resolve()
    root=input_root/'repository/VC-FHE';sys.path.insert(0,str(root/'distributed'))
    sys.path.insert(0,str(root/'threshold-kms/campaign'))
    os.environ['CLOUDSDK_PYTHON']=sys.executable;os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
    from cloud_tools import ensure
    ensure()
    from cloud_results.common import read,write,sha,require,now
    from remote import Remote
    import topology
    from frontier import inspect_frontier
    from selection import verify_exchange
    from prefix_validation import validator
    cfg=read(input_root/'job/config.local.json');source=read(input_root/'source-manifest.json')
    run=root/'threshold-kms/runs'/(source['runName']+'-workflows-c3')
    c=run/'distributed/workflow-continuation';manifest=read(c/'manifest.json');prep=read(c/'prepared.json')
    require(read(run/'launch-state.json')['status']=='failed-preserved','Predecessor not preserved as failed')
    require(sha(c/'manifest.json')==prep['manifestSha256'],'Frozen manifest changed')
    for name,value in manifest['overlays'].items():require(sha(c/name)==value['overlaySha256'],'Frozen overlay changed')
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    hosts=topology.hosts(cfg);remotes={h['id']:Remote(cfg,h) for h in hosts}
    old=prep['newBase'];base='/srv/vcfhe/'+cfg['campaign'];first=remotes['host-1']
    def phase(name):write(output/'progress.json',{'phase':name,'observedAt':now()});print(name,flush=True)
    phase('reading-frozen-completed-prefix')
    detail=first.json(['sudo','python3','-c',"import json;from pathlib import Path;p=Path("+repr(old+'/coordinator-1')+");print(json.dumps({'application':json.loads((p/'reports/application.json').read_text()),'prepared':json.loads((p/'fixtures/prepared.json').read_text()),'progress':(p/'reports/progress-evaluation.jsonl').read_text(),'exchange':[x.name for x in (p/'exchange').iterdir()]}))"])
    app=detail['application'];events=[json.loads(s) for s in detail['progress'].splitlines() if s]
    frontier=inspect_frontier(manifest['fullCases'],events,app)
    require(len(frontier['completedCases'])==10 and len(frontier['remainingCases'])==17,'Unexpected frontier')
    verify_exchange(detail['exchange'],10)
    require([e['caseName'] for e in events if e.get('phase')=='full-case' and e.get('state')=='start']==frontier['completedCases'],'Unfinished case started')
    write(output/'frontier.json',frontier,new=True);write(output/'original-observation.json',detail,new=True)
    material=output/'prefix'
    if reuse:
        import shutil
        earlier=Path(reuse).resolve();require(read(earlier/'original-observation.json')==detail,'Preserved prefix changed')
        shutil.copytree(earlier/'prefix',material,copy_function=os.link)
    else:
        material.mkdir(mode=0o700)
        first.download(old+'/coordinator-1',['config','reports','fixtures','release-evidence'],material)
    require(read(material/'reports/application.json')==app,'Prefix changed during acquisition')
    if not reuse:remotes['host-1'].download(old+'/owner-1',['owner/expected.json'],material)
    paths=[]
    for case in app['cases']:
        name=case['name']
        if case['half']=='nonlinear':paths.append('owner/'+name+'/approved-context.json')
        else:paths.extend(['owner/'+name+'/coordinates.json']+['owner/'+name+'/input-'+str(i)+'.bin' for i in range(case['n'])])
    if not reuse:remotes['host-1'].download(old+'/owner-1',paths,material)
    recipient=remotes['host-4']
    inspection=recipient.json(['sudo','python3','-c',"import json;from pathlib import Path;p=Path("+repr(old+'/recipient-1')+");print(json.dumps({'exchange':[x.name for x in (p/'exchange').iterdir()],'results':[x.name for x in (p/'recipient').glob('result-*.json')]}))"])
    verify_exchange(inspection['exchange'],10)
    require(set(inspection['results'])=={'result-'+str(i)+'.json' for i in range(10)},'Ambiguous recipient output set')
    if not reuse:recipient.download(old+'/recipient-1',['recipient/result-'+str(i)+'.json' for i in range(10)],material)
    write(output/'recipient-inventory.json',inspection,new=True)
    phase('restoring-only-retained-validators-for-read-only-reconciliation')
    def start_validator(host):
        r=remotes[host['id']];running=r.text(['sudo','docker','ps','--format','{{.Names}}'])
        require(not running,'Another participant is active')
        i=host['id'].split('-')[1]
        r.run(['sudo','docker','compose','-f',base+'/'+host['id']+'/compose.json','start','validator-'+i],stdout=subprocess.DEVNULL)
    list(ThreadPoolExecutor(max_workers=4).map(start_validator,hosts))
    recon=output/'inputs';recon.mkdir(mode=0o700)
    write(recon/'application.json',app,new=True);write(recon/'prepared.json',detail['prepared'],new=True)
    historical=[]
    historical_apps=first.json(['sudo','python3','-c',"import json;from pathlib import Path;b=Path("+repr(base)+");paths=[b/'coordinator-1/reports/application.json',b/'workflows-c1/coordinator-1/reports/application.json',b/'workflows-c2/coordinator-1/reports/application.json'];print(json.dumps({str(p.relative_to(b)):json.loads(p.read_text()) for p in paths if p.is_file()}))"])
    for path,a in historical_apps.items():
        require(a['cases']==[] and a['kmsCalls']==0 and a['status'] in ('failed','running'),'Historical execution contains a release')
        for event in a.get('policyEvents',[]):
            require(event['name'] not in ('ReleaseProposed','ReleaseReserved','ReleaseApproved'),'Historical release needs separate reconciliation')
            if event['name']=='ConsentCreated':historical.append({'consentId':event['args']['consentId'],
                'slot':event['args']['slot'],'transactionHash':event['transactionHash'],
                'source':path,'sourceRunId':a['config']['runId']})
    # The original recipient failed after receiving a request but before the
    # coordinator recorded its ConsentCreated event in application.json.
    # Reconcile this specific preserved request against on-chain state. Never
    # classify an arbitrary extra consent as harmless.
    original_recipient=recipient.json(['sudo','python3','-c',"import json;from pathlib import Path;p=Path("+repr(base+'/recipient-1')+");r=p/'exchange/request-0.json';w=p/'exchange/wire-0.json';print(json.dumps({'request':({'name':json.loads(r.read_text())['name'],'authorization':json.loads(r.read_text())['authorization']} if r.exists() else None),'releaseRequest':json.loads(w.read_text())['releaseRequest'] if w.exists() else None,'results':[x.name for x in (p/'recipient').glob('result-*.json')],'responses':[x.name for x in (p/'exchange').glob('responses-*.json')],'config':json.loads((p/'config/campaign.json').read_text())}))"])
    request0=original_recipient['request']
    if request0:
        require(request0['name']==frontier['completedCases'][0] and not original_recipient['results']
            and not original_recipient['responses'],'Original recipient requires separate release reconciliation')
        auth=request0['authorization'];wire=original_recipient['releaseRequest']
        require(wire is not None and wire['consentId']==auth['consentId'],'Historical wire mismatch')
        if auth['consentId'] not in {v['consentId'] for v in historical}:
            historical.append({'consentId':auth['consentId'],'slot':auth['slot'],
                'source':'original-recipient/exchange/request-0.json',
                'sourceRunId':original_recipient['config']['runId'],'caseName':request0['name'],
                'authorization':auth,'releaseRequest':wire})
    write(output/'historical-original-recipient.json',original_recipient,new=True)
    write(output/'historical-unreleased-applications.json',historical_apps,new=True)
    write(recon/'request.json',{'completed':frontier['completedCases'],'remaining':frontier['remainingCases'],
        'historicalConsents':historical,'nextRunId':source['runName']+'-workflows-c4'},new=True)
    import shutil,time
    shutil.copy2(Path(__file__).with_name('reconcile.mjs'),recon/'reconcile.mjs')
    remote_dir=base+'/'+output.name+'-read';first.upload(recon,remote_dir)
    aliases=[]
    for node in topology.inventory(cfg):
        if node['role']=='validator':aliases+=['--add-host','node'+str(node['index'])+':'+node['private_ip']]
    args=['sudo','docker','run','--rm','--network','host','--user','10001:10001','--read-only',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,nosuid,nodev,size=512m',*aliases,
        '--mount','type=bind,src='+old+'/coordinator-1/config,dst=/config,readonly',
        '--mount','type=bind,src='+remote_dir+',dst=/reconciliation,readonly',
        '--entrypoint','node',cfg['images']['campaign'],'/reconciliation/reconcile.mjs']
    # Validator restoration may need a few seconds. Only a side-effect-free read retries.
    observed=None
    for attempt in range(6):
        try:
            result=first.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=900)
            observed=json.loads(result.stdout);break
        except subprocess.CalledProcessError as error:
            write(output/('chain-read-error-'+str(attempt)+'.json'),{'stderr':error.stderr,'observedAt':now()},new=True)
            print(error.stderr,flush=True)
            if 'ECONNREFUSED' not in (error.stderr or '') and 'could not detect network' not in (error.stderr or ''):raise
            time.sleep(10)
    require(observed is not None,'Validator read unavailable')
    write(output/'reconciliation.json',observed,new=True)
    phase('validating-each-completed-release-and-dispute')
    native=(root/'threshold-kms/campaign/onchain_evidence.py').read_text()
    module,provenance=validator(native,app,events,manifest['fullCases'],observed,
        source_path=root/'threshold-kms/campaign/onchain_evidence.py')
    verdict=module.validate_run(material)
    require(verdict['status']=='completed-prefix-validated' and verdict['caseCount']==10,'Incomplete prefix validation')
    from experiment_plan import evidence_module
    pairs=read(material/'reports/paired.json');evidence_module(app['config']).validate_pairs(app['config'],pairs)
    require(sha(material/'reports/paired.json')==manifest['pairedSha256'],'Completed pairs changed')
    write(output/'prefix-validation.json',{'status':'validated-completed-prefix-only','verdict':verdict,
        'provenance':provenance,'applicationSha256':sha(material/'reports/application.json'),
        'reconciliationSha256':sha(output/'reconciliation.json'),'comparisonsPreserved':480,'warmupsPreserved':18,
        'fullCampaignValidated':False,'protocolOperationsRepeated':False,'observedAt':now()},new=True)
    phase('prefix-validated-ready-for-versioned-preparation')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',required=True);p.add_argument('--output',required=True);p.add_argument('--reuse')
    a=p.parse_args();os.umask(0o077);main(a.input,a.output,a.reuse)
