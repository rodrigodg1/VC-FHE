"""Preserve and validate each segment before any complete-campaign publication."""
from pathlib import Path
import json,shutil,subprocess,sys

def collect(worker):
    from cloud_results.common import read,write,sha,require,now
    from cloud_results.owner_materials import collect as collect_owner_witnesses
    run=worker.run;c=run/'distributed/workflow-continuation';manifest=read(c/'manifest.json')
    collect_owner_witnesses(worker)
    remote=worker.remote('coordinator-1')
    remote.download(worker.root('coordinator-1'),['reports','fixtures','release-evidence','keyset','config'],run)
    worker.remote('owner-1').download(worker.root('owner-1'),['owner/expected.json'],run)
    app=read(run/'reports/application.json');cfg=read(run/'config/campaign.json')
    require(app['status']=='passed' and [r['name'] for r in app['cases']]==manifest['fullCases'],
        'Pending segment incomplete or case selection changed')
    events=[json.loads(x) for x in (run/'reports/progress-evaluation.jsonl').read_text().splitlines() if x]
    done=[e['caseName'] for e in events if e.get('phase')=='full-case' and e.get('state')=='done' and e.get('group')=='full']
    require(done==manifest['fullCases'],'Released cases are not all completed workflows')
    for i in range(17):worker.remote('recipient-1').download(worker.root('recipient-1'),['recipient/result-'+str(i)+'.json'],run)
    for node,row in worker.nodes.items():
        if row['role']=='validator' or node=='coordinator-1':continue
        worker.remote(node).download(worker.root(node),['reports'],run/'collected'/node)
    for host,r in worker.remotes.items():
        base=worker.base+'/'+host
        names=['host-observations.jsonl','host-observations-workflows-c3.jsonl','host-observations-workflows-c4.jsonl']
        r.download(base,names,run/'distributed/samples'/host)
    root=Path(__file__).resolve().parents[3]
    # On the cloud this module is an external maintenance closure. Resolve the
    # measured native modules through the worker's frozen source repository.
    native=Path(worker.controller_job['work'])/'repository/VC-FHE/threshold-kms/campaign'
    sys.path.insert(0,str(native))
    import onchain_evidence
    from experiment_plan import evidence_module
    from scheduling_evidence import validate as scheduling
    from prefix_validation import validator
    from composite import combine
    prior=Path(manifest['completedPrefixPath']);prefix_run=prior/'prefix'
    original=read(prefix_run/'reports/application.json');observed=read(prior/'original-observation.json')
    old_events=[json.loads(x) for x in observed['progress'].splitlines() if x]
    plan=manifest['completedCases']+manifest['fullCases']
    module,provenance=validator((native/'onchain_evidence.py').read_text(),original,old_events,plan,
        read(prior/'reconciliation.json'),source_path=native/'onchain_evidence.py')
    a=module.validate_run(prefix_run);b=onchain_evidence.validate_run(run)
    scheduling(original['config'],original);scheduling(cfg,app)
    combined=combine(original,app,plan,prefix_verdict=a,continuation_verdict=b)
    pairs=read(run/'reports/paired.json');require(sha(run/'reports/paired.json')==manifest['pairedSha256'],'Reused pairs changed')
    evidence_module(cfg).validate_full_cases(cfg,combined,pairs)
    write(c/'composed-case-validation.json',{'observedAt':now(),'scope':'27-case-grid-with-separate-release-validation',
        'prefix':a,'continuation':b,'composite':combined,'originalFailurePreserved':True,
        'analysisComplete':False},new=True)
    # These are original raw bytes. The seal is explicitly a segment inventory,
    # never an original passed-campaign seal or publication approval.
    files={str(p.relative_to(run)):sha(p) for folder in ('config','reports','fixtures','release-evidence','recipient','owner','collected')
        for p in (run/folder).rglob('*') if p.is_file()}
    write(c/'segment-raw-inventory.json',{'schema':'completed-prefix-segment-inventory-v1',
        'files':files,'prefixApplicationSha256':sha(prefix_run/'reports/application.json'),
        'prefixEvidence':str(prior),'fullCampaignPublicationReady':False},new=True)

def verify_preservation_guard(run):
    """Permit backup of validated segment bytes, without certifying publication."""
    from cloud_results.common import read,sha,require
    run=Path(run);c=run/'distributed/workflow-continuation'
    m=read(c/'manifest.json');proof=read(c/'composed-case-validation.json');inventory=read(c/'segment-raw-inventory.json')
    require(m['profile']=='distributed-completed-prefix-continuation-v1','Wrong segment')
    require(proof['scope']=='27-case-grid-with-separate-release-validation'
        and proof['prefix']['status']=='completed-prefix-validated' and proof['prefix']['caseCount']==10
        and proof['continuation']['status']=='passed' and proof['continuation']['caseCount']==17
        and proof['composite']['status']=='case-grid-and-release-continuity-validated'
        and proof['composite']['kmsCalls']==27 and proof['analysisComplete'] is False,
        'Missing segment validation before preservation')
    for name,digest in inventory['files'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'Unsafe inventory path')
        require(sha(run/name)==digest,'Raw segment bytes changed before backup')
    prior=Path(m['completedPrefixPath'])/'prefix/reports/application.json'
    require(sha(prior)==inventory['prefixApplicationSha256'],'Preserved prefix changed')
    require([r['name'] for r in proof['composite']['cases']]==m['completedCases']+m['fullCases'],'Grid changed')
    return proof
