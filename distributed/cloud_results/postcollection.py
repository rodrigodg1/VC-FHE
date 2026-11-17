"""Explicit functional validation after a public-witness collection omission.

This does not repair or replace an original failed status or create its normal
seal. It is restricted to the single regional diagnostic. Evaluation campaigns must
still pass their original collection, seal and publication validators.
"""
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from cloud_results.common import read, write, require, sha, now
from cloud_results.owner_materials import public_paths
import deployment
import topology

SCHEMA = 'regional-functional-postcollection-attestation-v1'


def eligible(original, view, addendum):
    original, view, addendum = map(Path, (original, view, addendum))
    require(original.resolve() != view.resolve(), 'A separate verification view is required')
    state, launch = read(original/'state.json'), read(original/'launch-state.json')
    cfg = read(original/'config/campaign.json')
    from diagnostic_profile import validate_campaign, validate_cases
    require(validate_campaign(cfg), 'Only the explicit regional functional diagnostic is eligible')
    require(state.get('status') == 'validating' and state.get('config') == cfg
            and launch.get('status') == 'failed', 'Original diagnostic status is ineligible')
    require(not (original/'seal.json').exists() and not (view/'seal.json').exists()
            and not (original/'distributed/smoke-result.json').exists(), 'An ordinary seal cannot be replaced')
    stages = launch.get('stages', [])
    require([s['name'] for s in stages if s['status'] == 'failed'] == ['Collect and validate evidence']
            and all(s['status'] in ('passed','failed') for s in stages), 'Failure extends beyond evidence collection')
    require(sum(s['name']=='Full evaluation' and s['status']=='passed' for s in stages)==1,
            'The original protocol workflow did not complete')
    require('experiment_plan.py' in launch.get('error',''), 'Different collection failure')
    require(read(view/'state.json') == state and read(view/'config/campaign.json') == cfg,
            'Original state or configuration changed in the verification view')
    module = deployment.campaign_module()
    record = read(original/'distributed/source.json')
    require(state['source'] == record['localSource'] == module.source_manifest(), 'Native source closure changed')
    app = read(original/'reports/application.json')
    summary = validate_cases(app['cases'],cfg)
    require(app['status']=='passed', 'Application execution did not pass')
    paths=public_paths(app)
    require(paths==['owner/regional_qoe_compliance-0/approved-context.json'], 'Unexpected repair scope')
    missing=paths[0]
    require(not (original/missing).exists(), 'Original witness was present. This repair is inapplicable')
    proof=read(addendum/'acquisition.local.json')
    require(proof.get('schema')=='missing-owner-public-context-acquisition-v1'
            and proof.get('status')=='copied-existing-evidence'
            and proof.get('role')=='owner-1' and proof.get('host')=='host-1'
            and proof.get('file')==missing and proof.get('sha256')==sha(addendum/missing)
            and proof.get('protocolRequestsRepeated')==0 and proof.get('nativeRunUntouched') is True,
            'Acquisition does not attest a read-only recovery')
    require(sha(addendum/missing)==sha(view/missing), 'Recovered witness changed')
    # Every original native input, output and measured executable stays identical.
    inputs={}
    roots=(*module.SEALED_ARTIFACT_FOLDERS,'recipient','compose','validator-config','network')
    for folder in roots:
        for p in (original/folder).rglob('*'):
            if p.is_file():
                name=p.relative_to(original).as_posix()
                require(not p.is_symlink() and (view/name).is_file() and not (view/name).is_symlink()
                        and sha(p)==sha(view/name), 'Original measured evidence changed: '+name)
                inputs[name]=sha(p)
    for name in ('state.json','distributed/source.json','distributed/public-identities.json','distributed/task-inventory.json'):
        require(sha(original/name)==sha(view/name), 'Original control evidence changed')
        inputs[name]=sha(original/name)
    inputs['launch-state.json']=sha(original/'launch-state.json')
    return cfg, summary, inputs


def verify_attestation(view):
    view=Path(view)
    proof=read(view/'postcollection-attestation.local.json')
    require(proof.get('schema')==SCHEMA and proof.get('status')=='passed'
            and proof.get('evaluationPublishable') is False and proof.get('originalSealVerified') is False
            and proof.get('originalRunnerStatus')=='failed' and proof.get('originalStateStatus')=='validating'
            and proof.get('protocolRequestsRepeated')==0, 'Invalid functional-only attestation scope')
    require(not (view/'seal.json').exists() and read(view/'state.json')['status']=='validating',
            'Ordinary state or seal was replaced')
    for name,digest in proof['validatedFiles'].items():
        from cloud_results.common import safe_file
        require(sha(safe_file(view,name))==digest, 'Changed postcollection evidence: '+name)
    return proof


def attest(original, view, addendum):
    """Rerun only unchanged offline validators on already produced evidence."""
    original, view, addendum=map(Path,(original,view,addendum))
    cfg,summary,inputs=eligible(original,view,addendum)
    require(not any((view/name).exists() for name in (
        'postcollection-attestation.local.json','distributed/deployment.json',
        'distributed/execution.json','distributed/supplement')),
        'Use a fresh verification view. Derived reports cannot be substituted')
    module=deployment.campaign_module()
    # Export performs full on-chain authorization/output and dispute checks.
    import experiment_plan
    experiment_plan.validate_export(view)
    outer=read(original/'distributed-config.json');plan=topology.plan(outer)
    campaign=SimpleNamespace(run=view,plan=plan,
        compose=deployment.manifests(outer,original.name),identities=read(view/'distributed/public-identities.json'))
    import collect
    collect.distributed_deployment_files(campaign)
    hosts=[read(p) for p in sorted((view/'distributed/hosts').glob('host-*.json'))]
    require(len(hosts)==4, 'Missing measured host reports')
    write(view/'distributed/execution.json',{
        'executionProfile':'gcp-four-hosts-role-local-v1','status':'completed','hosts':hosts,
        'roles':plan['nodes'],'administration':'same-gcp-project',
        'pairTiming':'coordinator-request-response-including-public-transfer',
        'imageDigest':outer['images']['campaign'],'binarySha256':sha(view/'bin/kms-campaign'),
        'sourceSha256':topology.digest(read(original/'distributed/source.json')),
        'measuredPairs':0,'warmups':0,'fullCases':1,
        'verificationKind':'postcollection-functional-diagnostic','originalRunnerStatus':'failed'},new=True)
    from supplement import generate
    generate(view,plan)
    names={p.relative_to(view).as_posix() for p in view.rglob('*') if p.is_file()}
    module.validate_comparative_report(view,names)
    module.validate_availability(view,names)
    module.validate_scheduling(view,names)
    for name,item in read(view/'state.json')['datasets'].items():
        require(sha(deployment.ROOT/name)==item['sha256'], 'Source dataset changed')
    require(cfg['bountyEconomics']==read(deployment.ROOT/'fhe-pod/scripts/bounty-economics.json'),
            'Economic profile changed')
    import smoke_cleanup
    cleanup=read(original/'smoke-cleanup.local.json');stop=read(original/'compute-stop.local.json')
    require(cleanup.get('status')=='passed' and cleanup.get('privateStatePreserved') is True
            and len(stop['hosts'])==4 and all(h['stopped'] for h in stop['hosts']), 'Safe cleanup is incomplete')
    smoke_cleanup.verify_backup(original/'private-smoke-backup')
    # Inventory the measured closure plus all derived metrics, without a normal seal.
    files={}
    for folder in (*module.SEALED_ARTIFACT_FOLDERS,'recipient','compose','validator-config','network','distributed','collected'):
        for p in (view/folder).rglob('*'):
            if p.is_file():
                require(not p.is_symlink(), 'Linked postcollection evidence')
                files[p.relative_to(view).as_posix()]=sha(p)
    files['state.json']=sha(view/'state.json')
    proof={'schema':SCHEMA,'status':'passed','createdAt':now(),'evaluationPublishable':False,
        'originalRunnerStatus':'failed','originalStateStatus':'validating','originalSealVerified':False,
        'originalRun':original.name,'originalInputFiles':inputs,'validatedFiles':files,
        'sourceSha256':topology.digest(read(original/'distributed/source.json')),
        'imageDigest':outer['images']['campaign'],**summary,'protocolRequestsRepeated':0,
        'privateCloudBackupVerified':True,'ownedInfrastructureRemoved':True,
        'acquisitionSha256':sha(addendum/'acquisition.local.json'),
        'cleanupSha256':sha(original/'smoke-cleanup.local.json'),
        'computeStopSha256':sha(original/'compute-stop.local.json'),
        'postcollectionValidatorSha256':sha(Path(__file__)),
        'validation':['original-exporter','onchain-release-bindings','original-comparative-evidence',
            'original-availability-controls','original-scheduling','actual-distributed-deployment','distributed-supplement'],
        'scope':'Functional regional smoke only. Existing measured data revalidated after copying one missing public owner context. The failed original remains unchanged. No completed analysis.'}
    write(view/'postcollection-attestation.local.json',proof,new=True)
    return verify_attestation(view)
