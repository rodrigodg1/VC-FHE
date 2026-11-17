"""Full-campaign preparation requires a successful source-matched cloud smoke."""
from pathlib import Path
import re
from cloud_results.common import read,write,require,sha
import topology


def validate_proof(proof, record, publication, attestation=None):
    normal = proof.get('schema') == 'source-matched-successful-smoke-v1'
    repaired = proof.get('schema') == 'source-matched-postcollection-functional-smoke-v1'
    require((normal or repaired) and proof.get('status') == 'passed',
            'A successful cloud smoke is required before full preparation')
    require(proof.get('sourceSha256') == topology.digest(record) and proof.get('imageDigest') == publication['digest'],
            'Successful smoke used different image inputs')
    require(proof.get('evaluationPublishable') is False and proof.get('fullCases') in (1,3)
            and proof.get('privateCloudBackupVerified') is True and proof.get('ownedInfrastructureRemoved') is True,
            'Smoke validation, private preservation or cleanup is incomplete')
    if normal:
        require(re.fullmatch('[a-f0-9]{64}',proof.get('sealSha256','')),
                'Smoke validation, private preservation or cleanup is incomplete')
    else:
        from cloud_results.postcollection import SCHEMA
        require(isinstance(attestation,dict) and attestation.get('schema') == SCHEMA
                and attestation.get('status') == 'passed' and attestation.get('evaluationPublishable') is False
                and attestation.get('originalSealVerified') is False
                and attestation.get('originalRunnerStatus') == 'failed'
                and attestation.get('originalStateStatus') == 'validating'
                and attestation.get('protocolRequestsRepeated') == 0
                and attestation.get('sourceSha256') == proof['sourceSha256']
                and attestation.get('imageDigest') == proof['imageDigest']
                and attestation.get('privateCloudBackupVerified') is True
                and attestation.get('ownedInfrastructureRemoved') is True
                and proof.get('fullCases') == attestation.get('fullCases') == 1
                and proof.get('originalSealVerified') is False and proof.get('sealSha256') is None
                and proof.get('attestationSha256') == topology.digest(attestation),
                'Explicit postcollection functional validation is incomplete')
    return proof


def validate(context, record):
    context=Path(context)
    proof=read(context/'successful-smoke.local.json')
    attestation=(read(context/'postcollection-smoke-attestation.local.json')
                 if proof.get('schema')=='source-matched-postcollection-functional-smoke-v1' else None)
    return validate_proof(proof,record,read(context/'published-image.json'),attestation)


def certify(context,run):
    import deployment,smoke_cleanup
    context,run=Path(context),Path(run)
    record=read(context/'distributed-source.json');publication=read(context/'published-image.json')
    require(read(run/'distributed/source.json')==record,'Smoke source differs from prepared image')
    deployment.campaign_module().verify(run)
    result=read(run/'distributed/smoke-result.json');cleanup=read(run/'smoke-cleanup.local.json')
    stop=read(run/'compute-stop.local.json');state=read(run/'launch-state.json')
    require(result.get('status')=='passed' and result.get('evaluationPublishable') is False and state.get('status')=='completed',
            'An interrupted, incomplete or failed smoke cannot authorize a campaign')
    require(cleanup.get('status')=='passed' and cleanup.get('privateStatePreserved') is True
            and len(stop['hosts'])==4 and all(v['stopped'] for v in stop['hosts']),
            'Smoke infrastructure was not safely removed')
    smoke_cleanup.verify_backup(run/'private-smoke-backup')
    proof={'schema':'source-matched-successful-smoke-v1','status':'passed','sourceSha256':topology.digest(record),
        'imageDigest':publication['digest'],'sealSha256':sha(run/'seal.json'),
        'smokeResultSha256':sha(run/'distributed/smoke-result.json'),'fullCases':result['fullCases'],
        'evaluationPublishable':False,'privateCloudBackupVerified':True,'ownedInfrastructureRemoved':True,
        'scope':'Functional smoke evidence only. Full measurements and their original validation remain required.'}
    target=context/'successful-smoke.local.json'
    if target.exists():require(read(target)==proof,'Different successful-smoke proof already retained')
    else:write(target,proof,new=True)
    validate(context,record)
    return proof


def certify_postcollection(context, original, view):
    """Preserve an explicit functional-only exception, never a passing native seal."""
    from cloud_results.postcollection import verify_attestation
    import smoke_cleanup
    context,original,view=map(Path,(context,original,view))
    record=read(context/'distributed-source.json');publication=read(context/'published-image.json')
    require(record==read(original/'distributed/source.json'), 'Postcollection smoke source differs')
    attestation=verify_attestation(view)
    require(attestation['originalRun']==original.name and read(original/'launch-state.json')['status']=='failed'
            and not (original/'seal.json').exists(), 'Original failed status was replaced')
    for name,digest in attestation['originalInputFiles'].items():
        require(sha(original/name)==digest,'Original evidence changed after postcollection validation')
    cleanup=read(original/'smoke-cleanup.local.json');stop=read(original/'compute-stop.local.json')
    require(cleanup['status']=='passed' and cleanup['privateStatePreserved'] is True
            and len(stop['hosts'])==4 and all(h['stopped'] for h in stop['hosts']), 'Smoke cleanup incomplete')
    smoke_cleanup.verify_backup(original/'private-smoke-backup')
    proof={'schema':'source-matched-postcollection-functional-smoke-v1','status':'passed',
        'sourceSha256':topology.digest(record),'imageDigest':publication['digest'],
        'sealSha256':None,'originalSealVerified':False,'attestationSha256':topology.digest(attestation),
        'fullCases':1,'evaluationPublishable':False,'privateCloudBackupVerified':True,'ownedInfrastructureRemoved':True,
        'scope':'Functional regional smoke revalidated after one public-witness collection omission. Original failure retained. Full campaign still requires its original normal seal and publication validation.'}
    write(context/'postcollection-smoke-attestation.local.json',attestation,new=True)
    write(context/'successful-smoke.local.json',proof,new=True)
    return validate(context,record)
