"""Additional fail-closed evidence checks. Existing protocol validators still run.

Host reports and process records establish experimental placement, not remote
attestation or independence from the common cloud administrator.
"""
import hashlib
import json
from pathlib import Path
from verify_composite import require,sha
from distributed_profile import PROFILE,descriptor

def validate_byte_probe(probe,records):
    require(probe.get('status')=='passed' and probe.get('plaintextOpenings')==0,
            'cross-host byte test did not pass without decryption')
    require(probe.get('includedInMeasurements') is False,'byte admission test counted as a measurement')
    audits=probe.get('audits',[])
    require(len(audits)==3 and {a.get('node') for a in audits}=={'auditor-1','auditor-2','auditor-3'},
            'byte test does not cover all auditor hosts')
    operator=records.get(('operator-1',probe.get('operatorEventId')),{})
    require(operator.get('task')=='canonical-execute','byte test has no operator execution evidence')
    roots=set()
    for audit in audits:
        record=records.get((audit['node'],audit.get('eventId')),{})
        require(record.get('task')=='canonical-audit','byte test has no independent auditor task')
        evidence=audit.get('evidence',{})
        require('index' in evidence and evidence['index'] is None and evidence.get('plaintextOpenings')==0,
                'byte test reports a divergence or decryption')
        require(evidence.get('operatorRoot') and evidence['operatorRoot']==evidence.get('replayRoot'),
                'byte test ciphertext trace roots differ')
        roots.add(evidence['operatorRoot'])
    require(len(roots)==1,'auditors did not compare the same operator trace')

def validate(run,sealed):
    run=Path(run)
    cfg,state=sealed('config/campaign.json'),sealed('state.json')
    require(cfg.get('executionProfile')==PROFILE,'wrong distributed campaign profile')
    require(not cfg.get('smoke') and not cfg.get('readinessOnly'),'pilot cannot become evaluation evidence')
    require(cfg['half']=='both','distributed analysis requires both complete workflows')
    summary=sealed('distributed/execution.json')
    d=descriptor(summary)
    require(summary.get('status')=='completed','distributed run is incomplete')
    require(summary.get('measuredPairs')==480 and summary.get('warmups')==18 and summary.get('fullCases')==45,
            'incomplete distributed evaluation grid')
    require(summary.get('imageDigest') and '@sha256:' in summary['imageDigest'],'immutable campaign image required')
    require(summary.get('sourceSha256')==state.get('distributedSourceSha256'),'distributed source closure changed')
    hashes=sealed('distributed/source.json')
    require(hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(',',':')).encode()).hexdigest()==summary['sourceSha256'],
            'distributed source inventory mismatch')
    environments=[]
    for host in d['hosts']:
        report=sealed('distributed/hosts/'+host['id']+'.json')
        require(report['host']==host['id'] and report['region']==host['region'],'host evidence misassigned')
        require(report['imageDigest']==summary['imageDigest'],'different campaign images across hosts')
        require(report.get('binarySha256')==summary.get('binarySha256'),'FHE binary mismatch')
        require(report.get('cpuModel') and report.get('kernelRelease'),'missing actual execution environment')
        environments.append((report['cpuModel'],report['kernelRelease'],report.get('architecture')))
    require(len(set(environments))==1,'canonical evaluation context differs across hosts')
    # Independent task IDs and role placement prevent a controller-only run or
    # one recorded execution from being counted twice in the baseline.
    inventory=sealed('distributed/task-inventory.json')
    roles={r['id']:r for r in d['roles']}
    seen=set();counts={};records={}
    for item in inventory:
        require(item['path'].startswith('distributed/tasks/') and '..' not in Path(item['path']).parts,'invalid task evidence path')
        record=sealed(item['path'])
        require(sha(run/item['path'])==item['sha256'],'task evidence changed')
        node=roles.get(record.get('node'))
        require(node and record['host']==node['host'] and record['role']==node['role'],'computation on wrong host')
        identity=(record['node'],record['id'])
        require(identity not in seen,'duplicate participant task counted');seen.add(identity)
        records[identity]=record
        require(record['status']=='completed','failed or incomplete participant task')
        if record['task'] in ['canonical-execute','canonical-audit','canonical-attest','linear-aggregate','linear-proposed','linear-baseline']:
            m=record.get('measurement')
            require(m and m['exitCode']==0 and m.get('resources') is not None,'missing actual participant process measurement')
        counts[node['role']]=counts.get(node['role'],0)+1
    require(all(counts.get(role,0)>0 for role in ['operator','auditor','adjudicator','owner','recipient','kms']),
            'some protocol roles have no task evidence')
    readiness=sealed('distributed/readiness.json')
    for gate in ['sameCiphertextBytes','largestCaseCompleted','deadlineMarginsNonnegative','fourKmsDkg',
                 'fixedBlockQuorum','exactRecipientRelease','authorizationReuseRejected','budgetAdmitted']:
        require(readiness.get(gate) is True,'distributed admission gate missing: '+gate)
    # The gate must identify retained raw observations, not just boolean claims.
    refs=readiness.get('evidenceFiles',{})
    require(set(refs)=={'byteRepeatability','largestCase','kmsSetup','authorization','budget'},'readiness evidence inventory incomplete')
    for item in refs.values():
        require(isinstance(item,dict) and item.get('path') and item.get('sha256'),'missing readiness evidence reference')
        sealed(item['path']);require(sha(run/item['path'])==item['sha256'],'readiness evidence changed')
    validate_byte_probe(sealed(refs['byteRepeatability']['path']),records)
    require(sealed(refs['kmsSetup']['path']).get('parties')==4,'four-core key setup evidence missing')
    require(sealed(refs['budget']['path']).get('status')=='admit','budget was not admitted')
    return d
