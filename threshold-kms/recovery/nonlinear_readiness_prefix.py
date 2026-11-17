"""Audit an already released honest result before dispute-only continuation.

The failed predecessor remains unsealed. This audit is not a full-case result.
"""
import argparse
import hashlib
import json
from pathlib import Path
from readiness_prefix import require, read, sha, RESULT_CHECKS, ZERO

MODULE=Path(__file__).resolve().parents[1]
ROOT=MODULE.parent
ALLOWED_CHANGES={'fhe-pod/scripts/canonical-bounty-client.mjs',
                 'fhe-pod/scripts/canonical-game-driver.mjs',
                 'threshold-kms/campaign/run.py','threshold-kms/campaign/evaluate.mjs',
                 'threshold-kms/campaign/export.py','threshold-kms/campaign/bounty_evidence.py'}


def validate_material(state,app,prepared,result,expected,keys,snapshot):
    cfg=state['config'];name='regulatory_qoe_compliance-0'
    require(state['status']=='failed' and app['status']=='failed' and app['config']==cfg,
            'the failed predecessor must remain failed')
    require(cfg.get('half')=='nonlinear' and cfg.get('readinessOnly') and cfg.get('smoke')
            and cfg.get('parameters')=='Test' and cfg.get('records')==50 and cfg.get('repeats')==1
            and cfg.get('nonlinearProtocol')=='bounty-v2', 'unsupported nonlinear readiness scope')
    require([c['name'] for c in prepared['cases']]==[name,'regional_qoe_compliance-0'],
            'unexpected predecessor case grid')
    require(keys==prepared['keys']==app['keys'] and keys['status']=='passed'
            and keys['parameters']=='Test' and keys['fullPreprocessing']
            and not keys['preloadedFheKey'], 'invalid predecessor keyset')
    require(len(app['cases'])==app['kmsCalls']==1,'unexpected number of completed releases')
    case=app['cases'][0]
    require(case['name']==name and case['half']=='nonlinear' and case['n']==50
            and case['finalOutputKmsCalls']==1 and not case['metrics']['disputes'],
            'only an honest released result awaiting its dispute is supported')
    require(case['workflowKind']==2 and case['workflowManifest']['kind']=='canonical-bounty-nonlinear-v2'
            and len(case['recordIds'])==len(set(case['recordIds']))==50,
            'wrong released workload or protected records')
    require(result['name']==name and result['index']==0 and result['actual']==expected[name]
            and result['outputDigest']==case['outputDigest']
            and all(result.get(k)==v for k,v in RESULT_CHECKS.items()),'released output did not validate')
    require(snapshot['policy'].lower()==app['onChainPolicy']['address'].lower(),'policy changed')
    label=lambda n:f"{cfg['runId']}:{n}:final:onchain-v3"
    slot=snapshot['slots'][label(name)]
    require(slot['slot']==case['releaseSlot'] and slot['requestId']==case['releaseRequestId'],
            'released slot changed')
    require(snapshot['slots'][label('regional_qoe_compliance-0')]['requestId']==ZERO,
            'the regional release has already been consumed')
    for rid in case['recordIds']:
        before=app['protectedRecordBaselines'][rid];after=snapshot['records'][rid]
        require(all(before[k]==after[k] for k in ('owner','recordReference','releaseLimit'))
                and after['spent']==before['spent']+1<=after['releaseLimit'],
                'released record terms or counters changed')
    failed=snapshot['failedTransaction']
    require(failed['to'].lower()==case['workflowManifest']['availability'].lower()
            and failed['method']=='publishAuthenticatedTraceBatch' and failed['rows']==64
            and failed['status']==0 and failed['gasLimit']==failed['gasUsed']=='20000000',
            'the specific relay gas-limit failure was not established')
    return {'profile':'released-nonlinear-readiness-prefix-audit-v1','status':'passed',
            'scope':'honest-result-only-dispute-still-required','analysisComplete':False,
            'predecessorStatus':'failed','releasedCase':name,'completedReleaseCount':1,
            'pending':['regulatory-dispute-only','regional-full-readiness'],
            'pinnedBlock':snapshot['blockNumber'],'pinnedBlockHash':snapshot['blockHash']}


def audit(run,snapshot):
    run=Path(run).resolve();require(run.parent==MODULE/'runs' and not (run/'seal.json').exists(),
                                    'unexpected or sealed predecessor')
    state=read(run/'state.json');cache=MODULE/'.cache'/hashlib.sha256(json.dumps(state['source'],sort_keys=True).encode()).hexdigest()
    saved=read(cache/'complete.json');require(saved['source']==state['source'],'predecessor cache changed')
    changes=[]
    for name,digest in state['source'].items():
        require(sha(cache/'app'/name)==digest,'frozen predecessor source changed')
        if sha(ROOT/name)!=digest:changes.append(name)
    require(set(changes)<=ALLOWED_CHANGES and 'fhe-pod/scripts/canonical-game-driver.mjs' in changes,
            'source changes exceed the isolated relay/readiness repair')
    require([p.name for p in (run/'recipient').glob('result-*.json')]==['result-0.json'],
            'additional recipient results exist')
    summary=validate_material(state,read(run/'reports/application.json'),read(run/'fixtures/prepared.json'),
        read(run/'recipient/result-0.json'),read(run/'owner/expected.json'),read(run/'keyset/ready.json'),read(snapshot))
    summary.update(predecessor=str(run),sourceDelta=changes,snapshotSha256=sha(snapshot),
                   evidenceSha256={name:sha(run/name) for name in ['state.json','reports/application.json',
                       'fixtures/prepared.json','recipient/result-0.json','owner/expected.json','keyset/ready.json']})
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True)
    p.add_argument('--snapshot',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();summary=audit(a.run,a.snapshot)
    with a.output.open('x') as stream:stream.write(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ('profile','status','scope','predecessorStatus')}))
