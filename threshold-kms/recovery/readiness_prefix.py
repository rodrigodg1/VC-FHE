"""Audit the completed linear part of a failed combined readiness pilot.

This read-only audit neither resumes the predecessor nor seals it as passed.
The remaining nonlinear readiness checks must run in a new, sealed segment.
"""
import argparse
import hashlib
import json
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1]
ROOT = MODULE.parent
RESULT_CHECKS = {'responses': 3, 'directUserAndPublicDenied': 4,
                 'directAdministrativeDenied': 28, 'changedReservedWireDenied': 4,
                 'negativeResponseChecks': 4}
ZERO = '0x' + '0' * 64


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_material(state, app, prepared, result, expected, keys, snapshot):
    cfg = state['config']
    require(state['status'] == 'failed', 'the predecessor must remain failed')
    require(cfg.get('readinessOnly') and cfg.get('smoke') and cfg.get('half') == 'both'
            and cfg.get('parameters') == 'Test' and cfg.get('nonlinearProtocol') == 'bounty-v2'
            and cfg.get('linearSizes') == [27] and cfg.get('records') == 50
            and cfg.get('repeats') == 1, 'unsupported readiness configuration')
    require(app['config'] == cfg and app['status'] == 'failed', 'wrong predecessor report')
    names = ['linear-acr-27-0', 'regulatory_qoe_compliance-0', 'regional_qoe_compliance-0']
    require([row['name'] for row in prepared['cases']] == names, 'unexpected readiness grid')
    require(keys == prepared['keys'] == app['keys'] and keys['status'] == 'passed'
            and keys['parameters'] == 'Test' and keys['fullPreprocessing']
            and not keys['preloadedFheKey'], 'predecessor keyset did not pass')
    require(len(app['cases']) == app['kmsCalls'] == 1, 'only one completed release is supported')
    case = app['cases'][0]
    require(case['name'] == names[0] and case['half'] == 'linear' and case['n'] == 27
            and case['workflowKind'] == 1 and case['finalOutputKmsCalls'] == 1,
            'completed prefix is not the largest linear case')
    require(result['index'] == 0 and result['name'] == case['name']
            and result['actual'] == expected[case['name']]
            and result['outputDigest'] == case['outputDigest'], 'wrong delivered linear result')
    require(all(result.get(key) == value for key, value in RESULT_CHECKS.items()),
            'incomplete threshold release checks')
    require(snapshot['policy'].lower() == app['onChainPolicy']['address'].lower(),
            'policy deployment changed')
    require(snapshot['blockNumber'] >= case['validatorConfirmations'][0]['blockNumber'],
            'invalid pinned snapshot block')
    label = lambda name: f"{cfg['runId']}:{name}:final:onchain-v3"
    linear_slot = snapshot['slots'][label(names[0])]
    require(linear_slot['slot'] == case['releaseSlot']
            and linear_slot['requestId'] == case['releaseRequestId'], 'completed slot changed')
    for name in names[1:]:
        require(snapshot['slots'][label(name)]['requestId'] == ZERO,
                'an unfinished nonlinear case already consumed a slot')
    require(len(case['recordIds']) == len(set(case['recordIds'])) == 27,
            'unexpected linear record identifiers')
    for rid in case['recordIds']:
        before = app['protectedRecordBaselines'][rid]
        after = snapshot['records'][rid]
        require(all(after[key] == before[key] for key in ('owner', 'recordReference', 'releaseLimit')),
                'protected-record terms changed')
        require(after['spent'] == before['spent'] + 1 <= after['releaseLimit'],
                'completed linear counter changed or would be replayed')
    return {'profile': 'completed-linear-readiness-prefix-audit-v1', 'status': 'passed',
            'scope': 'completed-linear-case-only', 'predecessorStatus': state['status'],
            'analysisComplete': False, 'completedCase': names[0],
            'remainingCases': names[1:], 'completedReleaseCount': 1,
            'reservationRequestId': case['releaseRequestId'],
            'pinnedBlock': snapshot['blockNumber'], 'pinnedBlockHash': snapshot['blockHash']}


def audit(run, snapshot_file):
    run = Path(run).resolve()
    require(run.parent == MODULE / 'runs', 'unexpected predecessor location')
    require(not (run / 'seal.json').exists(), 'do not replace a sealed predecessor')
    state = read(run / 'state.json')
    require(state.get('error') == 'recipient exited (code 101, OOM=False); no release will be retried',
            'unsupported predecessor failure')
    diagnostics = (run / 'container-diagnostics.log').read_text(errors='replace')
    require('recipient release signing failed' in diagnostics
            and "actual: 'canonical-bounty-nonlinear-v2'" in diagnostics
            and "expected: 'canonical-nonlinear'" in diagnostics,
            'the specific decoder incompatibility was not established')
    require(sorted(p.name for p in (run / 'recipient').glob('result-*.json')) == ['result-0.json'],
            'unexpected additional recipient result')
    cache = MODULE / '.cache' / hashlib.sha256(json.dumps(state['source'], sort_keys=True).encode()).hexdigest()
    saved = read(cache / 'complete.json')
    require(saved['source'] == state['source'] and saved['upstream'] == state['upstream'],
            'predecessor source cache changed')
    changes = []
    for name, digest in state['source'].items():
        require(sha(cache / 'app' / name) == digest, 'frozen predecessor source changed: ' + name)
        if sha(ROOT / name) != digest:
            changes.append(name)
    require(changes == ['threshold-kms/scripts/kms-request-adapter.mjs'],
            'unexpected change to existing measured sources: ' + repr(changes))
    summary = validate_material(state, read(run / 'reports/application.json'),
                                read(run / 'fixtures/prepared.json'), read(run / 'recipient/result-0.json'),
                                read(run / 'owner/expected.json'), read(run / 'keyset/ready.json'),
                                read(snapshot_file))
    summary.update(predecessor=str(run), sourceDelta=changes,
                   sourceCache=str(cache), snapshotSha256=sha(snapshot_file),
                   evidenceSha256={name: sha(run / name) for name in (
                       'state.json', 'reports/application.json', 'fixtures/prepared.json',
                       'recipient/result-0.json', 'owner/expected.json', 'keyset/ready.json')})
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    summary = audit(args.run, args.snapshot)
    with args.output.open('x') as stream:
        stream.write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: summary[key] for key in ('profile', 'status', 'scope', 'predecessorStatus')}))
