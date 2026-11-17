"""Audit a completed zero-release dispute whose host export rejected tuple shape.

Keep the predecessor failed and unsealed. This is a read-only readiness prefix
audit, never an original campaign seal or evaluation evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from readiness_prefix import read, require, sha

MODULE = Path(__file__).resolve().parents[1]
ROOT = MODULE.parent
sys.path.insert(0, str(MODULE / 'campaign'))
from dispute_readiness import validate
from bounty_evidence import economic_observation
from availability_evidence import validate as validate_availability
from run import collect_seal_files
from onchain_evidence import _keccak256

ALLOWED_CHANGES = {'threshold-kms/campaign/bounty_evidence.py',
                   'threshold-kms/campaign/test_bounty_route.py'}
RELAY_CLIENT = 'fhe-pod/scripts/canonical-bounty-client.mjs'


def validate_source_changes(changes, frozen_client, current_client):
    require(set(changes) in (ALLOWED_CHANGES, ALLOWED_CHANGES | {RELAY_CLIENT}),
            'changes exceed the host tuple-validator and calibrated relay repair')
    if RELAY_CLIENT in changes:
        require('Math.min(requested, 16)' in frozen_client
                and current_client == frozen_client.replace('Math.min(requested, 16)', 'Math.min(requested, 48)'),
                'relay changes exceed the calibrated batch-size adjustment')


def validate_chain(app, snapshot):
    require(snapshot['policy'].lower() == app['onChainPolicy']['address'].lower(), 'policy changed')
    case = app['cases'][0]
    settlement = case['metrics']['disputes'][0]['settlement']
    b = settlement['bounty']
    observed = snapshot['completedDispute']
    require(all(observed[k].lower() == b[k].lower() for k in ('game', 'availability', 'taskId')),
            'dispute deployment or task changed')
    require(observed['state'] == settlement['state']
            and observed['disclosedLeaves'] == case['metrics']['leaves'],
            'chain does not confirm the completed disclosure and settlement')
    by_hash = {r['txHash']: r for r in observed['receipts']}
    require(len(by_hash) == len(observed['receipts']) == len(app['receipts']),
            'missing or duplicate independently observed receipts')
    for receipt in app['receipts']:
        actual = by_hash.get(receipt['txHash'])
        require(actual is not None and actual['status'] == 1
                and actual['blockNumber'] <= snapshot['blockNumber'], 'unconfirmed dispute transaction')
        require(all(receipt[k] == actual[k] for k in (
            'blockNumber', 'status', 'from', 'to', 'gasUsed', 'effectiveGasPriceWei',
            'transactionFeeWei', 'valueWei', 'calldataBytes', 'dataDigest')), 'receipt summary differs from chain')
        if 'logs' in receipt or not actual['logs']:
            require([{k: log[k] for k in ('address', 'topics', 'data')} for log in receipt.get('logs', [])]
                    == actual['logs'], 'event evidence differs from chain')
        else:
            # The sampling helper records a transaction summary without logs.
            # Retain and authenticate its missing public event from all four nodes.
            require(receipt['label'] == 'sampleParticipants' and len(actual['logs']) == 1,
                    'unexpected omitted event evidence')
            event = actual['logs'][0]
            require(event['address'].lower() == b['game'].lower()
                    and event['topics'] == [_keccak256(b'ParticipantsSampled(bytes32,bytes32,uint64)'), b['taskId']]
                    and len(event['data']) == 130
                    and 0 < int(event['data'][66:], 16) < actual['blockNumber'],
                    'missing sampling event belongs to another task or block')
        if receipt['label'] == 'publishAuthenticatedTraceBatch':
            require(int(actual['gasLimit']) == 20_000_000
                    and int(actual['gasUsed']) < int(actual['gasLimit']), 'relay gas limit not respected')


def audit(run, snapshot_file):
    run = Path(run).resolve()
    require(run.parent == MODULE / 'runs' and not (run / 'seal.json').exists(),
            'unexpected or sealed predecessor')
    state = read(run / 'state.json')
    require(state['status'] == 'failed' and 'campaign/export.py' in state.get('error', '')
            and 'returned non-zero exit status 1' in state['error'], 'not a failed host export')
    require(state['stages'] and all(s['status'] == 'passed' for s in state['stages'])
            and state['stages'][-1]['name'] == 'evaluation', 'measurement stage did not complete')
    cache = MODULE / '.cache' / hashlib.sha256(json.dumps(state['source'], sort_keys=True).encode()).hexdigest()
    cached = read(cache / 'complete.json')
    require(cached['source'] == state['source'] and cached['upstream'] == state['upstream'],
            'preserved source cache changed')
    changes = []
    for name, digest in state['source'].items():
        require(sha(cache / 'app' / name) == digest, 'frozen source changed: ' + name)
        if sha(ROOT / name) != digest:
            changes.append(name)
    validate_source_changes(changes, (cache / 'app' / RELAY_CLIENT).read_text(), (ROOT / RELAY_CLIENT).read_text())
    require("settlement['state'] == [3, 2, True]" in
            (cache / 'app/threshold-kms/campaign/bounty_evidence.py').read_text(),
            'the specific three-field validator incompatibility was not established')
    cfg = read(run / 'config/campaign.json')
    require(state['config'] == cfg, 'predecessor configuration changed')
    summary = validate(run)
    require(summary['cases'] == ['regulatory_qoe_compliance-0'], 'wrong dispute readiness workload')
    validate_availability(run)
    app = read(run / 'reports/application.json')
    snapshot = read(snapshot_file)
    validate_chain(app, snapshot)
    economic_observation(app['cases'][0], app['receipts'])
    files = collect_seal_files(run)
    files['evaluation.log'] = sha(run / 'evaluation.log')
    return dict(profile='completed-dispute-readiness-prefix-audit-v1', status='passed',
                scope='completed-regulatory-dispute-only-zero-releases', analysisComplete=False,
                predecessorStatus='failed', predecessor=str(run), kmsCalls=0,
                sourceCache=str(cache), sourceDelta=changes,
                validationSources={name: sha(ROOT / name) for name in changes},
                snapshotSha256=sha(snapshot_file), evidenceSha256=files,
                pinnedBlock=snapshot['blockNumber'], pinnedBlockHash=snapshot['blockHash'],
                pending=['regional-full-readiness'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--snapshot', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    summary = audit(args.run, args.snapshot)
    with args.output.open('x') as stream:
        stream.write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: summary[k] for k in ('profile', 'status', 'scope', 'predecessorStatus', 'kmsCalls')}))
