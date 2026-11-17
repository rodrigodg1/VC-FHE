"""Validate isolated committee controls without treating fixtures as FHE measurements."""
import json
from pathlib import Path

VERSION = 'committee-availability-local-v1'
REPORT = 'reports/committee-availability/committee-availability.json'
EXPECTED = {
    'context-certification-needs-quorum': {'threshold': 2, 'rejectedSignerCounts': [0, 1], 'acceptedSignerCount': 2},
    'baseline-zero-result-signatures': {'contextCertified': True, 'resultSignatures': 0, 'accepted': False},
    'baseline-one-result-signature': {'contextCertified': True, 'resultSignatures': 1, 'accepted': False},
    'optimistic-uncontested-after-context': {'contextCertified': True, 'auditFixtureOpened': True, 'resultSignatures': 0, 'accepted': True},
    'baseline-quorum-restored': {'resultSignatures': 2, 'accepted': True},
    'admitted-dispute-without-certificate': {'finalizationBlocked': True, 'timeoutAttributionBlocked': True, 'operatorBalancePreserved': True},
    'admitted-dispute-one-result-signature': {'resultSignatures': 1, 'settlementBlocked': True},
    'admitted-dispute-quorum-restored': {'resultSignatures': 2, 'operatorRejected': True},
    'no-audit-negative-control': {'operatorFixture': 4, 'canonicalFixture': 3, 'auditsSubmitted': 0, 'optimisticGameAccepted': True, 'baselineAccepted': False},
}


def require(condition, message):
    if not condition: raise ValueError('committee controls: '+message)


def validate(run, sealed_files=None):
    run = Path(run)
    cfg = json.loads((run/'config/campaign.json').read_text())
    if cfg.get('availabilityControlsVersion') is None: return None
    require(cfg['availabilityControlsVersion']==VERSION and cfg['half'] in {'nonlinear','both'}
            and cfg.get('nonlinearProtocol')=='bounty-v2', 'unsupported scope')
    if sealed_files is not None: require(REPORT in sealed_files, 'unsealed report')
    require((run/REPORT).is_file(), 'missing automatic control report')
    report = json.loads((run/REPORT).read_text())
    require(report.get('schema')==VERSION and report.get('status')=='passed'
            and report.get('classification')=='local-EVM-control-flow-only'
            and report.get('realFheExecutions')==0 and report.get('kmsReleases')==0
            and report.get('externalChain') is False and report.get('sourceUnchanged') is True,
            'invalid control scope or status')
    checks = report.get('checks',[])
    require(len(checks)==len(EXPECTED) and {r['name'] for r in checks}==set(EXPECTED), 'incomplete control set')
    for row in checks:
        require(row.get('status')=='passed' and all(row.get('detail',{}).get(k)==v
                for k,v in EXPECTED[row['name']].items()), 'unexpected outcome: '+row['name'])
    source = json.loads((run/'state.json').read_text())['source']
    hashes = report.get('sourceHashes',{})
    required = {k.removeprefix('fhe-pod/') for k in source if k.startswith('fhe-pod/contracts/src/')}
    required |= {'scripts/evaluate-committee-availability.mjs','scripts/canonical-bounty-client.mjs',
                 'scripts/canonical-chain.mjs','scripts/evm-lib.mjs','contracts/test/chain-harness.mjs'}
    require(set(hashes)==required and all(source.get('fhe-pod/'+k)==v for k,v in hashes.items()),
            'control source differs from campaign source')
    return report
