"""Validate a separately classified real-FHE dispute pilot with zero releases."""
import json
from pathlib import Path
from bounty_evidence import validate_bounty_evidence, economic_observation

PROFILE = 'bounty-v2-dispute-readiness-v1'
CLASSIFICATION = 'test-insecure-dispute-readiness-not-evaluation'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(run, write=False):
    run = Path(run)
    read = lambda name: json.loads((run / name).read_text())
    cfg, app, prepared, keys = [read(p) for p in ('config/campaign.json', 'reports/application.json',
                                                'fixtures/prepared.json', 'keyset/ready.json')]
    require(cfg.get('readinessDisputesOnly') == PROFILE and cfg.get('classification') == CLASSIFICATION
            and cfg.get('half') == 'nonlinear' and cfg.get('parameters') == 'Test'
            and cfg.get('readinessOnly') and cfg.get('smoke') and cfg.get('records') == 50
            and cfg.get('repeats') == 1 and cfg.get('nonlinearProtocol') == 'bounty-v2'
            and not cfg.get('pocPlan') and not cfg.get('policyRefreshPlan'), 'invalid dispute readiness scope')
    require(app['status'] == 'passed' and app['config'] == cfg, 'dispute pilot did not pass')
    require(app['keys'] == prepared['keys'] == keys and keys['status'] == 'passed'
            and keys['parameters'] == 'Test' and keys['fullPreprocessing']
            and not keys['preloadedFheKey'], 'missing real generated Test keyset')
    require(app['kmsCalls'] == 0 and not app['policyEvents'] and not app['protectedRecordBaselines']
            and not app['protectedRecords'], 'dispute-only pilot made release-policy changes')
    for folder, pattern in [('exchange', 'request-*.json'), ('recipient', 'result-*.json'),
                            ('release-evidence', '*.json')]:
        require(not list((run / folder).glob(pattern)), 'unexpected decryption request or result')
    names = [f'{name}_qoe_compliance-0' for name in cfg['nonlinearWorkloads']]
    require([row['name'] for row in app['cases']] == [row['name'] for row in prepared['cases']] == names,
            'incomplete dispute readiness coverage')
    for case in app['cases']:
        require(case['half'] == 'nonlinear' and case['n'] == 50
                and case.get('readinessScope') == 'dispute-only-no-output-release', 'wrong dispute case')
        disputes = case['metrics']['disputes']
        require(len(disputes) == 1 and disputes[0]['faultIndex'] == case['metrics']['leaves'] - 1,
                'terminal faulty case was not exercised')
        certificates = disputes[0]['settlement']['certificates']
        require(len(certificates) == 2 and all(c['plaintextOpenings'] == 0 for c in certificates),
                'missing public leaf certificates or intermediate plaintext opening')
    validate_bounty_evidence(cfg, app)
    summary = {'profile': PROFILE, 'status': 'passed', 'classification': CLASSIFICATION,
               'analysisComplete': False, 'kmsCalls': 0, 'cases': names}
    if write:
        (run / 'reports/dispute-readiness.json').write_text(json.dumps(summary, indent=2) + '\n')
        economics = {'profile': 'bounty-economics-observations-v1', 'analysisComplete': False,
                     'configuration': cfg['bountyEconomics'],
                     'cases': [{'case': c['name'], **economic_observation(c, app['receipts'])}
                               for c in app['cases']]}
        (run / 'reports/bounty-economics.json').write_text(json.dumps(economics, indent=2) + '\n')
        (run / 'reports/READINESS-ONLY.txt').write_text(
            'Dispute-only Test readiness. No output request, release or completed analysis.\n')
    return summary
