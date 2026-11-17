"""Keep audit-first scheduling observations separate from compute costs."""
import json
import math
from pathlib import Path

VERSION = 'audit-first-baseline-in-finality-wait-v1'


def require(value, message):
    if not value:
        raise ValueError('nonlinear scheduling: '+message)


def validate(cfg, app):
    version = cfg.get('nonlinearSchedulingVersion')
    if version is None:
        require(not any(c.get('metrics', {}).get('scheduling') for c in app.get('cases', [])),
                'unversioned scheduling observations')
        return None
    require(version == VERSION and cfg['half'] in ('nonlinear', 'both')
            and cfg['nonlinearProtocol'] == 'bounty-v2', 'unsupported profile')
    require(app.get('config', {}).get('nonlinearSchedulingVersion') == version, 'configuration mismatch')
    cases = [c for c in app['cases'] if c['half'] == 'nonlinear']
    require(bool(cases), 'missing nonlinear cases')
    for case in cases:
        m = case['metrics']
        s = m.get('scheduling', {})
        require(s.get('version') == version and s.get('baselinePlacement') == 'after-audit-opening'
                and s.get('finalizationIncludesBaseline') is True, 'missing or incorrect placement')
        for key in ('elapsedMs',):
            require(type(s.get(key)) in (float, int) and math.isfinite(s[key]) and s[key] >= 0,
                    'invalid '+key)
        for key in ('startTimestamp','endTimestamp','commitTimestamp','openTimestamp',
                    'commitDeadline','openDeadline','challengeDeadline'):
            require(type(s.get(key)) is int and s[key] >= 0, 'invalid '+key)
        require(s['commitTimestamp'] <= s['commitDeadline'] < s['openTimestamp'] <= s['openDeadline'],
                'audit missed its commitment or opening window')
        require(s['openTimestamp'] <= s['startTimestamp'] <= s['endTimestamp'],
                'baseline ran before audit opening')
        require(s['openDeadline']-s['commitDeadline'] == cfg['windowSeconds']
                and s['challengeDeadline']-s['openDeadline'] == cfg['windowSeconds'], 'windows changed')
        require(m['baseline'].get('accepted') is True and len(m['baseline']['certificates']) == 2,
                'full certified baseline missing')
        for timer in (m['baseline']['fullReplayWallMs'], m['finalizationMs']):
            require(type(timer) in (float, int) and math.isfinite(timer) and timer >= 0,
                    'invalid overlapping timer')
        require(0 <= m['baseline']['fullReplayWallMs'] <= s['elapsedMs'] <= m['finalizationMs'],
                'inconsistent overlapping timers')
        game, baseline = case['workflowManifest']['game'].lower(), m['baseline']['contract'].lower()
        expected = ['honestSubmitSealedAudit','honestRevealSealedAudit','acceptFullExecution',
                    'finalizeUnchallenged','honestClaimAuditBond']
        observed = [(r['label'], str(r.get('to', '')).lower()) for r in app['receipts']
                    if r['label'] in expected and str(r.get('to', '')).lower() in (game, baseline)]
        destinations = [(label, baseline if label == 'acceptFullExecution' else game) for label in expected]
        require(observed == destinations, 'missing, repeated, misdirected or reordered workflow receipts')
    return version


def validate_run(run, sealed_files=None):
    run = Path(run)
    cfg = json.loads((run/'config/campaign.json').read_text())
    if cfg.get('nonlinearSchedulingVersion') is None:
        return None
    if sealed_files is not None:
        require('reports/application.json' in sealed_files, 'unsealed application observations')
    return validate(cfg, json.loads((run/'reports/application.json').read_text()))
