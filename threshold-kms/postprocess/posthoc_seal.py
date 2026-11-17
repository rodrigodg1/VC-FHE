#!/usr/bin/env python3
"""Explicit post-hoc export seal for a measured run whose export validator was fixed.

The campaign runner seals only when export passes with the exact measured source.
When a host-side validator defect stopped export after a passing evaluation, this
tool records that fact instead of rewriting it: state.json keeps its `failed`
status, the measured source closure is preserved, and the only files allowed to
differ are listed host-side validators that no container executes. It re-runs the
validators on the unchanged evidence and writes a new, exclusive
`posthoc-seal.json`. It never writes `seal.json` and never changes the run.
"""
import argparse
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MODULE = HERE.parent
ROOT = MODULE.parent
sys.path.insert(0, str(MODULE / 'campaign'))
from run import VERSION, collect_seal_files, sha  # noqa: E402

SEAL = 'posthoc-seal.json'
KIND = 'posthoc-export-seal'
# Host-side export validators only: no container, measurement or release path runs them.
ALLOWED_VALIDATOR_CHANGES = {
    'threshold-kms/campaign/onchain_evidence.py',
    'threshold-kms/campaign/test_onchain_evidence.py',
}
CONTAINER_SUFFIXES = ('.mjs', '.rs', '.cjs', '.js', '.sol', '.sh')


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def changed_sources(state):
    return {name: {'measuredSha256': digest, 'currentSha256': sha(ROOT / name)}
            for name, digest in state['source'].items() if sha(ROOT / name) != digest}


def check(run, seal=None):
    """Validate a run for (or against) a post-hoc seal; return the seal payload."""
    state = read(run / 'state.json')
    cfg = read(run / 'config/campaign.json')
    require(state['config'] == cfg and cfg['version'] == VERSION, 'state is not bound to the V3 configuration')
    require(not (run / 'seal.json').exists(), 'run already has a runner seal')
    stages = state['stages']
    require(stages and stages[-1]['name'] == 'evaluation' and stages[-1]['status'] == 'passed'
            and all(s['status'] == 'passed' for s in stages), 'evaluation did not pass')
    require(state['status'] == 'failed' and 'export.py' in state.get('error', ''),
            'only an export-stage failure after a passing evaluation is eligible')
    app = read(run / 'reports/application.json')
    require(app['status'] == 'passed' and app['config'] == cfg, 'application evidence did not pass')
    changes = changed_sources(state)
    require(set(changes) <= ALLOWED_VALIDATOR_CHANGES,
            'measured source changed beyond host-side export validators: ' + ', '.join(sorted(set(changes) - ALLOWED_VALIDATOR_CHANGES)))
    require(not any(n.endswith(CONTAINER_SUFFIXES) for n in changes), 'container code changed')
    for name, record in state['datasets'].items():
        require(sha(ROOT / name) == record['sha256'], 'changed source dataset: ' + name)
    from poc_evidence import validate_full_cases, validate_pairs
    from onchain_evidence import validate_run
    paired = read(run / 'reports/paired.json')
    design = validate_pairs(cfg, paired)
    validate_full_cases(cfg, app, paired)
    require(validate_run(run) == read(run / 'reports/onchain-release-evidence.json'),
            'on-chain evidence summary differs from the exported report')
    files = collect_seal_files(run)
    payload = {'version': VERSION, 'kind': KIND, 'measuredSource': state['source'],
               'validatorChanges': changes,
               'reason': ('Evaluation passed; export.py stopped on an owner-oracle precondition that required '
                          'the oracle (498 entries: paired and full-case jobs) to equal the 45 released case '
                          'names. The corrected validator requires released cases to be a subset. '
                          'Per-case plaintext equality with the oracle is unchanged.'),
               'files': files, 'classification': cfg['classification'], 'parameters': cfg['parameters'],
               'halves': [cfg['half']] if cfg['half'] != 'both' else ['linear', 'nonlinear'],
               'designSha256': design['designSha256'], 'runnerStatus': state['status']}
    if seal is not None:
        for key in ['version', 'kind', 'measuredSource', 'validatorChanges', 'files', 'classification',
                    'parameters', 'halves', 'designSha256', 'runnerStatus']:
            require(seal.get(key) == payload[key], 'post-hoc seal differs: ' + key)
    return payload


def verify(run):
    run = Path(run).resolve()
    return check(run, read(run / SEAL))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    require(run.parent == MODULE / 'runs', 'run must be a direct child of the campaign runs directory')
    payload = check(run)
    payload['sealedAt'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    with (run / SEAL).open('x') as stream:
        json.dump(payload, stream, indent=2)
        stream.write('\n')
    verify(run)
    print(json.dumps({k: payload[k] for k in ['kind', 'validatorChanges', 'designSha256', 'runnerStatus']}, indent=2))
    print('files sealed:', len(payload['files']))


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error))
