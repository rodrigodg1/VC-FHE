#!/usr/bin/env python3
"""Read-only provenance for one complete, sealed V3 Test PoC run.

The counterpart of verify_composite.py for an uninterrupted campaign: no
predecessor, continuation or recovery claim exists. It never changes the run.
Output is an exclusive new directory under threshold-kms/composites; it is NOT a
analysis completion.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from verify_composite import MODULE, ROOT, read, require, sha

KIND = 'single-complete-run'


def seal_path(run):
    """The runner seal, or an explicit post-hoc export seal (never both)."""
    normal, posthoc = run / 'seal.json', run / 'posthoc-seal.json'
    require(normal.exists() != posthoc.exists(), 'expected exactly one of seal.json or posthoc-seal.json')
    return normal if normal.exists() else posthoc


def sealed_reader(run):
    """Return a reader that only yields files bound by the run's seal."""
    files = read(seal_path(run))['files']
    def sealed(rel):
        require(rel in files and sha(run / rel) == files[rel], 'changed or unsealed evidence: ' + rel)
        return read(run / rel)
    return sealed


def load(base):
    """Shared loader for diagnostics/workflow/tables on a single-run provenance."""
    provenance = read(base / 'provenance.json')
    require(provenance.get('kind') == KIND and provenance['validation'] == 'passed'
            and provenance['analysisComplete'] is False, 'unvalidated single-run provenance')
    run = Path(provenance['run'])
    require(sha(seal_path(run)) == provenance['sealSha256'], 'changed campaign seal')
    return provenance, run, sealed_reader(run)


def validate(run):
    run = Path(run).resolve()
    require(run.parent == MODULE / 'runs', 'run must be a direct child of the campaign runs directory')
    state = read(run / 'state.json')
    posthoc = seal_path(run).name == 'posthoc-seal.json'
    require(state['status'] == 'passed' or posthoc, 'run did not complete and seal')
    require(not state['config'].get('recovery'), 'continuation segments need composite provenance')
    sys.path.insert(0, str(MODULE / 'campaign'))
    import run as campaign
    from poc_evidence import validate_full_cases, validate_pairs
    from onchain_evidence import validate_run
    if posthoc:
        from posthoc_seal import verify as verify_posthoc
        verify_posthoc(run)
    else:
        campaign.verify(run)
    sealed = sealed_reader(run)
    cfg, app, paired = sealed('config/campaign.json'), sealed('reports/application.json'), sealed('reports/paired.json')
    distributed=None
    if cfg.get('executionProfile'):
        from distributed_evidence import validate as validate_distributed
        distributed=validate_distributed(run,sealed)
    require(cfg.get('pocPlan') and cfg['classification'] == 'test-insecure-functional-poc'
            and cfg['parameters'] == 'Test', 'not the complete Test PoC plan')
    design = validate_pairs(cfg, paired)
    validate_full_cases(cfg, app, paired)
    require(validate_run(run) == sealed('reports/onchain-release-evidence.json'), 'on-chain evidence summary differs')
    expected = sealed('owner/expected.json')
    for i, case in enumerate(app['cases']):
        result = sealed(f'recipient/result-{i}.json')
        require(result['actual'] == expected[case['name']] and result['outputDigest'] == case['outputDigest'],
                'recipient mismatch: ' + case['name'])
    cache = MODULE / '.cache' / hashlib.sha256(
        json.dumps(state['source'], sort_keys=True).encode()).hexdigest()
    for rel in ['threshold-kms/campaign/poc_evidence.py', 'threshold-kms/campaign/poc_plan.py']:
        require(sha(cache / 'app' / rel) == state['source'][rel], 'changed statistical method')
    report = {'kind': KIND, 'validation': 'passed', 'analysisComplete': False, 'run': str(run),
              'sealKind': seal_path(run).name, 'sealSha256': sha(seal_path(run)),
              'stateSha256': sha(run / 'state.json'),
              'sourceCache': str(cache), 'designSha256': design['designSha256'],
              'measuredPairs': sum(not r['warmup'] for r in paired['rows']),
              'warmups': sum(r['warmup'] for r in paired['rows']), 'fullCases': len(app['cases']),
              'kmsCalls': app['kmsCalls'], 'onchainEvidenceSha256': sha(run / 'reports/onchain-release-evidence.json'),
              'interruptions': 0,
              'scope': 'Insecure Test PoC on one host; no confidentiality, production or independent-party claim.'}
    if distributed is not None:
        report['distributedExecution']=distributed
        report['distributedExecutionSha256']=sha(run/'distributed/execution.json')
        report['scope']='Complete Test campaign across four Google Cloud hosts and regions, under common administration.'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='new directory under threshold-kms/composites')
    args = parser.parse_args()
    report = validate(args.run)
    print(json.dumps(report, indent=2))
    if args.output:
        out = args.output.resolve()
        require(out.parent == MODULE / 'composites' and not out.exists(), 'new composites child required')
        out.mkdir()
        (out / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
