"""Prepare cloud-only profile copies. Never apply to the active source tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE/'fixtures/original-cloud'
FILES = ('topology.py', 'deployment.py', 'smoke.py', 'collect.py', 'supplement.py', 'budget.py')


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('focused profile source anchor changed: '+old[:80])
    return source.replace(old, new)


def render(name, source):
    if name == 'budget.py':
        source = 'from diagnostic_profile import requested as diagnostic_requested\n'+source
        source = once(source,
            "    hours=amount(quote['planned_hours'] if remaining_hours is None else remaining_hours)",
            "    if diagnostic_requested(config) and amount(quote['planned_hours'])!=4:\n        raise ValueError('the regional diagnostic requires its quoted four-hour bound')\n    hours=amount(quote['planned_hours'] if remaining_hours is None else remaining_hours)")
        return once(source,
            "    nonlinear_cases=2 if config.get('execution_mode')=='smoke' else 18",
            "    nonlinear_cases=1 if diagnostic_requested(config) else 2 if config.get('execution_mode')=='smoke' else 18")
    if name == 'deployment.py':
        source = 'from diagnostic_profile import apply_campaign_profile\n'+source
        source = once(source, "    return {'version':module.VERSION,'half':'both'",
                      "    common={'version':module.VERSION,'half':'both'")
        return once(source, "        'executionProfile':'gcp-four-hosts-role-local-v1'}\n",
                    "        'executionProfile':'gcp-four-hosts-role-local-v1'}\n    return apply_campaign_profile(config,common)\n")
    if name == 'topology.py':
        source = 'from diagnostic_profile import requested as diagnostic_requested, active_grid as diagnostic_active_grid\n'+source
        source = once(source,
            "    if type(duration) is not int or not 21600<=duration<=86400:\n        raise ValueError('bound VM lifetime explicitly between 6 and 24 hours')",
            "    if not diagnostic_requested(config):\n        if type(duration) is not int or not 21600<=duration<=86400:\n            raise ValueError('bound VM lifetime explicitly between 6 and 24 hours')")
        return once(source,
            '            "active_grid": {"full_workflows":3,"paired_measurements":0,"warmups":0}\n                if config.get(\'execution_mode\')==\'smoke\' else config[\'publication\'],',
            '            "active_grid": diagnostic_active_grid(config),')
    if name == 'smoke.py':
        source = 'from diagnostic_profile import validate_campaign as is_regional_diagnostic, validate_cases as validate_regional_diagnostic\n'+source
        return once(source, 'def validate_cases(cases):\n',
            'def validate_cases(cases, config=None):\n    if config is not None and is_regional_diagnostic(config):\n        return validate_regional_diagnostic(cases,config)\n')
    if name == 'collect.py':
        if source.count("validate_cases(app['cases'])") != 2:
            raise ValueError('focused profile collector case guards changed')
        source = source.replace("validate_cases(app['cases'])", "validate_cases(app['cases'],cfg)")
        return once(source, "'halves':['linear','nonlinear']}",
                    "'halves':[cfg['half']] if cfg['half']!='both' else ['linear','nonlinear']}")
    if name == 'supplement.py':
        source = 'from diagnostic_profile import expected_counts\n'+source
        return once(source,
            "    expected_nonlinear=2 if cfg.get('smoke') else 18\n    expected_full=3 if cfg.get('smoke') else 27",
            '    expected_full,expected_nonlinear=expected_counts(cfg)')
    raise ValueError('unexpected cloud profile source')


def prepare(output, source=SOURCE):
    output, source = Path(output), Path(source)
    expected = json.loads((HERE/'source-guards.json').read_text())
    for name in FILES:
        if hashlib.sha256((source/name).read_bytes()).hexdigest() != expected[name]:
            raise ValueError('reviewed cloud source changed: '+name)
    if output.exists() or output.is_symlink():
        raise ValueError('profile output must be a fresh directory')
    output.mkdir(parents=True, mode=0o700)
    patches = []
    for name in FILES:
        original = (source/name).read_text()
        candidate = render(name, original)
        compile(candidate, name, 'exec')
        (output/name).write_text(candidate)
        patches.extend(difflib.unified_diff(original.splitlines(True), candidate.splitlines(True),
            fromfile='a/VC-FHE/distributed/'+name, tofile='b/VC-FHE/distributed/'+name))
    helper = (HERE/'diagnostic_profile.py').read_bytes()
    (output/'diagnostic_profile.py').write_bytes(helper)
    patches.extend(difflib.unified_diff([], helper.decode().splitlines(True),
        fromfile='/dev/null', tofile='b/VC-FHE/distributed/diagnostic_profile.py'))
    (output/'profile.proposed.patch').write_text(''.join(patches))
    report = {'schema': 'vcfhe-regional-release-profile-proposal-v1', 'status': 'not-applied',
              'sources': expected, 'outputs': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in output.glob('*.py')},
              'originalSecurityValidatorsEdited': False, 'runtimeAdapterEdited': False,
              'localCampaignEdited': False, 'cloudResourcesCreated': False}
    (output/'proposal.local.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=SOURCE,
                        help='Exact original source snapshot. Defaults to the public frozen fixture.')
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.source), indent=2))
