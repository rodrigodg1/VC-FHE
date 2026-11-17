"""Portable profile regressions. No cloud, FHE, credentials or ignored runs."""
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import budget
import deployment
import diagnostic_profile
import analysis
import smoke
import topology

PROPOSAL = HERE/'maintenance/proposals/regional-release-diagnostic'
FROZEN = PROPOSAL/'fixtures/original-cloud'


@contextlib.contextmanager
def original_modules():
    names = ['topology', 'deployment', 'smoke', 'budget']
    saved = {name: sys.modules.pop(name, None) for name in names}
    old_path = list(sys.path)
    sys.path.insert(0, str(FROZEN))
    try:
        modules = {name: importlib.import_module(name) for name in names}
        modules['deployment'].ROOT = HERE.parent
        for module in modules.values():
            if Path(module.__file__).parent != FROZEN:
                raise AssertionError('default comparison did not load the original fixture')
        yield modules
    finally:
        for name in names:
            sys.modules.pop(name, None)
            if saved[name] is not None:
                sys.modules[name] = saved[name]
        sys.path[:] = old_path


class RegionalDiagnosticProfileTests(unittest.TestCase):
    def setUp(self):
        self.base = json.loads((HERE/'config.example.json').read_text())
        self.focused = copy.deepcopy(self.base)
        self.focused.update(execution_mode='smoke', diagnostic_profile=diagnostic_profile.PROFILE,
                            campaign='vcfhe-reg-smoke', maximum_vm_runtime_seconds=14400)

    def common(self):
        return deployment.campaign_config(self.focused, 'fresh-regional-fixture')

    def regional_case(self, disputes=1):
        return {'name':'regional_qoe_compliance-0', 'half':'nonlinear', 'n':50,
                'regional':True, 'metrics':{'disputes':[{} for _ in range(disputes)]}}

    def test_one_regional_and_original_dispute_are_mandatory(self):
        cfg = self.common()
        result = smoke.validate_cases([self.regional_case()], cfg)
        self.assertEqual((result['fullCases'], result['nonlinearDisputes']), (1, 1))
        self.assertFalse(result['evaluationPublishable'])
        self.assertEqual(diagnostic_profile.expected_counts(cfg), (1, 1))
        self.assertEqual((cfg['half'], cfg['records'], cfg['repeats'], cfg['linearSizes'],
                          cfg['nonlinearWorkloads']), ('nonlinear', 50, 1, [], ['regional']))
        for cases in [[], [self.regional_case(0)], [self.regional_case(2)],
                      [self.regional_case(), self.regional_case()]]:
            with self.assertRaises(ValueError):
                smoke.validate_cases(cases, cfg)
        wrong = self.regional_case()
        wrong['name'] = 'regulatory_qoe_compliance-0'
        with self.assertRaises(ValueError):
            smoke.validate_cases([wrong], cfg)


    def test_standard_smoke_still_requires_three_cases_and_two_disputes(self):
        cases = [{'name':'linear-acr-27-0','half':'linear','n':27},
                 {'name':'regulatory_qoe_compliance-0','half':'nonlinear','n':50,
                  'metrics':{'disputes':[{}]}}, self.regional_case()]
        self.assertEqual(smoke.validate_cases(cases)['nonlinearDisputes'], 2)
        with self.assertRaises(ValueError):
            smoke.validate_cases([self.regional_case()])

    def test_four_hour_exception_is_explicit_and_does_not_change_windows(self):
        topology.validate(self.focused)
        self.assertEqual(self.common()['windowSeconds'], 120)
        for update in [dict(diagnostic_profile=None), dict(diagnostic_profile='unknown'),
                       dict(execution_mode='evaluation'), dict(window_seconds=119),
                       dict(window_seconds=121), dict(maximum_vm_runtime_seconds=14399)]:
            with self.assertRaises(ValueError):
                topology.validate(dict(self.focused, **update))
        with self.assertRaises(ValueError):
            topology.validate(dict(self.base, maximum_vm_runtime_seconds=14400))

    def test_fresh_keyset_lineage_all_roles_and_full_measurement_grid_remain(self):
        cfg = self.common()
        self.assertNotIn('keysetReuse', cfg)
        self.assertNotIn('pocPlan', cfg)
        self.assertEqual(cfg['policyLineage'], {'kind':'explicit-new-distributed-lineage',
                                              'continuityWithLocalRun':False})
        plan = topology.plan(self.focused)
        self.assertEqual(plan['active_grid'], {'full_workflows':1,'paired_measurements':0,'warmups':0})
        self.assertEqual(plan['measurement_grid'], self.base['measurement_grid'])
        self.assertEqual(plan['role_counts'], {'validator':4,'kms':4,'owner':4,'operator':1,
                                              'auditor':3,'adjudicator':3,'recipient':1,'coordinator':1})
        manifests = deployment.manifests(self.focused, 'fixture')
        cores = [service for doc in manifests.values() for name,service in doc['services'].items()
                 if name.endswith('-core')]
        self.assertEqual(len(cores), 4)
        self.assertEqual({c['environment']['VCFHE_PARTY'] for c in cores}, {'1','2','3','4'})


    def test_profile_and_actual_publisher_refuse_evaluation_relabelling(self):
        cfg = self.common()
        for update in [dict(smoke=False), dict(readinessOnly=False), dict(half='both'),
                       dict(distributedDiagnosticProfile=None), dict(pocPlan={'fullCases':1}),
                       dict(keysetReuse={'restored':True})]:
            with self.assertRaises(ValueError):
                diagnostic_profile.validate_campaign(dict(cfg, **update))
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run/'config').mkdir()
            (run/'config/campaign.json').write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, 'not a complete campaign'):
                analysis.generate(run, run/'unused')

    def test_budget_accounts_for_one_case_all_six_windows_and_four_hours(self):
        quote = {'currency':'USD','campaign':self.focused['campaign'],'layout':'four-hosts',
                 'hourly':{'compute':'0.8','nat':'0.2','disks':'0.1','ipv4':'0'},
                 'planned_hours':'4','build_registry':'2','retained_resources':'1',
                 'transfer_storage_upper_bound':'8','quoted_at':datetime.now(timezone.utc).isoformat(),
                 'source_urls':['https://example.org/synthetic-test-only']}
        result = budget.assess(self.focused, quote)
        self.assertEqual(result['mandatory_window_hours'], '0.2')
        self.assertFalse(result['changes_protocol_windows'])
        with self.assertRaises(ValueError):
            budget.assess(self.focused, dict(quote, planned_hours='6'))


if __name__ == '__main__':
    unittest.main()
