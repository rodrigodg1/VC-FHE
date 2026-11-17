import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
FIXTURE = HERE/'fixtures/original-cloud'
sys.path.insert(0, str(SOURCE))
spec = importlib.util.spec_from_file_location('focused_profile_preparer', HERE/'prepare.py')
preparer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparer)


@contextlib.contextmanager
def isolated_modules(directory, baseline=False):
    names = ['diagnostic_profile', 'topology', 'deployment', 'smoke', 'collect', 'supplement', 'budget']
    previous = {name: sys.modules.pop(name, None) for name in names}
    old_path = list(sys.path)
    sys.path.insert(0, str(directory))
    try:
        modules = {name: importlib.import_module(name) for name in names
                   if not baseline or name != 'diagnostic_profile'}
        # Only test lookup of the unchanged original parser and validators.
        modules['deployment'].ROOT = SOURCE.parent
        yield modules
    finally:
        for name in names:
            sys.modules.pop(name, None)
            if previous[name] is not None:
                sys.modules[name] = previous[name]
        sys.path[:] = old_path


class FocusedProfileProposalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)/'cloud-candidate'
        self.report = preparer.prepare(self.output, FIXTURE)
        self.base = json.loads((SOURCE/'config.example.json').read_text())
        self.focused = copy.deepcopy(self.base)
        self.focused.update(execution_mode='smoke', diagnostic_profile='regional-output-release-v1',
                            campaign='vcfhe-reg-smoke', maximum_vm_runtime_seconds=14400)

    def case(self, disputes=1):
        return {'name': 'regional_qoe_compliance-0', 'half': 'nonlinear', 'n': 50,
                'regional': True, 'metrics': {'disputes': [{} for _ in range(disputes)]}}

    def test_one_regional_config_retains_real_protocol_and_fresh_lineage(self):
        with isolated_modules(self.output) as m:
            cfg = m['deployment'].campaign_config(self.focused, 'fresh-focused-fixture')
            self.assertTrue(m['diagnostic_profile'].validate_campaign(cfg))
            self.assertEqual((cfg['half'], cfg['linearSizes'], cfg['records'], cfg['repeats'],
                              cfg['nonlinearWorkloads']), ('nonlinear', [], 50, 1, ['regional']))
            self.assertEqual(cfg['windowSeconds'], 120)
            self.assertNotIn('pocPlan', cfg)
            self.assertNotIn('keysetReuse', cfg)
            self.assertEqual(cfg['policyLineage']['continuityWithLocalRun'], False)
            self.assertEqual(m['topology'].plan(self.focused)['active_grid'],
                             {'full_workflows': 1, 'paired_measurements': 0, 'warmups': 0})
            self.assertEqual(m['topology'].plan(self.focused)['role_counts'],
                             {'validator':4,'kms':4,'owner':4,'operator':1,'auditor':3,
                              'adjudicator':3,'recipient':1,'coordinator':1})
            self.assertEqual(m['topology'].plan(self.focused)['measurement_grid'], self.base['measurement_grid'])

    def test_default_three_case_smoke_and_full_grid_are_byte_equivalent(self):
        smoke_base = dict(self.base, execution_mode='smoke')
        with isolated_modules(FIXTURE, baseline=True) as original:
            self.assertEqual(Path(original['deployment'].__file__).parent, FIXTURE)
            self.assertEqual(Path(original['topology'].__file__).parent, FIXTURE)
            full = original['deployment'].campaign_config(self.base, 'fixture')
            smoke = original['deployment'].campaign_config(smoke_base, 'fixture')
        with isolated_modules(self.output) as m:
            self.assertEqual(m['deployment'].campaign_config(self.base, 'fixture'), full)
            self.assertEqual(m['deployment'].campaign_config(smoke_base, 'fixture'), smoke)
            self.assertEqual(m['topology'].plan(smoke_base)['active_grid']['full_workflows'], 3)
            self.assertEqual(m['topology'].plan(self.base)['measurement_grid']['full_workflows'], 27)
            self.assertEqual((full['pocPlan']['measuredPairs'], full['pocPlan']['fullCases']), (480, 27))
            self.assertEqual(m['diagnostic_profile'].expected_counts(smoke), (3, 2))
            self.assertEqual(m['diagnostic_profile'].expected_counts(full), (27, 18))

    def test_all_participants_and_four_hour_infrastructure_are_rendered(self):
        with isolated_modules(self.output) as m:
            modules = {}
            for name in ['configure', 'gcp']:
                spec = importlib.util.spec_from_file_location('focused_'+name, SOURCE/(name+'.py'))
                modules[name] = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(modules[name])
            nodes = m['topology'].inventory(self.focused)
            identities = {n['id']: {'node': n['id'], 'host': n['host'],
                'address': '0x'+f'{i+1:040x}', 'fingerprint256': f'{i+1:064x}',
                'certificate': 'SYNTHETIC PUBLIC CERTIFICATE', 'binarySha256': 'a'*64,
                'setupPublicKey': '02'+'b'*64} for i,n in enumerate(nodes)}
            output = Path(self.directory.name)/'participants'
            report = modules['configure'].render(self.focused, identities, '0x'+'1'*64, output, 'fixture')
            self.assertEqual(report['participants'], 21)
            for i in range(1,5):
                cfg = json.loads((output/f'owner-{i}/campaign.json').read_text())
                self.assertTrue(m['diagnostic_profile'].validate_campaign(cfg))
                self.assertEqual((output/f'kms-{i}/client.toml').read_text().count('[[cores]]'), 4)
                self.assertIn('num_reconstruct = 3', (output/f'kms-{i}/client.toml').read_text())
            resource = modules['gcp'].terraform(self.focused)['resource']['google_compute_instance']
            self.assertEqual(len(resource), 4)
            self.assertTrue(all(vm['scheduling']['max_run_duration']['seconds']==14400
                                for vm in resource.values()))

    def test_budget_retains_all_six_windows_and_exact_four_hour_quote(self):
        quote = {'currency':'USD', 'campaign':self.focused['campaign'], 'layout':'four-hosts',
                 'hourly':{'compute':'0.8','nat':'0.2','disks':'0.1','ipv4':'0'},
                 'planned_hours':'4', 'build_registry':'2', 'retained_resources':'1',
                 'transfer_storage_upper_bound':'8', 'quoted_at':datetime.now(timezone.utc).isoformat(),
                 'source_urls':['https://example.org/synthetic-test-only']}
        with isolated_modules(self.output) as m:
            result = m['budget'].assess(self.focused, quote)
            self.assertEqual(result['mandatory_window_hours'], '0.2')
            self.assertFalse(result['changes_protocol_windows'])
            self.assertFalse(result['billing_hard_cap'])
            with self.assertRaises(ValueError):
                m['budget'].assess(self.focused, dict(quote, planned_hours='6'))

    def test_one_case_still_requires_the_original_fault_dispute(self):
        with isolated_modules(self.output) as m:
            cfg = m['deployment'].campaign_config(self.focused, 'fixture')
            result = m['smoke'].validate_cases([self.case()], cfg)
            self.assertEqual((result['fullCases'], result['nonlinearDisputes']), (1, 1))
            self.assertFalse(result['evaluationPublishable'])
            self.assertEqual(m['diagnostic_profile'].expected_counts(cfg), (1, 1))
            for cases in [[], [self.case(0)], [self.case(2)], [self.case(), self.case()]]:
                with self.assertRaises(ValueError):
                    m['smoke'].validate_cases(cases, cfg)
            wrong = self.case()
            wrong['name'] = 'regulatory_qoe_compliance-0'
            with self.assertRaises(ValueError):
                m['smoke'].validate_cases([wrong], cfg)
            # Without the explicit profile, the standard smoke still demands all three.
            with self.assertRaises(ValueError):
                m['smoke'].validate_cases([self.case()])

    def test_four_hour_bound_cannot_shorten_other_campaigns_or_protocol_windows(self):
        with isolated_modules(self.output) as m:
            m['topology'].validate(self.focused)
            for change in [dict(diagnostic_profile=None), dict(execution_mode='evaluation'),
                           dict(window_seconds=119), dict(window_seconds=121),
                           dict(maximum_vm_runtime_seconds=14399), dict(diagnostic_profile='unknown')]:
                cfg = dict(self.focused, **change)
                with self.assertRaises(ValueError):
                    m['topology'].validate(cfg)
            cfg = dict(self.base, maximum_vm_runtime_seconds=14400)
            with self.assertRaises(ValueError):
                m['topology'].validate(cfg)

    def test_classification_and_profile_cannot_be_relabelled_as_evaluation(self):
        with isolated_modules(self.output) as m:
            cfg = m['deployment'].campaign_config(self.focused, 'fixture')
            for change in [dict(smoke=False), dict(readinessOnly=False), dict(half='both'),
                           dict(nonlinearWorkloads=['regulatory', 'regional']), dict(keysetReuse={'x': 1}),
                           dict(pocPlan={'fullCases': 1}), dict(distributedDiagnosticProfile=None)]:
                with self.assertRaises(ValueError):
                    m['diagnostic_profile'].validate_campaign(dict(cfg, **change))
            run = Path(self.directory.name)/'publication-refusal'
            (run/'config').mkdir(parents=True)
            (run/'config/campaign.json').write_text(json.dumps(cfg))
            spec = importlib.util.spec_from_file_location('original_publication_guard', SOURCE/'publication.py')
            publication = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(publication)
            with self.assertRaisesRegex(ValueError, 'cannot be published'):
                publication.generate(run, Path(self.directory.name)/'unused')

    def test_collector_uses_config_and_nonlinear_seal_without_changing_validators(self):
        text = (self.output/'collect.py').read_text()
        self.assertEqual(text.count("validate_cases(app['cases'],cfg)"), 2)
        self.assertIn("'halves':[cfg['half']] if cfg['half']!='both' else ['linear','nonlinear']", text)
        self.assertIn('module.verify(run)', text)
        self.assertIn("str(Path(__file__).with_name('experiment_plan.py'))", text)
        self.assertFalse(self.report['originalSecurityValidatorsEdited'])
        self.assertFalse(self.report['runtimeAdapterEdited'])
        self.assertEqual(set(self.report['outputs']), set(preparer.FILES)|{'diagnostic_profile.py'})
        self.assertIn('+++ b/VC-FHE/distributed/diagnostic_profile.py',
                      (self.output/'profile.proposed.patch').read_text())
        for file in self.output.glob('*.py'):
            compile(file.read_text(), str(file), 'exec')

    def test_source_drift_and_existing_output_fail_closed(self):
        with self.assertRaises(ValueError):
            preparer.prepare(self.output, FIXTURE)
        source = Path(self.directory.name)/'drifted'
        source.mkdir()
        for name in preparer.FILES:
            shutil.copyfile(FIXTURE/name, source/name)
        with (source/'collect.py').open('a') as stream:
            stream.write('\n# drift\n')
        with self.assertRaisesRegex(ValueError, 'reviewed cloud source changed'):
            preparer.prepare(Path(self.directory.name)/'refused', source)
        expected = json.loads((HERE/'source-guards.json').read_text())
        self.assertEqual(expected, {name: hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest()
                                    for name in preparer.FILES})


if __name__ == '__main__':
    unittest.main()
