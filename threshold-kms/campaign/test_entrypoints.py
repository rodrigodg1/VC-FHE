import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]


class PublicEntryTests(unittest.TestCase):

    def plan(self, script, *args):
        return subprocess.run([str(ROOT/script),*args,'--list'],cwd=ROOT,text=True,
                              capture_output=True,timeout=15,
                              env=os.environ|{'VCFHE_CAFFEINATED':'1','VCFHE_LEGACY_EVALUATION':'0'})

    def test_independent_and_combined_defaults(self):
        for name, pairs, full, protocol in [('run-linear.sh',300,15,'not-used'),
                                           ('non-linear.sh',180,30,'bounty-v2'),
                                           ('run-nonlinear.sh',180,30,'bounty-v2'),
                                           ('run-nonlinear-bounty.sh',180,30,'bounty-v2'),
                                           ('run-poc.sh',480,45,'bounty-v2')]:
            with self.subTest(script=name):
                result=self.plan(name);self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('FHE_PARAMETERS Test',result.stdout)
                self.assertIn('NONLINEAR_PROTOCOL '+protocol,result.stdout)
                self.assertIn('results-analysis',result.stdout)
                self.assertNotIn('evaluation-update',result.stdout)
                self.assertEqual('nonlinear:committee-availability-controls' in result.stdout,protocol=='bounty-v2')
                self.assertEqual('NONLINEAR_SCHEDULING audit-first-baseline-in-finality-wait-v1 (protocol windows unchanged)'
                                 in result.stdout,protocol=='bounty-v2')
                self.assertEqual('LINEAR_COMPILATION source-and-compiler-keyed in-process cache'
                                 in result.stdout,name in ('run-linear.sh','run-poc.sh'))
                data=json.loads(result.stdout[result.stdout.index('{'):])
                self.assertEqual(data['measuredPairs'],pairs);self.assertEqual(data['fullCases'],full)
                self.assertEqual(data['windowSeconds'],120)

    def test_pilots_are_not_full_publication_designs(self):
        for name in ['run-linear.sh','non-linear.sh','run-poc.sh','run-nonlinear-bounty.sh']:
            result=self.plan(name,'--readiness');self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('"measuredPairs"',result.stdout)

    def test_legacy_selection_is_explicit_and_lineage_cannot_reset(self):
        result=self.plan('non-linear.sh','--nonlinear-protocol','canonical')
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('PROTOCOL canonical',result.stdout)
        self.assertNotIn('NONLINEAR_SCHEDULING',result.stdout)
        result=self.plan('run-poc.sh','--new-policy-lineage')
        self.assertNotEqual(result.returncode,0);self.assertIn('existing release-policy lineage',result.stderr)

    def test_readonly_postprocess_route_never_invokes_campaign_stages(self):
        from unittest.mock import patch
        import run
        with patch('sys.argv',['run.py','--postprocess-only','--run-dir','/nonexistent/test-run']),\
             patch.object(run,'postprocess') as derived,\
             patch.object(run,'selection',side_effect=AssertionError('experiment selection reached')):
            run.main()
        self.assertEqual(derived.call_count,1)

    def test_preflight_reports_missing_state_without_recreating_it(self):
        from unittest.mock import patch
        import tempfile
        import run
        with tempfile.TemporaryDirectory() as directory,patch.object(run,'MODULE',Path(directory)),\
             patch.object(run.shutil,'which',return_value='/tool'):
            report=run.startup_preflight(run.parser().parse_args(['--half','both']))
            self.assertFalse(report['startupPrerequisitesPresent'])
            self.assertFalse(report['experimentsExecuted'])
            self.assertFalse((Path(directory)/'.policy-state').exists())

    def test_preflight_does_not_claim_live_chain_capacity(self):
        from unittest.mock import patch
        import run
        with patch.object(run,'policy_lineage',return_value='existing-on-chain-lineage'),\
             patch.object(run.shutil,'which',return_value='/tool'):
            report=run.startup_preflight(run.parser().parse_args([]))
            self.assertTrue(report['startupPrerequisitesPresent'])
            self.assertIn('live policy counters and chain state',report['notChecked'])

    def test_public_postprocess_options_reach_derivation_without_experiments(self):
        from unittest.mock import patch
        import run
        args=run.parser().parse_args(['--postprocess-only','--run-dir','/retained/run',
            '--derived-dir','/derived/new'])
        with patch.object(run,'command') as command:
            run.postprocess(Path('/retained/run'),args)
        called=[str(x) for x in command.call_args.args[0]]
        self.assertEqual(called[called.index('--output')+1],'/derived/new')
        self.assertNotIn('docker',called)
        self.assertNotIn('--manual-review',called)
        args.manual_review=True
        with patch.object(run,'command') as command:
            run.postprocess(Path('/retained/run'),args)
        self.assertIn('--manual-review',[str(x) for x in command.call_args.args[0]])


