"""Runner integration checks with temporary state and no Docker execution."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import run


def arguments(*extra):
    return run.parser().parse_args([
        '--poc', '--fhe-params', 'Test', '--allow-insecure-test',
        '--nonlinear-protocol', 'bounty-v2', '--kms-threads', '1',
        '--kms-tokio-threads', '1', '--auto-policy-setup', *extra])


def inventory(**resources):
    return dict(project='vcfhe-besu', network='vcfhe-besu_default',
                binding=dict(context='fixture', endpoint='unix:///fixture/docker.sock',
                             daemonId='fixture-daemon'),
                volumes=resources.get('volumes', []),
                networks=resources.get('networks', []),
                containers=resources.get('containers', []))


class StopBeforeBuild(RuntimeError):
    pass


class InitialSetupRunnerTests(unittest.TestCase):
    def test_public_wrappers_enable_inspected_setup_and_keep_the_complete_grid(self):
        root = Path(__file__).resolve().parents[2]
        for script, pairs, cases in [('run-linear.sh', 300, 15),
                                      ('non-linear.sh', 180, 30),
                                      ('run-poc.sh', 480, 45)]:
            with self.subTest(script=script):
                result = subprocess.run(
                    [str(root/script), '--list'], cwd=root, text=True,
                    capture_output=True, timeout=15,
                    env=os.environ | {'VCFHE_CAFFEINATED': '1', 'VCFHE_LEGACY_EVALUATION': '0'})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('POLICY_SETUP automatic only for an empty installation', result.stdout)
                plan = json.loads(result.stdout[result.stdout.index('{'):])
                self.assertEqual((plan['measuredPairs'], plan['fullCases'], plan['windowSeconds']),
                                 (pairs, cases, 120))

    def test_cli_setup_flag_alone_does_not_authorize_identity_or_policy_creation(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(run, 'MODULE', Path(temporary)):
            directory = Path(temporary)/'run-existing'
            directory.mkdir()
            run.configuration(directory, arguments(), 'fixture-image')
            compose = json.loads((directory/'compose.json').read_text())
            for role in ['identities', 'policy-init']:
                self.assertEqual(compose['services'][role]['environment']['VCFHE_ALLOW_NEW_POLICY_LINEAGE'], '0')
            self.assertFalse((directory/'config/identities-compose.json').exists())

    def test_verified_first_setup_provisions_identities_without_external_networks(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(run, 'MODULE', Path(temporary)):
            directory = Path(temporary)/'run-first'
            directory.mkdir()
            args = arguments()
            args.verified_initial_policy_setup = True
            run.configuration(directory, args, 'fixture-image')
            compose = json.loads((directory/'compose.json').read_text())
            isolated = json.loads((directory/'config/identities-compose.json').read_text())
            self.assertEqual(set(isolated['services']), {'identities'})
            self.assertNotIn('networks', isolated)
            identity = isolated['services']['identities']
            self.assertEqual(identity['network_mode'], 'none')
            self.assertNotIn('networks', identity)
            self.assertNotIn('depends_on', identity)
            self.assertEqual(identity, compose['services']['identities'])
            for role in ['identities', 'policy-init']:
                self.assertEqual(compose['services'][role]['environment']['VCFHE_ALLOW_NEW_POLICY_LINEAGE'], '1')

    def test_auto_preflight_classifies_fresh_installation_without_creating_state(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(run, 'MODULE', Path(temporary)), \
             patch.object(run.shutil, 'which', return_value='/fixture/tool'), \
             patch.object(run, 'inspect_docker_state', return_value=inventory()) as inspect, \
             patch.object(run, 'prepare_bootstrap', side_effect=AssertionError('preflight mutated state')):
            report = run.startup_preflight(arguments())
            self.assertTrue(report['startupPrerequisitesPresent'])
            self.assertEqual(report['policyLineage'], 'automatic-first-setup-planned')
            self.assertEqual(report['initialPolicySetup']['kind'], 'fresh')
            self.assertFalse(report['experimentsExecuted'])
            self.assertFalse(report['policyStateChanged'])
            self.assertEqual(list(Path(temporary).iterdir()), [])
            inspect.assert_called_once_with(network='vcfhe-besu_default')

    def test_auto_preflight_rejects_orphaned_chain_without_creating_policy_state(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(run, 'MODULE', Path(temporary)), \
             patch.object(run.shutil, 'which', return_value='/fixture/tool'), \
             patch.object(run, 'inspect_docker_state', return_value=inventory(volumes=['vcfhe-besu_node1'])):
            report = run.startup_preflight(arguments())
            self.assertFalse(report['startupPrerequisitesPresent'])
            self.assertIsNone(report['policyLineage'])
            self.assertIn('orphaned', report['policyError'])
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_setup_preserves_selection_and_all_protocol_windows(self):
        automatic = arguments()
        retained = arguments()
        retained.auto_policy_setup = False
        selected = run.selection(automatic)
        self.assertEqual(selected, run.selection(retained))
        self.assertEqual(selected['windowSeconds'], 120)
        self.assertEqual(selected['pocPlan']['measuredPairs'], 480)
        self.assertEqual(selected['pocPlan']['fullCases'], 45)

    @contextlib.contextmanager
    def mocked_startup(self, temporary, docker_inventory):
        """Stop tests before builds while retaining real bootstrap locking/state checks."""
        with contextlib.ExitStack() as stack:
            args = arguments('--cache-dir', str(Path(temporary)/'cache'))
            stack.enter_context(patch.object(run, 'MODULE', Path(temporary)))
            stack.enter_context(patch.object(run, 'parser')).return_value.parse_args.return_value = args
            stack.enter_context(patch.object(run.subprocess, 'run',
                                             return_value=subprocess.CompletedProcess(['docker', 'info'], 0)))
            stack.enter_context(patch.object(run, 'output', return_value=json.dumps(
                dict(NCPU=4, MemTotal=32*2**30))))
            stack.enter_context(patch.object(run.shutil, 'disk_usage',
                                             return_value=type('Disk', (), {'free': 100*2**30})()))
            stack.enter_context(patch.object(run, 'inspect_docker_state', return_value=docker_inventory))
            command = stack.enter_context(patch.object(run, 'command'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            yield command

    def test_main_prepares_bootstrap_under_lock_before_building(self):
        with tempfile.TemporaryDirectory() as temporary, self.mocked_startup(temporary, inventory()) as command:
            policy = Path(temporary)/'.policy-state'
            original_prepare = run.prepare_bootstrap
            order = []

            def prepare(*args):
                # The real helper raises if the runner has not acquired the lock.
                decision = original_prepare(*args)
                order.append('prepared')
                return decision

            def build(*args):
                self.assertEqual(order, ['prepared'])
                self.assertEqual(json.loads((policy/'bootstrap.json').read_text())['phase'], 'planned')
                raise StopBeforeBuild('intentional stop before any Docker build')

            with patch.object(run, 'prepare_bootstrap', side_effect=prepare), \
                 patch.object(run, 'source_manifest', return_value={}), \
                 patch.object(run, 'build_context', side_effect=build):
                with self.assertRaises(StopBeforeBuild):
                    run.main()
            command.assert_not_called()
            # The same process can reacquire the released bootstrap lock.
            with run.bootstrap_lock(policy):
                pass

    def test_main_rejects_orphaned_resources_before_build_or_state_creation(self):
        with tempfile.TemporaryDirectory() as temporary, \
             self.mocked_startup(temporary, inventory(containers=['vcfhe-besu-node1-1'])) as command, \
             patch.object(run, 'source_manifest') as sources, \
             patch.object(run, 'build_context') as build:
            with self.assertRaisesRegex(ValueError, 'orphaned'):
                run.main()
            sources.assert_not_called()
            build.assert_not_called()
            command.assert_not_called()
            self.assertFalse((Path(temporary)/'.policy-state').exists())


if __name__ == '__main__':
    unittest.main()
