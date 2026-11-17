"""Local bootstrap state tests. No Docker daemon or experiment is used."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import policy_bootstrap as bootstrap


def inventory(resources=False):
    return {'project': bootstrap.PROJECT, 'network': bootstrap.NETWORK,
            'binding': {'context': 'desktop-linux', 'endpoint': 'unix:///example/docker.sock',
                        'daemonId': 'retained-daemon-id'},
            'volumes': ['vcfhe-besu_net'] if resources else [],
            'networks': ['vcfhe-besu_default'] if resources else [], 'containers': []}


def write_identities(root):
    for relative in bootstrap.IDENTITIES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(['0x' + f'{index:064x}' for index in range(1, 5)])
                        if relative.startswith('owner/') else f'{8 if relative.startswith("setup/") else 9:064x}')


def write_deployment(root, status='deployed'):
    path = root / 'onchain/deployment.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {'schema': 'vcfhe-release-policy-deployment-v3', 'status': status,
             'address': '0x' + 'a' * 40, 'chainId': '46853', 'policyVersion': '3',
             'genesisBlockHash': '0x' + 'b' * 64, 'transactionHash': '0x' + 'c' * 64,
             'deploymentBlock': 2, 'deploymentBlockHash': '0x' + 'd' * 64,
             'sourceSha256': 'e' * 64, 'compilerVersion': 'test-compiler'}
    path.write_text(json.dumps(value))
    return value


class PolicyBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / '.policy-state'

    def prepare(self):
        return bootstrap.prepare_bootstrap(self.root, inventory())

    def identities_ready(self):
        self.prepare()
        write_identities(self.root)
        return bootstrap.mark_identities_ready(self.root, inventory())

    def policy_started(self):
        self.identities_ready()
        return bootstrap.mark_policy_starting(self.root, inventory(True))

    def test_classification_never_creates_state_or_lock(self):
        self.assertEqual(bootstrap.classify_bootstrap(self.root, inventory())['kind'], 'fresh')
        self.assertEqual(list(self.root.parent.iterdir()), [])

    def test_mutations_require_policy_lock(self):
        for function in (bootstrap.prepare_bootstrap, bootstrap.mark_identities_ready,
                         bootstrap.mark_policy_starting, bootstrap.mark_deployed):
            with self.subTest(function=function.__name__), self.assertRaisesRegex(RuntimeError, 'bootstrap_lock'):
                function(self.root, inventory())
        self.assertFalse(self.root.exists())

    def test_fresh_manifest_is_persistent_and_exclusive(self):
        with bootstrap.bootstrap_lock(self.root):
            first = self.prepare()
            second = self.prepare()
            self.assertEqual(first['kind'], 'fresh')
            self.assertEqual(second['kind'], 'bootstrap-resume')
            self.assertEqual(first['bootstrapId'], second['bootstrapId'])
            self.assertTrue(first['allowNewLineage'])
            self.assertTrue(first['identitiesMustRunFirst'])
            self.assertEqual((self.root / bootstrap.MANIFEST).stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(RuntimeError, 'already held'):
                with bootstrap.bootstrap_lock(self.root):
                    pass
        with bootstrap.bootstrap_lock(self.root):
            self.assertEqual(self.prepare()['bootstrapId'], first['bootstrapId'])

    def test_lock_does_not_depend_on_cache_and_blocks_other_process(self):
        script = ('from pathlib import Path\nimport policy_bootstrap as b\n'
                  f'with b.bootstrap_lock(Path({str(self.root)!r})):\n print("UNSAFE")\n')
        with bootstrap.bootstrap_lock(self.root):
            result = subprocess.run([os.sys.executable, '-c', script], cwd=Path(__file__).parent,
                                    capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('another campaign', result.stderr)
        self.assertNotIn('UNSAFE', result.stdout)

    def test_missing_manifest_with_any_chain_resource_is_orphaned(self):
        for field in ('volumes', 'networks', 'containers'):
            value = inventory()
            value[field] = ['retained-resource']
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'orphaned'):
                bootstrap.classify_bootstrap(self.root, value)
        self.assertFalse(self.root.exists())

    def test_identity_files_without_manifest_are_not_first_setup(self):
        write_identities(self.root)
        with self.assertRaisesRegex(ValueError, 'orphaned'):
            bootstrap.classify_bootstrap(self.root, inventory())

    def test_empty_directories_are_fresh_but_unknown_files_are_not(self):
        (self.root / 'owner').mkdir(parents=True)
        self.assertEqual(bootstrap.classify_bootstrap(self.root, inventory())['kind'], 'fresh')
        (self.root / 'unrecognized.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'orphaned'):
            bootstrap.classify_bootstrap(self.root, inventory())

    def test_existing_deployment_never_creates_bootstrap_manifest(self):
        write_identities(self.root)
        write_deployment(self.root)
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with bootstrap.bootstrap_lock(self.root):
            result = self.prepare()
        self.assertEqual(result['kind'], 'existing')
        self.assertFalse(result['allowNewLineage'])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_existing_pending_deployment_is_preserved_for_policy_init(self):
        write_identities(self.root)
        write_deployment(self.root, 'pending')
        self.assertEqual(bootstrap.classify_bootstrap(self.root, inventory())['kind'], 'existing')

    def test_existing_deployment_with_missing_owner_or_malformed_state_fails(self):
        write_deployment(self.root)
        with self.assertRaisesRegex(ValueError, 'owner identities are missing'):
            bootstrap.classify_bootstrap(self.root, inventory())
        write_identities(self.root)
        (self.root / 'onchain/deployment.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'malformed'):
            bootstrap.classify_bootstrap(self.root, inventory())

    def test_legacy_migration_remains_separate(self):
        write_identities(self.root)
        (self.root / 'gateway').mkdir()
        (self.root / 'gateway/ledger.json').write_text('{}')
        with bootstrap.bootstrap_lock(self.root):
            result = self.prepare()
        self.assertEqual(result['kind'], 'legacy-migration')
        self.assertFalse(result['allowNewLineage'])
        self.assertFalse((self.root / bootstrap.MANIFEST).exists())

    def test_auto_setup_refuses_custom_project_or_network(self):
        for field in ('project', 'network'):
            value = inventory()
            value[field] = 'different'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'default Besu'):
                bootstrap.classify_bootstrap(self.root, value)

    def test_planned_bootstrap_can_resume_partial_keys_only_before_chain(self):
        with bootstrap.bootstrap_lock(self.root):
            self.prepare()
            partial = self.root / 'recipient/signing.hex'
            partial.parent.mkdir()
            partial.write_text('1' * 64)
            self.assertTrue(self.prepare()['identitiesMustRunFirst'])
            self.assertEqual(partial.read_text(), '1' * 64)
            with self.assertRaisesRegex(ValueError, 'before creating chain'):
                bootstrap.prepare_bootstrap(self.root, inventory(True))

    def test_checkpoint_requires_all_valid_distinct_keys(self):
        with bootstrap.bootstrap_lock(self.root):
            self.prepare()
            with self.assertRaisesRegex(ValueError, 'identity is missing'):
                bootstrap.mark_identities_ready(self.root, inventory())
            write_identities(self.root)
            owners = self.root / 'owner/identities.json'
            owners.write_text(json.dumps(['0x' + '1' * 64] * 4))
            with self.assertRaisesRegex(ValueError, 'owner identity'):
                bootstrap.mark_identities_ready(self.root, inventory())
            write_identities(self.root)
            (self.root / 'setup/signing.hex').write_text('f' * 64)
            with self.assertRaisesRegex(ValueError, 'invalid retained signing'):
                bootstrap.mark_identities_ready(self.root, inventory())

    def test_identities_ready_resumes_with_hashes_and_retained_chain(self):
        with bootstrap.bootstrap_lock(self.root):
            ready = self.identities_ready()
            result = bootstrap.prepare_bootstrap(self.root, inventory(True))
            self.assertEqual(result['bootstrapId'], ready['bootstrapId'])
            self.assertEqual(result['phase'], 'identities-ready')
            self.assertTrue(result['allowNewLineage'])
            self.assertFalse(result['identitiesMustRunFirst'])

    def test_identities_ready_never_regenerates_lost_or_changed_keys(self):
        with bootstrap.bootstrap_lock(self.root):
            self.identities_ready()
            (self.root / 'owner/identities.json').unlink()
            with self.assertRaisesRegex(ValueError, 'identity is missing'):
                bootstrap.prepare_bootstrap(self.root, inventory(True))
            write_identities(self.root)
            (self.root / 'setup/signing.hex').write_text('1' * 64)
            with self.assertRaisesRegex(ValueError, 'identities changed'):
                self.prepare()

    def test_deployment_without_policy_started_checkpoint_fails(self):
        with bootstrap.bootstrap_lock(self.root):
            self.identities_ready()
            write_deployment(self.root)
            with self.assertRaisesRegex(ValueError, 'before the bootstrap policy-started'):
                self.prepare()

    def test_policy_started_without_deployment_refuses_reinitialization(self):
        with bootstrap.bootstrap_lock(self.root):
            self.policy_started()
            with self.assertRaisesRegex(ValueError, 'missing after policy initialization'):
                bootstrap.prepare_bootstrap(self.root, inventory(True))

    def test_pending_deployment_resumes_without_new_lineage_permission(self):
        with bootstrap.bootstrap_lock(self.root):
            self.policy_started()
            write_deployment(self.root, 'pending')
            result = bootstrap.prepare_bootstrap(self.root, inventory(True))
            self.assertEqual(result['kind'], 'existing')
            self.assertFalse(result['allowNewLineage'])
            with self.assertRaisesRegex(ValueError, 'pending deployment'):
                bootstrap.mark_deployed(self.root, inventory(True))

    def test_completed_bootstrap_keeps_anchor_and_allows_checkpoint_updates(self):
        with bootstrap.bootstrap_lock(self.root):
            self.policy_started()
            state = write_deployment(self.root)
            completed = bootstrap.mark_deployed(self.root, inventory(True))
            self.assertEqual(completed['phase'], 'deployed')
            state['lastVerifiedBlockNumber'] = 100
            (self.root / 'onchain/deployment.json').write_text(json.dumps(state))
            self.assertEqual(bootstrap.prepare_bootstrap(self.root, inventory(True))['kind'], 'existing')
            state['genesisBlockHash'] = '0x' + '0' * 64
            (self.root / 'onchain/deployment.json').write_text(json.dumps(state))
            with self.assertRaisesRegex(ValueError, 'deployment changed'):
                bootstrap.prepare_bootstrap(self.root, inventory(True))

    def test_deployed_checkpoint_cannot_hide_lost_deployment(self):
        with bootstrap.bootstrap_lock(self.root):
            self.policy_started()
            write_deployment(self.root)
            bootstrap.mark_deployed(self.root, inventory(True))
            (self.root / 'onchain/deployment.json').unlink()
            with self.assertRaisesRegex(ValueError, 'missing after policy initialization'):
                bootstrap.prepare_bootstrap(self.root, inventory(True))

    def test_bootstrap_pins_each_docker_binding_field(self):
        with bootstrap.bootstrap_lock(self.root):
            self.prepare()
            for field in ('context', 'endpoint', 'daemonId'):
                value = inventory()
                value['binding'][field] = 'changed'
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'daemon, context or project changed'):
                    bootstrap.prepare_bootstrap(self.root, value)

    def test_bad_manifest_and_missing_daemon_identity_fail_closed(self):
        self.root.mkdir()
        (self.root / bootstrap.MANIFEST).write_text('{}')
        with self.assertRaisesRegex(ValueError, 'malformed'):
            bootstrap.classify_bootstrap(self.root, inventory())
        value = inventory()
        value['binding']['daemonId'] = None
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            bootstrap.classify_bootstrap(self.root, value)

    def test_symlinks_cannot_redirect_state(self):
        other = self.root.parent / 'elsewhere'
        other.mkdir()
        self.root.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            bootstrap.classify_bootstrap(self.root, inventory())


class DockerInventoryTests(unittest.TestCase):
    def test_only_read_only_commands_are_used_and_unlabelled_resources_are_detected(self):
        answers = ['desktop-linux', json.dumps('unix:///example/docker.sock'),
                   json.dumps({'ID': 'daemon-a'}),
                   json.dumps({'Name': 'vcfhe-besu_net', 'Labels': ''}) + '\n' +
                   json.dumps({'Name': 'unrelated', 'Labels': ''}),
                   json.dumps({'Name': 'vcfhe-besu_default', 'Labels': ''}),
                   json.dumps({'Names': 'vcfhe-besu-node1-1', 'Labels': ''})]
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return types.SimpleNamespace(stdout=answers.pop(0))

        with patch.dict(os.environ, {}, clear=True):
            value = bootstrap.inspect_docker_state(runner=run)
        self.assertEqual(value['volumes'], ['vcfhe-besu_net'])
        self.assertEqual(value['containers'], ['vcfhe-besu-node1-1'])
        self.assertEqual([command[1:3] for command in calls],
                         [['context', 'show'], ['context', 'inspect'], ['info', '--format'],
                          ['volume', 'ls'], ['network', 'ls'], ['ps', '-a']])
        self.assertFalse(any(word in command for command in calls for word in ('up', 'start', 'rm', 'prune')))

    def test_daemon_failure_does_not_fall_back_to_empty_inventory(self):
        def fail(command, **kwargs):
            raise subprocess.CalledProcessError(1, command)

        with self.assertRaisesRegex(ValueError, 'could not be inspected'):
            bootstrap.inspect_docker_state(runner=fail)

    def test_docker_host_override_is_part_of_binding(self):
        answers = ['default', json.dumps('unix:///default.sock'), json.dumps({'ID': 'daemon'}), '', '', '']
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://remote:2376'}, clear=True):
            result = bootstrap.inspect_docker_state(
                runner=lambda *args, **kwargs: types.SimpleNamespace(stdout=answers.pop(0)))
        self.assertEqual(result['binding']['endpoint'], 'tcp://remote:2376')


class RunnerBootstrapIntegrationTests(unittest.TestCase):
    def test_first_identity_compose_needs_no_besu_network(self):
        import run
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / 'module'
            module.mkdir()
            run_dir = Path(directory) / 'new-run'
            run_dir.mkdir()
            root = module / '.policy-state'
            args = run.parser().parse_args(['--auto-policy-setup', '--poc', '--fhe-params',
                                           'Test', '--allow-insecure-test', '--nonlinear-protocol', 'bounty-v2'])
            with patch.object(run, 'MODULE', module), bootstrap.bootstrap_lock(root):
                decision = bootstrap.prepare_bootstrap(root, inventory())
                args.verified_initial_policy_setup = decision['allowNewLineage']
                run.configuration(run_dir, args, 'test-image-without-running-it')
                isolated = json.loads((run_dir / 'config/identities-compose.json').read_text())
                self.assertEqual(set(isolated['services']), {'identities'})
                self.assertNotIn('networks', isolated)
                identity = isolated['services']['identities']
                self.assertEqual(identity['network_mode'], 'none')
                self.assertNotIn('networks', identity)
                self.assertEqual(identity['environment']['VCFHE_ALLOW_NEW_POLICY_LINEAGE'], '1')
                write_identities(root)
                bootstrap.mark_identities_ready(root, inventory())
                bootstrap.mark_policy_starting(root, inventory(True))
                write_deployment(root)
                self.assertEqual(bootstrap.mark_deployed(root, inventory(True))['phase'], 'deployed')

    def test_preflight_reports_fresh_setup_without_writing_state(self):
        import run
        with tempfile.TemporaryDirectory() as directory, patch.object(run, 'MODULE', Path(directory)), \
                patch.object(run, 'inspect_docker_state', return_value=inventory()), \
                patch.object(run.shutil, 'which', return_value='/fake/tool'):
            args = run.parser().parse_args(['--auto-policy-setup', '--poc', '--fhe-params',
                                           'Test', '--allow-insecure-test', '--nonlinear-protocol', 'bounty-v2'])
            report = run.startup_preflight(args)
            self.assertTrue(report['startupPrerequisitesPresent'])
            self.assertEqual(report['initialPolicySetup']['kind'], 'fresh')
            self.assertFalse(report['policyStateChanged'])
            self.assertFalse(report['experimentsExecuted'])
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
