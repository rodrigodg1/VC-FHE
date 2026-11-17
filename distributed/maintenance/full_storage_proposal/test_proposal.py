"""Historical prototype regression against exact public A11 source fixtures.

The active gate is tested by distributed/tests/test_controller_storage.py.
These tests never render the old patch against the current controller.
"""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
import prepare_patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
FIXTURES = HERE/'fixtures/a11'
sys.path.insert(0, str(SOURCE))


class StorageProposalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='vcfhe-storage-proposal-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        # The patch is historical. Preserve its original inputs after the gate
        # has been incorporated into and extended in the active controller.
        self.fixture_source = self.root/'source'; self.fixture_source.mkdir()
        for name in ('cli.py', 'launch.py'):
            (self.fixture_source/name).write_bytes((FIXTURES/(name+'.fixture')).read_bytes())
        with patch.object(prepare_patch, 'SOURCE', self.fixture_source):
            self.original, self.candidate, self.diff = prepare_patch.render()
        module_file = self.root/'storage_preflight.py'
        module_file.write_text(self.candidate['storage_preflight.py'])
        spec = importlib.util.spec_from_file_location('candidate_storage_preflight', module_file)
        self.storage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.storage)
        self.storage.ROOT = SOURCE.parent
        self.run = self.root/'future-run'
        self.tmp = self.root/'tar'; self.tmp.mkdir()

    def check(self, frees, devices=(1, 1), config=None):
        usage = [SimpleNamespace(free=n) for n in frees]
        stats = [SimpleNamespace(st_dev=n) for n in devices]
        with patch.object(self.storage.shutil, 'disk_usage', side_effect=usage), \
             patch.object(self.storage, 'filesystem_stat', side_effect=stats):
            return self.storage.check_full_controller_storage(
                config or {}, self.run, self.tmp)

    def test_same_volume_exactly50_is_checked_once_not100(self):
        value = self.storage.FULL_MINIMUM_FREE_BYTES
        result = self.check([value, value])
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(result['uniqueFilesystems']), 1)
        self.assertEqual(result['uniqueFilesystems'][0]['requiredFreeBytes'], value)
        self.assertEqual(result['uniqueFilesystems'][0]['purposes'],
                         ['run-evidence', 'temporary-tar'])
        self.assertFalse(result['totalStorageUpperBoundEstablished'])
        self.assertFalse(self.run.exists())

    def test_different_filesystems_each_need50(self):
        value = self.storage.FULL_MINIMUM_FREE_BYTES
        self.assertEqual(len(self.check([value, value], (1, 2))['uniqueFilesystems']), 2)
        for free in [(value-1, value), (value, value-1), (1, 100*2**30)]:
            with self.subTest(free=free), self.assertRaisesRegex(ValueError, '50 GiB'):
                self.check(free, (1, 2))

    def test_same_filesystem_does_not_hide_lower_later_free_space(self):
        value = self.storage.FULL_MINIMUM_FREE_BYTES
        with self.assertRaisesRegex(ValueError, 'planning headroom'):
            self.check([value, value-1])

    def test_smoke_does_not_inspect_or_change_capacity_policy(self):
        with patch.object(self.storage.shutil, 'disk_usage') as usage, \
             patch.object(self.storage, 'filesystem_stat') as stat:
            result = self.storage.check_full_controller_storage({'execution_mode': 'smoke'})
            usage.assert_not_called(); stat.assert_not_called()
        self.assertEqual(result['status'], 'not-applicable-smoke')
        self.assertFalse(result['policyChanged'])

    def test_nonexistent_target_uses_existing_ancestor_without_creating(self):
        self.assertEqual(self.storage.existing_directory(self.run/'nested'), self.root)
        file = self.root/'regular-file'; file.write_text('synthetic')
        with self.assertRaisesRegex(ValueError, 'directory'):
            self.storage.existing_directory(file/'nested')
        self.assertFalse(self.run.exists())

    def test_default_temporary_filesystem_is_actual_tempfile_selection(self):
        value = self.storage.FULL_MINIMUM_FREE_BYTES
        with patch.object(self.storage.tempfile, 'gettempdir', return_value=str(self.tmp)) as selected, \
             patch.object(self.storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=value)), \
             patch.object(self.storage, 'filesystem_stat', return_value=SimpleNamespace(st_dev=1)):
            result = self.storage.check_full_controller_storage({})
        selected.assert_called_once()
        self.assertEqual(result['filesystemChecks'][1]['requestedPath'], str(self.tmp))

    def cli_candidate(self):
        file = self.root/'cli.py'; file.write_text(self.candidate['cli.py'])
        spec = importlib.util.spec_from_file_location('candidate_storage_cli', file)
        cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        config = json.loads((SOURCE/'config.example.json').read_text())
        config['project_id'] = 'synthetic-storage-test'
        path = self.root/'config.local.json'; path.write_text(json.dumps(config))
        return cli, path, config

    def test_cloud_run_full_blocks_before_tools_setup_or_paid_builder(self):
        cli, path, _ = self.cli_candidate()
        tools = SimpleNamespace(ensure=Mock(side_effect=AssertionError('must not run')))
        argv = ['cli.py', 'cloud-run', '--config', str(path), '--quote', str(self.root/'quote.local.json'),
                '--build', str(self.root/'build'), '--run', str(self.run)]
        with patch.object(sys, 'argv', argv), \
             patch.dict(sys.modules, {'storage_preflight': self.storage, 'cloud_tools': tools}), \
             patch.object(self.storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=3*2**30)):
            with self.assertRaisesRegex(ValueError, '50 GiB'):
                cli.main()
        tools.ensure.assert_not_called()
        self.assertFalse(self.run.exists())

    def test_cloud_build_alone_and_smoke_bypass_new_full_gate(self):
        cli, path, config = self.cli_candidate()
        for command, smoke in [('cloud-build', False), ('cloud-run', True)]:
            with self.subTest(command=command, smoke=smoke):
                if smoke:
                    config['campaign'] = 'synthetic-smoke'; config['execution_mode'] = 'smoke'
                path.write_text(json.dumps(config))
                tools = SimpleNamespace(ensure=Mock(side_effect=RuntimeError('stop before any cloud work')))
                argv = ['cli.py', command, '--config', str(path), '--quote', str(self.root/'quote.local.json'),
                        '--build', str(self.root/'build'), '--run', str(self.run)]
                with patch.object(sys, 'argv', argv), \
                     patch.dict(sys.modules, {'storage_preflight': self.storage, 'cloud_tools': tools}), \
                     patch.object(self.storage.shutil, 'disk_usage') as usage:
                    with self.assertRaisesRegex(RuntimeError, 'stop before any cloud work'):
                        cli.main()
                tools.ensure.assert_called_once(); usage.assert_not_called()

    def test_readiness_and_direct_launch_recheck_before_build_evidence(self):
        node = next(n for n in ast.parse(self.candidate['launch.py']).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'check_launch')
        scope = {'topology': SimpleNamespace(validate=lambda cfg: cfg)}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<candidate check_launch>', 'exec'), scope)
        with patch.dict(sys.modules, {'storage_preflight': self.storage}), \
             patch.object(self.storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=3*2**30)):
            with self.assertRaisesRegex(ValueError, '50 GiB'):
                scope['check_launch']({}, {}, '/missing-image-evidence')
        self.assertIn('try:check_launch(config,json.loads(args.quote.read_text()),args.build)',
                      self.candidate['cli.py'])
        self.assertIn('self.record,self.costs=check_launch(config,quote,build)',
                      self.candidate['launch.py'])

    def test_patch_is_source_bound_and_only_applied_to_temporary_copy(self):
        record = json.loads((HERE/'proposal.json').read_text())
        self.assertEqual(record['source'], prepare_patch.hashes(self.original))
        self.assertEqual(record['candidate'], prepare_patch.hashes(self.candidate))
        self.assertEqual((HERE/'proposal.patch').read_text(), self.diff)
        target = self.root/'VC-FHE/distributed'; target.mkdir(parents=True)
        for name, value in self.original.items(): (target/name).write_text(value)
        subprocess.run(['patch', '--batch', '-p1', '-d', str(self.root), '-i', str(HERE/'proposal.patch')],
                       check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual({name:(target/name).read_text() for name in self.candidate}, self.candidate)
        with patch.object(prepare_patch, 'SOURCE', self.fixture_source):
            self.assertEqual(prepare_patch.hashes(prepare_patch.render()[0]), record['source'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
