"""Exercise the active storage prerequisite without cloud calls or large files."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import cli
import cloud_tools
import controller_inputs
import cloud_setup
import gce_image
import launch
import storage_preflight as storage


class ControllerStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vcfhe-storage-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.run = self.root/'future-run'
        self.tar = self.root/'temporary-tar'
        self.tar.mkdir()
        self.config = json.loads((HERE/'config.example.json').read_text())
        self.config['project_id'] = 'synthetic-storage-test'
        self.config_path = self.root/'config.local.json'
        self.quote_path = self.root/'quote.local.json'
        self.quote = {
            'currency': 'USD', 'campaign': self.config['campaign'],
            'layout': 'four-hosts', 'quoted_at': datetime.now(timezone.utc).isoformat(),
            'hourly': {'compute': '.8', 'nat': '.01', 'disks': '.1', 'ipv4': '.02'},
            'planned_hours': '12', 'case_allowance_hours': 2,
            'build_registry': '2', 'retained_resources': '0',
            'transfer_storage_upper_bound': '3',
            'source_urls': ['https://example.org/synthetic-storage-test-only'],
        }

    def check(self, frees, devices=(1, 1)):
        with patch.object(storage.shutil, 'disk_usage',
                          side_effect=[SimpleNamespace(free=n) for n in frees]), \
             patch.object(storage, 'filesystem_stat',
                          side_effect=[SimpleNamespace(st_dev=n) for n in devices]):
            return storage.check_full_controller_storage(self.config, self.run, self.tar)

    def argv(self, command, *, smoke=False):
        config = dict(self.config)
        if smoke:
            config.update(campaign='storage-test-smoke', execution_mode='smoke')
        self.config_path.write_text(json.dumps(config))
        self.quote_path.write_text(json.dumps(dict(self.quote, campaign=config['campaign'])))
        return ['distributed', command, '--config', str(self.config_path),
                '--quote', str(self.quote_path), '--build', str(self.root/'future-build'),
                '--run', str(self.run)]

    def test_shared_filesystem_needs50_not100_gib(self):
        minimum = storage.FULL_MINIMUM_FREE_BYTES
        self.assertEqual(minimum, 50*2**30)
        result = self.check([minimum, minimum])
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(result['uniqueFilesystems']), 1)
        volume = result['uniqueFilesystems'][0]
        self.assertEqual(volume['purposes'], ['run-evidence', 'temporary-tar'])
        self.assertEqual(volume['freeBytes'], minimum)
        self.assertEqual(volume['requiredFreeBytes'], minimum)
        self.assertFalse(result['totalStorageUpperBoundEstablished'])
        self.assertFalse(self.run.exists())

    def test_separate_filesystems_each_require50_gib(self):
        minimum = storage.FULL_MINIMUM_FREE_BYTES
        self.assertEqual(len(self.check([minimum, minimum], (1, 2))['uniqueFilesystems']), 2)
        for available in [(minimum-1, minimum), (minimum, minimum-1), (1, minimum*2)]:
            with self.subTest(available=available), self.assertRaisesRegex(ValueError, '50 GiB'):
                self.check(available, (1, 2))

    def test_shared_volume_uses_lower_of_consecutive_observations(self):
        minimum = storage.FULL_MINIMUM_FREE_BYTES
        with self.assertRaisesRegex(ValueError, 'planning headroom'):
            self.check([minimum, minimum-1])

    def test_smoke_does_not_inspect_or_modify_capacity_policy(self):
        with patch.object(storage.shutil, 'disk_usage') as usage, \
             patch.object(storage, 'filesystem_stat') as stat, \
             patch.object(storage.tempfile, 'gettempdir') as temp:
            result = storage.check_full_controller_storage({'execution_mode': 'smoke'})
        usage.assert_not_called()
        stat.assert_not_called()
        temp.assert_not_called()
        self.assertEqual(result['status'], 'not-applicable-smoke')
        self.assertFalse(result['policyChanged'])

    def test_future_destination_uses_existing_directory_without_creating(self):
        self.assertEqual(storage.existing_directory(self.run/'nested'), self.root)
        regular = self.root/'regular-file'
        regular.write_text('public synthetic fixture')
        with self.assertRaisesRegex(ValueError, 'directory'):
            storage.existing_directory(regular/'nested')
        self.assertFalse(self.run.exists())

    def test_selected_temporary_volume_is_checked(self):
        minimum = storage.FULL_MINIMUM_FREE_BYTES
        with patch.object(storage.tempfile, 'gettempdir', return_value=str(self.tar)) as temp, \
             patch.object(storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=minimum)), \
             patch.object(storage, 'filesystem_stat', return_value=SimpleNamespace(st_dev=1)):
            result = storage.check_full_controller_storage(self.config, self.run)
        temp.assert_called_once()
        self.assertEqual(result['filesystemChecks'][1]['requestedPath'], str(self.tar))

    def test_cloud_run_refuses_before_tools_setup_inputs_and_paid_builder(self):
        argv = self.argv('cloud-run')
        with patch.object(sys, 'argv', argv), \
             patch.object(storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=3*2**30)), \
             patch.object(storage, 'filesystem_stat', return_value=SimpleNamespace(st_dev=1)), \
             patch.object(cloud_tools, 'ensure') as tools, \
             patch.object(controller_inputs, 'prepare') as inputs, \
             patch.object(cloud_setup, 'inspect') as setup, \
             patch.object(gce_image, 'build') as builder:
            with self.assertRaisesRegex(ValueError, '50 GiB'):
                cli.main()
        for operation in [tools, inputs, setup, builder]:
            operation.assert_not_called()
        self.assertFalse(self.run.exists())
        self.assertFalse((self.root/'future-build').exists())

    def test_cloud_run_capacity_pass_reaches_tools_before_any_cloud_work(self):
        argv = self.argv('cloud-run')
        with patch.object(sys, 'argv', argv), \
             patch.object(storage.shutil, 'disk_usage',
                          return_value=SimpleNamespace(free=storage.FULL_MINIMUM_FREE_BYTES)) as usage, \
             patch.object(storage, 'filesystem_stat', return_value=SimpleNamespace(st_dev=1)), \
             patch.object(cloud_tools, 'ensure', side_effect=RuntimeError('test stop before cloud')) as tools, \
             patch.object(cloud_setup, 'inspect') as setup, \
             patch.object(gce_image, 'build') as builder:
            with self.assertRaisesRegex(RuntimeError, 'test stop before cloud'):
                cli.main()
        self.assertEqual(usage.call_count, 2)
        tools.assert_called_once()
        setup.assert_not_called()
        builder.assert_not_called()

    def test_cloud_build_alone_and_smoke_keep_full_storage_exemption(self):
        for command, smoke in [('cloud-build', False), ('cloud-run', True)]:
            with self.subTest(command=command, smoke=smoke):
                argv = self.argv(command, smoke=smoke)
                with patch.object(sys, 'argv', argv), \
                     patch.object(storage.shutil, 'disk_usage') as usage, \
                     patch.object(cloud_tools, 'ensure',
                                  side_effect=RuntimeError('test stop before cloud')) as tools, \
                     patch.object(cloud_setup, 'inspect') as setup, \
                     patch.object(gce_image, 'build') as builder:
                    with self.assertRaisesRegex(RuntimeError, 'test stop before cloud'):
                        cli.main()
                tools.assert_called_once()
                usage.assert_not_called()
                setup.assert_not_called()
                builder.assert_not_called()

    def test_real_check_launch_refuses_before_build_evidence_or_budget(self):
        with patch.object(storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=3*2**30)), \
             patch.object(storage, 'filesystem_stat', return_value=SimpleNamespace(st_dev=1)), \
             patch.object(launch.deployment, 'campaign_module') as evidence, \
             patch.object(launch.budget, 'assess') as assess:
            with self.assertRaisesRegex(ValueError, '50 GiB'):
                launch.check_launch(self.config, self.quote, self.root/'missing-build')
        evidence.assert_not_called()
        assess.assert_not_called()

    def test_actual_readiness_cli_reports_storage_refusal_and_valid_quote(self):
        argv = self.argv('readiness')
        output = io.StringIO()
        with patch.object(sys, 'argv', argv), \
             patch.object(storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=3*2**30)), \
             patch.object(storage, 'filesystem_stat', return_value=SimpleNamespace(st_dev=1)), \
             patch.object(cloud_tools, 'ensure') as tools, \
             patch.object(launch.deployment, 'campaign_module') as evidence, \
             redirect_stdout(output):
            status = cli.main()
        result = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertFalse(result['ready_to_launch'])
        self.assertEqual(result['budget']['status'], 'admit')
        self.assertEqual(result['cloud_actions_executed'], [])
        self.assertTrue(any('50 GiB' in item for item in result['failures']))
        tools.assert_not_called()
        evidence.assert_not_called()

    def test_campaign_constructor_cannot_create_a_run_before_storage_pass(self):
        with patch.object(storage.shutil, 'disk_usage', return_value=SimpleNamespace(free=3*2**30)), \
             patch.object(storage, 'filesystem_stat', return_value=SimpleNamespace(st_dev=1)):
            with self.assertRaisesRegex(ValueError, '50 GiB'):
                launch.Campaign(self.config, self.quote, self.root/'missing-build', self.run)
        self.assertFalse(self.run.exists())


if __name__ == '__main__':
    unittest.main()
