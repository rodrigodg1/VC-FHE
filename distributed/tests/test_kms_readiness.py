import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import launch


class KmsReadinessTests(unittest.TestCase):
    def campaign(self, directory, probe):
        campaign = launch.Campaign.__new__(launch.Campaign)
        campaign.run = Path(directory)
        campaign.nodes = {f'kms-{i}': {'private_ip': f'10.{i}.0.10'} for i in range(1, 5)}
        campaign.nodes['coordinator-1'] = {'private_ip': '10.1.0.10'}
        remote = Mock()
        remote.text.return_value = 'PUBLIC CERTIFICATE'
        remote.run.side_effect = probe

        def download(root, names, destination):
            keyset = Path(destination) / 'keyset'
            keyset.mkdir(parents=True)
            (keyset / 'ready.json').write_text(json.dumps({
                'status': 'passed', 'fullPreprocessing': True, 'preloadedFheKey': False}))

        remote.download.side_effect = download
        campaign.remote = Mock(return_value=remote)
        campaign.root = lambda node: '/test/' + node
        campaign.compose_run = Mock()
        return campaign, remote

    def test_delayed_endpoints_are_probed_before_exactly_one_prss_and_dkg(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, remote = self.campaign(directory, [
                subprocess.CalledProcessError(1, ['readiness-probe']), None])
            with patch.object(launch.time, 'sleep') as sleep:
                campaign.kms()
            self.assertEqual(remote.run.call_count, 2)
            sleep.assert_called_once_with(2)
            args = remote.run.call_args.args[0]
            self.assertEqual(json.loads(args[-1]), [f'10.{i}.0.10' for i in range(1, 5)])
            self.assertIn('(50001,50100)', args[2])
            protocol = [call.args for call in campaign.compose_run.call_args_list
                        if call.args[-1] in ('init', 'setup')]
            self.assertEqual(protocol, [('coordinator-1', 'run', '--rm', 'init'),
                                        ('coordinator-1', 'run', '--rm', 'setup')])

    def test_probe_timeout_cannot_start_prss_or_dkg(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, remote = self.campaign(directory,
                subprocess.TimeoutExpired(['readiness-probe'], 30))
            elapsed = [0]
            with patch.object(launch.time, 'monotonic', side_effect=lambda: elapsed[0]), \
                 patch.object(launch.time, 'sleep', side_effect=lambda seconds: elapsed.__setitem__(0, elapsed[0] + seconds)):
                with self.assertRaisesRegex(ValueError, 'before PRSS'):
                    campaign.kms()
            self.assertGreater(remote.run.call_count, 1)
            self.assertFalse(any(call.args[-1] in ('init', 'setup')
                                 for call in campaign.compose_run.call_args_list))
            remote.download.assert_not_called()

    def test_failed_prss_is_never_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, remote = self.campaign(directory, None)

            def compose(*args):
                if args[-1] == 'init':
                    raise subprocess.CalledProcessError(1, ['kms-init'])

            campaign.compose_run.side_effect = compose
            with self.assertRaises(subprocess.CalledProcessError):
                campaign.kms()
            self.assertEqual(remote.run.call_count, 1)
            self.assertEqual(sum(call.args[-1] == 'init'
                                 for call in campaign.compose_run.call_args_list), 1)
            self.assertFalse(any(call.args[-1] == 'setup'
                                 for call in campaign.compose_run.call_args_list))
            remote.download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
