import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import launch


class RolePreparationTests(unittest.TestCase):
    def test_qbft_encoder_uses_the_private_directory_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = launch.Campaign.__new__(launch.Campaign)
            campaign.run = Path(directory)
            campaign.base = '/srv/vcfhe/example'
            campaign.identities = {f'validator-{i}': {'address': '0x' + str(i) * 40}
                                   for i in range(1, 5)}
            campaign.config = {'images': {'besu': 'registry/besu@sha256:' + '1' * 64}}
            remote = Mock()
            # Stop immediately after the actual argument list is constructed.
            remote.text.side_effect = RuntimeError('encoder-boundary')
            campaign.remote = Mock(return_value=remote)
            with self.assertRaisesRegex(RuntimeError, 'encoder-boundary'):
                campaign.validators()
            args = remote.text.call_args.args[0]
            self.assertEqual(args[args.index('--user') + 1], '10001:10001')
            self.assertEqual(args[args.index('--network') + 1], 'none')
            self.assertIn('readonly', args[args.index('--mount') + 1])
            self.assertEqual(json.loads((campaign.run / 'network/validators.json').read_text()),
                             sorted(p['address'] for p in campaign.identities.values()))

    def test_independent_enrollments_keep_separate_roles_and_public_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = launch.Campaign.__new__(launch.Campaign)
            campaign.run = Path(directory)
            campaign.config = {'images': {'campaign': 'registry/campaign@sha256:' + '2' * 64}}
            campaign.nodes = {f'owner-{i}': {'host': f'host-{i}', 'private_ip': f'10.81.{i}.10'}
                              for i in range(1, 5)}
            remotes = {}
            for name in campaign.nodes:
                remote = Mock()
                remote.json.return_value = {'node': name, 'address': name + '-public'}
                remotes[name] = remote
            campaign.remote = lambda name: remotes[name]
            campaign.root = lambda name: '/srv/vcfhe/example/' + name
            campaign.enrollment()
            self.assertEqual(set(campaign.identities), set(campaign.nodes))
            self.assertEqual(json.loads((campaign.run / 'distributed/public-identities.json').read_text()),
                             campaign.identities)
            for name, remote in remotes.items():
                remote.json.assert_called_once()
                folder = campaign.run / 'enrollment' / name
                self.assertEqual(json.loads((folder / 'enrollment.json').read_text())['node'], name)
                remote.upload.assert_called_once_with(folder, campaign.root(name) + '/config')


if __name__ == '__main__':
    unittest.main()
