import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import launch


class SmokeLifecycleTests(unittest.TestCase):
    def campaign(self, directory, mode='smoke'):
        campaign = launch.Campaign.__new__(launch.Campaign)
        campaign.run = Path(directory) / 'run'
        campaign.config = {'execution_mode': mode}
        campaign.state = {'status': 'prepared', 'stages': []}
        campaign.provisioned = False
        campaign.remotes = {}
        campaign.base = '/unused'
        events = []

        def initialize():
            campaign.run.mkdir()
            events.append('initialize')

        def provision():
            campaign.provisioned = True
            events.append('provision')

        def collect():
            events.append('collect')
            (campaign.run / 'distributed').mkdir()
            (campaign.run / 'distributed/smoke-result.json').write_text(json.dumps({'status': 'passed'}))

        campaign.initialize = Mock(side_effect=initialize)
        campaign.provision = Mock(side_effect=provision)
        campaign.collect = Mock(side_effect=collect)
        for name in ['bootstrap', 'sampling', 'enrollment', 'validators', 'policy', 'kms', 'roles', 'wait', 'stop']:
            setattr(campaign, name, Mock(side_effect=lambda name=name: events.append(name)))
        return campaign, events

    def modules(self, events, *, backup_error=None):
        def backup(*args, **kwargs):
            events.append('backup')
            if backup_error is not None:
                raise backup_error

        cleanup = SimpleNamespace(backup=Mock(side_effect=backup),
                                  apply=Mock(side_effect=lambda *args, **kwargs: events.append('apply')))
        publication = SimpleNamespace(derive=Mock(return_value={'status': 'results-ready'}))
        return cleanup, publication

    def test_successful_smoke_backs_up_before_stop_and_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, events = self.campaign(directory)
            cleanup, publication = self.modules(events)
            with patch.dict(sys.modules, {'smoke_cleanup': cleanup, 'analysis': publication}):
                self.assertEqual(campaign.run_all(), {'status': 'passed'})
            self.assertEqual(events[-3:], ['backup', 'stop', 'apply'])
            cleanup.backup.assert_called_once()
            cleanup.apply.assert_called_once()
            self.assertEqual(cleanup.backup.call_args.args[2], campaign.run / 'private-smoke-backup')
            self.assertEqual(cleanup.apply.call_args.args[2], campaign.run / 'private-smoke-backup')
            publication.derive.assert_not_called()

    def test_backup_failure_still_stops_compute_and_refuses_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, events = self.campaign(directory)
            cleanup, publication = self.modules(events, backup_error=OSError('backup unavailable'))
            with patch.dict(sys.modules, {'smoke_cleanup': cleanup, 'analysis': publication}):
                with self.assertRaisesRegex(ValueError, 'Smoke cleanup failed'):
                    campaign.run_all()
            self.assertEqual(events[-2:], ['backup', 'stop'])
            cleanup.apply.assert_not_called()
            publication.derive.assert_not_called()
            report = json.loads((campaign.run / 'smoke-cleanup-failure.local.json').read_text())
            self.assertEqual(report['stage'], 'private backup')
            self.assertFalse(report['resourcesDeleted'])
            self.assertEqual(campaign.state['status'], 'smoke-complete-cleanup-failed')

    def test_evaluation_keeps_normal_stop_and_never_invokes_smoke_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, events = self.campaign(directory, mode='evaluation')
            cleanup, publication = self.modules(events)
            with patch.dict(sys.modules, {'smoke_cleanup': cleanup, 'analysis': publication}):
                self.assertEqual(campaign.run_all(), {'status': 'results-ready'})
            cleanup.backup.assert_not_called()
            cleanup.apply.assert_not_called()
            publication.derive.assert_called_once_with(campaign.run)
            self.assertEqual(events[-1], 'stop')
            self.assertEqual(campaign.state['resultsStatus'], 'results-ready')

    def test_failed_smoke_preserves_original_error_and_allows_scoped_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, events = self.campaign(directory)
            campaign.wait.side_effect = RuntimeError('workflow failed')
            cleanup, publication = self.modules(events)
            with patch.dict(sys.modules, {'smoke_cleanup': cleanup, 'analysis': publication}):
                with self.assertRaisesRegex(RuntimeError, 'workflow failed'):
                    campaign.run_all()
            self.assertEqual(events[-3:], ['backup', 'stop', 'apply'])
            self.assertIs(cleanup.backup.call_args.kwargs['allow_failed'], True)
            self.assertIs(cleanup.apply.call_args.kwargs['allow_failed'], True)
            campaign.collect.assert_not_called()
            publication.derive.assert_not_called()
            self.assertEqual(campaign.state['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
