"""Fixture-only validation of scheduling observations, never a campaign run."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import scheduling_evidence as evidence


class SchedulingEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.cfg = dict(half='nonlinear', nonlinearProtocol='bounty-v2', windowSeconds=120,
                        nonlinearSchedulingVersion=evidence.VERSION)
        self.game = '0x'+'11'*20
        self.baseline = '0x'+'22'*20
        self.schedule = dict(version=evidence.VERSION, baselinePlacement='after-audit-opening',
                             finalizationIncludesBaseline=True, elapsedMs=1000,
                             commitTimestamp=100, commitDeadline=120, openTimestamp=121,
                             openDeadline=240, challengeDeadline=360, startTimestamp=121,
                             endTimestamp=150)
        self.case = dict(half='nonlinear', workflowManifest=dict(game=self.game), metrics=dict(
            scheduling=self.schedule, finalizationMs=3000,
            baseline=dict(accepted=True, contract=self.baseline, fullReplayWallMs=500,
                          certificates=[dict(plaintextOpenings=0), dict(plaintextOpenings=0)])))
        self.receipts = [dict(label=label, to=destination) for label, destination in [
            ('honestSubmitSealedAudit', self.game), ('honestRevealSealedAudit', self.game),
            ('acceptFullExecution', self.baseline), ('finalizeUnchallenged', self.game),
            ('honestClaimAuditBond', self.game)]]
        self.app = dict(config=copy.deepcopy(self.cfg), cases=[self.case], receipts=self.receipts)

    def rejects(self, pattern=None):
        if pattern:
            return self.assertRaisesRegex(ValueError, pattern)
        return self.assertRaises(ValueError)

    def test_current_profile_accepts_complete_sequential_evidence(self):
        self.assertEqual(evidence.validate(self.cfg, self.app), evidence.VERSION)

    def test_combined_scope_ignores_linear_cases(self):
        self.cfg['half'] = 'both'
        self.app['config']['half'] = 'both'
        self.app['cases'].insert(0, dict(half='linear', metrics={}))
        self.assertEqual(evidence.validate(self.cfg, self.app), evidence.VERSION)

    def test_historical_profile_keeps_old_observations_without_relabelling(self):
        del self.cfg['nonlinearSchedulingVersion']
        del self.app['config']['nonlinearSchedulingVersion']
        del self.case['metrics']['scheduling']
        self.assertIsNone(evidence.validate(self.cfg, self.app))

    def test_unversioned_or_unsupported_profile_cannot_claim_new_scheduling(self):
        original = copy.deepcopy(self.cfg)
        for update in [dict(nonlinearSchedulingVersion=None), dict(nonlinearSchedulingVersion='future-v2'),
                       dict(half='linear'), dict(nonlinearProtocol='canonical')]:
            with self.subTest(update=update), self.rejects():
                evidence.validate(original | update, self.app)

    def test_configuration_mismatch_and_missing_cases_rejected(self):
        self.app['config']['nonlinearSchedulingVersion'] = 'other'
        with self.rejects('configuration mismatch'):
            evidence.validate(self.cfg, self.app)
        self.app['config'] = copy.deepcopy(self.cfg)
        self.app['cases'] = []
        with self.rejects('missing nonlinear cases'):
            evidence.validate(self.cfg, self.app)

    def test_missing_duplicate_reordered_or_wrong_contract_receipts_rejected(self):
        variants = [self.receipts[:-1], self.receipts+[self.receipts[-1]],
                    [self.receipts[i] for i in [0, 2, 1, 3, 4]],
                    [row | dict(to='0x'+'33'*20) if i == 2 else row for i, row in enumerate(self.receipts)]]
        for receipts in variants:
            with self.subTest(receipts=receipts), self.rejects('workflow receipts'):
                evidence.validate(self.cfg, self.app | dict(receipts=receipts))

    def test_unrelated_receipts_are_not_misclassified(self):
        self.receipts.insert(0, dict(label='registerCanonicalContext', to=self.game))
        self.receipts.append(dict(label='acceptFullExecution', to='0x'+'44'*20))
        self.assertEqual(evidence.validate(self.cfg, self.app), evidence.VERSION)

    def test_game_and_baseline_receipt_destinations_cannot_be_exchanged(self):
        for changed_index in range(len(self.receipts)):
            receipts = copy.deepcopy(self.receipts)
            receipts[changed_index]['to'] = self.game if changed_index == 2 else self.baseline
            with self.subTest(label=receipts[changed_index]['label']), self.rejects():
                evidence.validate(self.cfg, self.app | dict(receipts=receipts))

    def test_late_commit_early_or_late_opening_and_baseline_before_opening_rejected(self):
        original = copy.deepcopy(self.schedule)
        for update in [dict(commitTimestamp=121), dict(openTimestamp=120), dict(openTimestamp=241),
                       dict(startTimestamp=120), dict(endTimestamp=120)]:
            with self.subTest(update=update):
                self.case['metrics']['scheduling'] = original | update
                with self.rejects():
                    evidence.validate(self.cfg, self.app)

    def test_windows_cannot_be_shortened_or_extended(self):
        original = copy.deepcopy(self.schedule)
        for update in [dict(openDeadline=239), dict(challengeDeadline=359), dict(challengeDeadline=480)]:
            with self.subTest(update=update):
                self.case['metrics']['scheduling'] = original | update
                with self.rejects('windows changed'):
                    evidence.validate(self.cfg, self.app)

    def test_callback_overrun_is_valid_without_a_deadline_extension(self):
        self.schedule['endTimestamp'] = 400
        self.schedule['elapsedMs'] = 279000
        self.case['metrics']['finalizationMs'] = 280000
        self.assertEqual(evidence.validate(self.cfg, self.app), evidence.VERSION)
        self.assertEqual(self.schedule['challengeDeadline'], 360)

    def test_incomplete_or_rejected_baseline_cannot_be_recorded_as_preserved(self):
        baseline = copy.deepcopy(self.case['metrics']['baseline'])
        for update in [dict(accepted=False), dict(certificates=[]), dict(certificates=[{}]),
                       dict(certificates=[{}, {}, {}])]:
            with self.subTest(update=update):
                self.case['metrics']['baseline'] = baseline | update
                with self.rejects('baseline missing'):
                    evidence.validate(self.cfg, self.app)

    def test_placement_and_overlap_classification_are_required(self):
        original = copy.deepcopy(self.schedule)
        for update in [dict(version='unknown'), dict(baselinePlacement='before-audit'),
                       dict(finalizationIncludesBaseline=False)]:
            with self.subTest(update=update):
                self.case['metrics']['scheduling'] = original | update
                with self.rejects('placement'):
                    evidence.validate(self.cfg, self.app)

    def test_inconsistent_overlapping_timers_rejected(self):
        for elapsed, baseline, finalization in [(499, 500, 3000), (3001, 500, 3000), (1000, -1, 3000)]:
            with self.subTest(elapsed=elapsed, baseline=baseline, finalization=finalization):
                self.schedule['elapsedMs'] = elapsed
                self.case['metrics']['baseline']['fullReplayWallMs'] = baseline
                self.case['metrics']['finalizationMs'] = finalization
                with self.rejects():
                    evidence.validate(self.cfg, self.app)

    def test_timers_require_finite_nonboolean_numbers(self):
        for container, key in [(self.schedule, 'elapsedMs'),
                               (self.case['metrics'], 'finalizationMs'),
                               (self.case['metrics']['baseline'], 'fullReplayWallMs')]:
            original = container[key]
            for value in [float('nan'), float('inf'), True]:
                with self.subTest(key=key, value=value):
                    container[key] = value
                    with self.rejects():
                        evidence.validate(self.cfg, self.app)
            container[key] = original

    def test_timestamps_require_nonnegative_integers(self):
        for key in ['startTimestamp', 'endTimestamp', 'commitTimestamp', 'openTimestamp',
                    'commitDeadline', 'openDeadline', 'challengeDeadline']:
            original = self.schedule[key]
            for value in [-1, 1.5, True]:
                with self.subTest(key=key, value=value):
                    self.schedule[key] = value
                    with self.rejects():
                        evidence.validate(self.cfg, self.app)
            self.schedule[key] = original

    def test_run_requires_sealed_application_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run/'config').mkdir()
            (run/'reports').mkdir()
            (run/'config/campaign.json').write_text(json.dumps(self.cfg))
            (run/'reports/application.json').write_text(json.dumps(self.app))
            self.assertEqual(evidence.validate_run(run, {'reports/application.json'}), evidence.VERSION)
            with self.rejects('unsealed'):
                evidence.validate_run(run, set())

    def test_historical_run_does_not_require_new_report(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run/'config').mkdir()
            (run/'config/campaign.json').write_text(json.dumps(dict(half='linear')))
            self.assertIsNone(evidence.validate_run(run, set()))


if __name__ == '__main__':
    unittest.main()
