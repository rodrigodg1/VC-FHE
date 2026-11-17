import copy
import unittest
from readiness_prefix import RESULT_CHECKS, ZERO, validate_material


class PrefixAuditTests(unittest.TestCase):
    def material(self):
        names = ['linear-acr-27-0', 'regulatory_qoe_compliance-0', 'regional_qoe_compliance-0']
        cfg = dict(readinessOnly=True, smoke=True, half='both', parameters='Test',
                   nonlinearProtocol='bounty-v2', linearSizes=[27], records=50, repeats=1, runId='pilot')
        state = dict(status='failed', config=cfg)
        keys = dict(status='passed', parameters='Test', fullPreprocessing=True, preloadedFheKey=False)
        ids = [f'0x{i:064x}' for i in range(1, 28)]
        baselines = {rid: dict(owner='owner', recordReference='ref-' + rid,
                              releaseLimit=18, spent=0) for rid in ids}
        case = dict(name=names[0], half='linear', n=27, workflowKind=1, finalOutputKmsCalls=1,
                    recordIds=ids, outputDigest='output', releaseSlot='linear-slot',
                    releaseRequestId='released-request', validatorConfirmations=[dict(blockNumber=10)])
        app = dict(config=cfg, status='failed', cases=[case], kmsCalls=1, keys=keys,
                   protectedRecordBaselines=baselines, onChainPolicy=dict(address='policy'))
        prepared = dict(cases=[dict(name=name) for name in names], keys=keys)
        result = dict(index=0, name=names[0], actual=88, outputDigest='output', **RESULT_CHECKS)
        snapshot = dict(policy='policy', blockNumber=20, blockHash='block',
                        records={rid: {**row, 'spent': 1} for rid, row in baselines.items()},
                        slots={f'pilot:{name}:final:onchain-v3': dict(slot='linear-slot' if i == 0 else name,
                               requestId='released-request' if i == 0 else ZERO)
                               for i, name in enumerate(names)})
        return [state, app, prepared, result, {names[0]: 88}, keys, snapshot]

    def test_validated_prefix_never_relabels_failed_run(self):
        material = self.material()
        before = copy.deepcopy(material)
        summary = validate_material(*material)
        self.assertEqual(summary['predecessorStatus'], 'failed')
        self.assertFalse(summary['analysisComplete'])
        self.assertEqual(len(summary['remainingCases']), 2)
        self.assertEqual(material, before)

    def test_consumed_pending_slot_is_rejected(self):
        data = self.material()
        data[-1]['slots']['pilot:regulatory_qoe_compliance-0:final:onchain-v3']['requestId'] = 'another-request'
        with self.assertRaisesRegex(ValueError, 'already consumed'):
            validate_material(*data)

    def test_counter_reset_and_extra_charge_are_rejected(self):
        for spent in (0, 2):
            data = self.material()
            next(iter(data[-1]['records'].values()))['spent'] = spent
            with self.assertRaisesRegex(ValueError, 'counter changed'):
                validate_material(*data)

    def test_changed_output_is_rejected(self):
        data = self.material()
        data[3]['actual'] += 1
        with self.assertRaisesRegex(ValueError, 'delivered linear result'):
            validate_material(*data)

    def test_missing_release_checks_are_rejected(self):
        data = self.material()
        data[3]['responses'] = 2
        with self.assertRaisesRegex(ValueError, 'threshold release checks'):
            validate_material(*data)

    def test_changed_policy_or_completed_request_is_rejected(self):
        for change in ('policy', 'request'):
            data = self.material()
            if change == 'policy':
                data[-1]['policy'] = 'different-policy'
            else:
                data[-1]['slots']['pilot:linear-acr-27-0:final:onchain-v3']['requestId'] = 'different-request'
            with self.assertRaisesRegex(ValueError, 'changed'):
                validate_material(*data)


if __name__ == '__main__':
    unittest.main()
