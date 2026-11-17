import copy
import unittest
from dispute_readiness_prefix import validate_chain, _keccak256, validate_source_changes, ALLOWED_CHANGES, RELAY_CLIENT


class DisputePrefixTests(unittest.TestCase):
    def test_only_the_calibrated_client_delta_is_allowed(self):
        frozen='return Math.min(requested, 16);'
        validate_source_changes(ALLOWED_CHANGES, frozen, frozen)
        validate_source_changes(ALLOWED_CHANGES | {RELAY_CLIENT}, frozen, 'return Math.min(requested, 48);')
        for changes, text in [(ALLOWED_CHANGES | {'other'}, frozen),
                              (ALLOWED_CHANGES | {RELAY_CLIENT}, 'return 48;')]:
            with self.assertRaises(ValueError):validate_source_changes(changes, frozen, text)

    def material(self):
        receipt = dict(txHash='tx', blockNumber=10, status=1, **{'from': 'relayer'},
                       to='availability', gasUsed='10', effectiveGasPriceWei='2', transactionFeeWei='20',
                       valueWei='0', calldataBytes=10, dataDigest='digest', logs=[],
                       label='publishAuthenticatedTraceBatch')
        state = [3, 2, True, 'operator', 'challenger']
        b = dict(game='game', availability='availability', taskId='task')
        app = dict(onChainPolicy=dict(address='policy'), receipts=[receipt], cases=[dict(metrics=dict(
            leaves=128, disputes=[dict(settlement=dict(state=state, bounty=b))]))])
        snapshot = dict(policy='policy', blockNumber=20, completedDispute=dict(**b,
            state=state.copy(), disclosedLeaves=128, receipts=[{**receipt, 'gasLimit': '20000000'}]))
        return app, snapshot

    def test_exact_chain_confirmation_passes(self):
        validate_chain(*self.material())
        app, snapshot = self.material()
        del app['receipts'][0]['logs']
        validate_chain(app, snapshot)
        snapshot['completedDispute']['receipts'][0]['logs'] = [dict(address='other', topics=[], data='0x')]
        with self.assertRaises(ValueError):validate_chain(app, snapshot)

    def test_wrong_task_status_or_incomplete_disclosure_rejects(self):
        for field, value in [('taskId', 'other'), ('state', [2, 0, True, 'operator', 'challenger']),
                             ('disclosedLeaves', 127)]:
            app, snapshot = self.material();snapshot['completedDispute'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):validate_chain(app, snapshot)

    def test_misattributed_or_failed_receipt_rejects(self):
        for field, value in [('txHash', 'other'), ('status', 0), ('from', 'operator'),
                             ('dataDigest', 'changed'), ('transactionFeeWei', '1'), ('logs', [dict()]),
                             ('gasLimit', '30000000')]:
            app, snapshot = self.material();snapshot['completedDispute']['receipts'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):validate_chain(app, snapshot)

    def test_duplicate_or_missing_receipt_rejects(self):
        for receipts in [[], [self.material()[1]['completedDispute']['receipts'][0]] * 2]:
            app, snapshot = self.material();snapshot['completedDispute']['receipts'] = receipts
            with self.assertRaises(ValueError):validate_chain(app, snapshot)

    def test_omitted_sampling_log_requires_the_exact_public_task_event(self):
        app, snapshot = self.material()
        app['receipts'][0]['label'] = 'sampleParticipants'
        del app['receipts'][0]['logs']
        event = dict(address='game', topics=[_keccak256(b'ParticipantsSampled(bytes32,bytes32,uint64)'), 'task'],
                     data='0x'+'0'*64+format(9, '064x'))
        snapshot['completedDispute']['receipts'][0]['logs'] = [event]
        validate_chain(app, snapshot)
        event['topics'][1] = 'other'
        with self.assertRaises(ValueError):validate_chain(app, snapshot)


if __name__ == '__main__':unittest.main()
