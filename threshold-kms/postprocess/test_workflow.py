import copy
import unittest
from workflow import receipt_index, select_receipts, describe, totals


class WorkflowChecks(unittest.TestCase):
    def setUp(self):
        self.receipts = [{'hash': 'a', 'label': 'owner-key', 'gasUsed': '12', 'calldataBytes': 4},
                         {'txHash': 'b', 'label': 'bound-result', 'gasUsed': '20', 'calldataBytes': 8}]
        self.scopes = {'ownerAdmission': {'transactionCount': 1, 'gasUsed': '12', 'calldataBytes': 4, 'transactions': ['a']},
                       'proposed': {'transactionCount': 1, 'gasUsed': '20', 'calldataBytes': 8, 'transactions': ['b']}}
        self.reported = {'transactionCount': 2, 'gasUsed': '32', 'calldataBytes': 12}

    def select(self, used=None):
        return select_receipts(self.scopes, self.reported, receipt_index(self.receipts), set() if used is None else used)

    def test_partition_reconciles(self):
        self.assertEqual(totals(self.select()), {'transactionCount': 2, 'gasUsed': 32, 'calldataBytes': 12})

    def test_unknown_label_rejected(self):
        self.receipts[0]['label'] = 'unknown'
        with self.assertRaises(ValueError): self.select()

    def test_wrong_scope_rejected(self):
        self.receipts[0]['label'] = 'acceptFullExecution'
        with self.assertRaises(ValueError): self.select()

    def test_duplicate_receipt_rejected(self):
        self.receipts.append(copy.deepcopy(self.receipts[0]))
        with self.assertRaises(ValueError): self.select()

    def test_cross_case_reuse_rejected(self):
        with self.assertRaises(ValueError): self.select({'a'})

    def test_missing_receipt_rejected(self):
        self.scopes['proposed']['transactions'] = ['absent']
        with self.assertRaises(ValueError): self.select()

    def test_total_tampering_rejected(self):
        self.reported['gasUsed'] = '31'
        with self.assertRaises(ValueError): self.select()

    def test_scoped_calldata_tampering_rejected(self):
        self.scopes['ownerAdmission']['calldataBytes'] = 3
        with self.assertRaises(ValueError): self.select()

    def test_sample_sd(self):
        self.assertEqual(describe([1, 2, 3])['sampleSd'], 1)
        self.assertIsNone(describe([1])['sampleSd'])
        with self.assertRaises(ValueError): describe([float('nan')])


if __name__ == '__main__':
    unittest.main()
