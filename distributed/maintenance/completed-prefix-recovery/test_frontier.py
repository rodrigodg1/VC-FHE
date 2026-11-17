import unittest
from frontier import inspect_frontier
class FrontierTests(unittest.TestCase):
    def run_case(self,names,done,rows,calls):
        events=[{'phase':'full-case','group':'full','state':'done','caseName':n} for n in done]
        return inspect_frontier(names,events,{'cases':[{'name':n} for n in rows],'kmsCalls':calls})
    def test_selects_only_unfinished_suffix_without_authorizing_execution(self):
        v=self.run_case(['a','b','c'],['a'],['a'],1)
        self.assertEqual(v['remainingCases'],['b','c'])
        self.assertFalse(v['analysisComplete'])
        self.assertTrue(v['requiresChainReconciliation'])
    def test_rejects_ambiguous_released_but_unsettled_case(self):
        with self.assertRaises(ValueError):self.run_case(['a','b','c'],['a'],['a','b'],2)
    def test_rejects_duplicate_or_reordered_completion(self):
        for done in [['a','a'],['b'],['b','a']]:
            with self.subTest(done=done),self.assertRaises(ValueError):self.run_case(['a','b','c'],done,done,len(done))
    def test_rejects_mismatched_kms_count(self):
        with self.assertRaises(ValueError):self.run_case(['a','b'],['a'],['a'],2)
    def test_refuses_zero_prefix_and_completed_campaign(self):
        for done in [[],['a','b']]:
            with self.subTest(done=done),self.assertRaises(ValueError):self.run_case(['a','b'],done,done,len(done))
    def test_refuses_duplicate_plan(self):
        with self.assertRaises(ValueError):self.run_case(['a','a'],['a'],['a'],1)
if __name__=='__main__':unittest.main()
