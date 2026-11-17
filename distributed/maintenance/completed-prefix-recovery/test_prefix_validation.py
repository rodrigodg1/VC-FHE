import copy
import unittest
from prefix_validation import validator

SOURCE = '''
def validate_run(path):
    app = EXPECTED_FAILED_APPLICATION
    require(app.get("status") == "passed", "application report did not pass")
    final_records = _normalized_record_map(app.get("protectedRecords"), "protectedRecords")
    return {"status": "passed", "caseCount": len(app['cases'])}
'''

class PrefixValidationTests(unittest.TestCase):
    def setUp(self):
        self.app={'status':'failed','error':'budget duration leaves insufficient allowance for another complete case',
          'cases':[{'name':'a','recordIds':['r']}],'kmsCalls':1}
        self.events=[{'phase':'full-case','group':'full','state':'start','caseName':'a'},
          {'phase':'full-case','group':'full','state':'done','caseName':'a'}]
        view={'records':{'r':{'owner':'o','recordReference':'x','releaseLimit':3,'spent':1}}}
        self.recon={'status':'reconciled','transactionsSubmitted':0,'completed':['a'],'remaining':['b'],
          'views':[copy.deepcopy(view) for _ in range(4)]}
    def check(self):return validator(SOURCE,self.app,self.events,['a','b'],self.recon)
    def test_scope_remains_failed_prefix_not_campaign_success(self):
        module,proof=self.check()
        self.assertEqual(module.EXPECTED_FAILED_APPLICATION['status'],'failed')
        self.assertFalse(proof['analysisComplete'])
        self.assertEqual(module.RECONCILED_FINAL_RECORDS['r']['spent'],1)
    def test_rejects_protocol_failure(self):
        self.app['error']='incorrect plaintext'
        with self.assertRaises(ValueError):self.check()
    def test_rejects_partial_next_case(self):
        self.events.append({'phase':'full-case','state':'start','caseName':'b'})
        with self.assertRaises(ValueError):self.check()
    def test_rejects_counter_disagreement(self):
        self.recon['views'][2]['records']['r']['spent']=0
        with self.assertRaises(ValueError):self.check()
    def test_rejects_missing_quorum_or_mutation(self):
        self.recon['views'].pop()
        with self.assertRaises(ValueError):self.check()
        self.setUp();self.recon['transactionsSubmitted']=1
        with self.assertRaises(ValueError):self.check()
    def test_rejects_different_frontier(self):
        self.recon['remaining']=['c']
        with self.assertRaises(ValueError):self.check()

if __name__=='__main__':unittest.main()
