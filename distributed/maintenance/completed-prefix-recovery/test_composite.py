import unittest,copy
from composite import combine
class CompositeTests(unittest.TestCase):
 def setUp(self):
  self.names=[str(i) for i in range(27)]
  rows=[{'name':n,**{k:k+n for k in ['releaseSlot','releaseRequestId','requestKey','reservationTransaction','consentId']},'recordIds':['r']} for n in self.names]
  baseline={'owner':'o','recordReference':'v','releaseLimit':30,'spent':0}
  self.a={'cases':rows[:10],'kmsCalls':10,'keys':{'key':'same'},'onChainPolicy':{'policy':'same'},'config':{'runId':'c3'},'protectedRecordBaselines':{'r':baseline}}
  self.b={'cases':rows[10:],'kmsCalls':17,'keys':{'key':'same'},'onChainPolicy':{'policy':'same'},'config':{'runId':'c4'},'protectedRecordBaselines':{'r':{**baseline,'spent':10}}}
  self.va={'status':'completed-prefix-validated','caseCount':10};self.vb={'status':'passed','caseCount':17}
 def verify(self):return combine(self.a,self.b,self.names,prefix_verdict=self.va,continuation_verdict=self.vb)
 def test_complete_grid_requires_separate_validation(self):
  v=self.verify();self.assertEqual(v['kmsCalls'],27);self.assertFalse(v['analysisComplete'])
 def test_counters_cannot_reset(self):
  self.b['protectedRecordBaselines']['r']['spent']=0
  with self.assertRaises(ValueError):self.verify()
 def test_duplicate_release_refused(self):
  self.b['cases'][0]['releaseRequestId']=self.a['cases'][0]['releaseRequestId']
  with self.assertRaises(ValueError):self.verify()
 def test_missing_reordered_case_refused(self):
  self.b['cases'].reverse()
  with self.assertRaises(ValueError):self.verify()
 def test_keyset_and_lineage_immutable(self):
  for k in ['keys','onChainPolicy']:
   old=self.b[k];self.b[k]={}
   with self.assertRaises(ValueError):self.verify()
   self.b[k]=old
 def test_no_placeholder_validation(self):
  self.va['status']='passed'
  with self.assertRaises(ValueError):self.verify()
if __name__=='__main__':unittest.main()
