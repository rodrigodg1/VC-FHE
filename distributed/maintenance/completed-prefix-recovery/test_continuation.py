import unittest
from pathlib import Path
from copy import deepcopy
from window import renewal,check,overlay
from selection import select,configuration,verify_config,verify_exchange

class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.old={'startedAt':'2026-10-28T00:00:00+00:00','caseAllowanceHours':2,'plannedHours':24,'hourlyUsd':1}
        self.new=renewal(self.old,'2026-10-30T00:00:00+00:00')
    def test_cost_clock_preserved(self):
        self.assertEqual(check(self.new,'2026-10-30T20:00:00+00:00'),{'windowElapsedHours':20,'totalElapsedHours':68})
        self.assertEqual({k:v for k,v in self.new.items() if k!='continuationWindow'},self.old)
    def test_finite_boundary(self):
        with self.assertRaises(ValueError):check(self.new,'2026-10-30T20:00:01+00:00')
        with self.assertRaises(ValueError):check(self.new,'2026-10-29T23:59:59+00:00')
    def test_modified_window_refused(self):
        for key,value in [('hours',100),('costAccountingReset',True),('maximumVmRuntimeSeconds',999999)]:
            n=deepcopy(self.new);n['continuationWindow'][key]=value
            with self.assertRaises(ValueError):check(n,'2026-10-30T01:00:00+00:00')
    def test_overlay_only_duration(self):
        source=(Path(__file__).parents[2]/'admission.mjs').read_text()
        result=overlay(source)
        self.assertIn('const projected=elapsed*envelope.hourlyUsd+envelope.fixedUpperUsd;',result)
        self.assertIn("disk.bavail*disk.bsize>=envelope.minimumFreeBytes",result)
        self.assertIn('envelope.maximumUsd',result)
        with self.assertRaises(ValueError):overlay(result)
    def test_selection(self):
        p={'keys':{'a':1},'cases':[{'name':str(i),'half':'linear' if i<9 else 'nonlinear'} for i in range(27)]}
        done=[str(i) for i in range(10)];todo=[str(i) for i in range(10,27)]
        selected=select(p,done,todo)
        self.assertEqual([c['name'] for c in selected['cases']],todo)
        self.assertEqual(len(p['cases']),27)
        with self.assertRaises(ValueError):select(p,done[::-1],todo)
    def test_protocol_configuration_immutable(self):
        p={'runId':'old','windowSeconds':120,'chainId':'46853'}
        n=configuration(p,'new-workflows-c4',['a'],['b'])
        verify_config(p,n,['a'],['b'])
        n['windowSeconds']=1
        with self.assertRaises(ValueError):verify_config(p,n,['a'],['b'])
    def test_exchange_unknown_or_next_request_refused(self):
        verify_exchange(['request-0.json','wire-9.json'],10)
        for n in ['request-10.json','request-01.json','complete.json','unknown-0.json']:
            with self.assertRaises(ValueError):verify_exchange([n],10)

if __name__=='__main__':unittest.main()
