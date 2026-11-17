"""Reconcile retained CPU budgets and reject misleading aggregation inputs."""
import copy
import csv
import json
from pathlib import Path
import statistics as st
import unittest

from verification_budget import load_retained, derive, summary, GROUPS

ROOT = Path(__file__).resolve().parents[2]


class VerificationBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows, cls.inputs = load_retained(ROOT/'results/distributed/cpu-inputs')
        with (ROOT/'results/distributed/workflow/observations.csv').open() as f:
            cls.obs = list(csv.DictReader(f))
        with (ROOT/'results/distributed/diagnostics/paired-observations.csv').open() as f:
            cls.pairs = list(csv.DictReader(f))
        cls.evidence = derive(cls.workflows, cls.obs, cls.pairs)

    def test_context_counted_once_and_certification_preserved(self):
        for row in self.evidence['cases']:
            self.assertAlmostEqual(row['honest_cpu_s'], row['context_honest_s']+row['audit_honest_s'])
            self.assertAlmostEqual(row['baseline_cpu_s'],
                row['context_honest_s']+row['full_checks_s']+row['full_fhe_s'])
            self.assertAlmostEqual(row['faulty_cpu_s'],
                row['context_faulty_s']+row['audit_faulty_s']+row['leaf_checks_s']+row['leaf_fhe_s'])
        expected = [(32.05,70.97,62.55),(34.59,75.71,67.62),(35.25,77.41,69.85),
                    (34.51,75.38,67.48),(39.39,85.97,77.24),(48.37,101.91,94.16)]
        for group, means in zip(GROUPS, expected):
            for key, value in zip(['honest_cpu_s','faulty_cpu_s','baseline_cpu_s'], means):
                self.assertAlmostEqual(summary(self.evidence, group, [key])[0],value,delta=.005)

    def test_casewise_sums_preserve_covariance(self):
        evidence={'cases':[dict(group='g',a=a,b=b) for a,b in [(1,5),(3,3),(5,1)]]}
        self.assertEqual(summary(evidence,'g',['a','b']), (6,0,3))

    def test_deadlines_are_honest_commit_margins(self):
        values=[r['honest_commit_margin_s'] for r in self.evidence['cases']]
        self.assertEqual((len(values),min(values),max(values)),(18,46,94))
        largest=[r['honest_commit_margin_s'] for r in self.evidence['cases'] if r['group']==GROUPS[-1]]
        self.assertEqual(sorted(largest),[46,48,48])

    def test_each_order_retains_fifteen_pairs_and_pooled_means(self):
        self.assertEqual(len(self.evidence['orders']),12)
        for group in GROUPS:
            orders=[r for r in self.evidence['orders'] if r['group']==group]
            rows=[p for p in self.pairs if p['group']==group and p['warmup']=='False']
            self.assertEqual([r['n'] for r in orders],[15,15])
            for key in ['proposed','baseline']:
                self.assertAlmostEqual(st.mean(r[key+'_mean_ms'] for r in orders),
                                       st.mean(float(p[key+'_ms']) for p in rows))


    def test_reused_process_and_overlapping_scope_are_rejected(self):
        for mode in ['worker','native','scope','task','cpu','missing']:
            workflows=copy.deepcopy(self.workflows)
            row=next(r for r in workflows if r['half']=='nonlinear')
            workers=row['metrics']['roleWork']+row['metrics']['adjudicatorWork']
            audit=next(w for w in workers if w['purpose']=='auditor-full-recomputation' and w['phase']=='honest')
            other=next(w for w in workers if w['purpose']=='auditor-full-recomputation' and w['phase']=='challenged')
            if mode=='worker':audit['measurementId']=other['measurementId']
            if mode=='native':audit['publicWorkerResources'][0]['requestId']=other['publicWorkerResources'][0]['requestId']
            if mode=='scope':audit['executionScope']='includes-remote-fhe'
            if mode=='task':audit['taskId']=other['taskId']
            if mode=='cpu':audit['resources']['totalCpuMs']=float('nan')
            if mode=='missing':row['metrics']['roleWork'].remove(audit)
            with self.subTest(mode=mode),self.assertRaises(ValueError):derive(workflows,self.obs,self.pairs)

    def test_changed_published_cpu_missing_case_and_unbalanced_order_fail(self):
        obs=copy.deepcopy(self.obs)
        row=next(r for r in obs if r['metric']=='adjudicator_leaf_complete_cpu_ms')
        row['value']=str(float(row['value'])+1)
        with self.assertRaises(ValueError):derive(self.workflows,obs,self.pairs)
        with self.assertRaises(ValueError):derive(self.workflows[:-1],self.obs,self.pairs)
        pairs=copy.deepcopy(self.pairs)
        row=next(r for r in pairs if r['group'] in GROUPS and r['warmup']=='False')
        row['order']='unexpected'
        with self.assertRaises(ValueError):derive(self.workflows,self.obs,pairs)


if __name__=='__main__':unittest.main()
