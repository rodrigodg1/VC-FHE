"""Completion authority changes only explicit financial admission."""
from pathlib import Path
import sys,copy,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_cloud_results import config,synthetic_quote
from cloud_results.completion_budget import authorization,assess,original_admission,SCHEMA
import budget

class CompletionBudgetTests(unittest.TestCase):
    def fixture(self):
        c=config();c['budget']['maximum']=100;c['maximum_vm_runtime_seconds']=86400
        c['completion_authorization']={'schema':SCHEMA,'explicitUserRequest':True,'finishDespiteFormerBudget':True,
            'referenceBudgetUsd':'100','estimatedAdmissionEnvelopeUsd':'125','maximumVmRuntimeSeconds':86400,
            'stopOnBillingThreshold':False,'requestedAt':'2026-10-29T00:00:00+10:00'}
        q=synthetic_quote(c,cost='1');q['planned_hours']='24';q['prior_experiment_upper_bound_usd']='80'
        return c,q
    def test_no_authorization_preserves_original_admission(self):
        c,q=self.fixture();del c['completion_authorization']
        self.assertEqual(assess(c,q),budget.assess(c,q))
    def test_authorized_forecast_retains_every_prior_cost_and_reserve(self):
        c,q=self.fixture();before=copy.deepcopy(c);original=budget.assess(c,q);extended=assess(c,q)
        self.assertEqual(original['status'],'refuse');self.assertEqual(extended['status'],'admit')
        for key in ['projected_usd','reserve_usd','prior_experiment_upper_bound_usd','hourly_usd']:
            self.assertEqual(extended[key],original[key])
        self.assertFalse(extended['stop_on_billing_threshold']);self.assertEqual(c,before)
    def test_forecast_beyond_completion_envelope_is_refused(self):
        c,q=self.fixture();q['prior_experiment_upper_bound_usd']='120'
        self.assertEqual(assess(c,q)['status'],'refuse')
    def test_malformed_or_unscoped_authority_is_refused(self):
        for field,value in [('explicitUserRequest',False),('estimatedAdmissionEnvelopeUsd','1000'),
                            ('referenceBudgetUsd','0'),('stopOnBillingThreshold',True)]:
            c,q=self.fixture();c['completion_authorization'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):assess(c,q)
    def test_protocol_windows_and_grid_are_unchanged(self):
        c,q=self.fixture();a=assess(c,q)
        self.assertFalse(a['changes_protocol_windows']);self.assertFalse(a['reduces_repetitions'])
        self.assertEqual(c['window_seconds'],120);self.assertEqual(c['measurement_grid']['full_workflows'],27)
    def test_original_preflight_override_is_restored_after_failure(self):
        c,q=self.fixture();original=budget.assess
        with self.assertRaises(RuntimeError):
            with original_admission(c):
                self.assertEqual(budget.assess(c,q)['status'],'admit');raise RuntimeError('synthetic failure')
        self.assertIs(budget.assess,original)
    def test_smoke_cannot_use_completion_authority(self):
        c,q=self.fixture();c['execution_mode']='smoke'
        with self.assertRaises(ValueError):authorization(c)

if __name__=='__main__':unittest.main()
