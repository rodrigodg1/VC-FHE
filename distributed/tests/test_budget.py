from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import unittest
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import budget
class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((HERE/'config.example.json').read_text())
        self.quote={'currency':'USD','campaign':self.config['campaign'],'layout':'four-hosts',
            'hourly':{'compute':'0.8','nat':'0.2','disks':'0.1','ipv4':'0.0'},'planned_hours':'12',
            'build_registry':'2','retained_resources':'1','transfer_storage_upper_bound':'8',
            'quoted_at':datetime.now(timezone.utc).isoformat(),'source_urls':['https://example.org/synthetic-test-only']}
    def test_full_remaining_run_must_fit(self):
        self.assertEqual(budget.assess(self.config,self.quote)['status'],'admit')
        self.quote['transfer_storage_upper_bound']='40'
        self.assertEqual(budget.assess(self.config,self.quote)['status'],'refuse')
    def test_missing_costs_and_impossible_duration_rejected(self):
        self.quote['planned_hours']='1'
        with self.assertRaises(ValueError):budget.assess(self.config,self.quote)
        self.quote['planned_hours']='12';del self.quote['hourly']['nat']
        with self.assertRaises(ValueError):budget.assess(self.config,self.quote)
    def test_elapsed_cost_is_not_forgotten(self):
        result=budget.assess(self.config,self.quote,elapsed_hours=20,remaining_hours=10,spent_transfer_storage=5)
        self.assertEqual(result['status'],'refuse')
        self.assertFalse(result['billing_hard_cap'])
    def test_unfilled_quote_template_is_rejected(self):
        self.quote['quoted_at']=None
        with self.assertRaises(ValueError):budget.assess(self.config,self.quote)
        for value in [None,'not-a-price',float('nan'),True]:
            with self.assertRaises(ValueError):budget.amount(value)
if __name__=='__main__':unittest.main()
