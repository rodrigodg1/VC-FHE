from datetime import datetime,timezone
from decimal import Decimal
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import budget

HERE=Path(__file__).resolve().parents[1]

class CarryforwardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.changed={'launch.py':(HERE/'launch.py').read_text()}
        self.module=budget
        self.config={'campaign':'synthetic-probe','layout':'four-hosts','execution_mode':'smoke','window_seconds':120,
            'budget':{'maximum':50,'reserve':10}}
        self.quote={'currency':'USD','campaign':'synthetic-probe','layout':'four-hosts',
            'quoted_at':datetime.now(timezone.utc).isoformat(),'source_urls':['https://example.org/synthetic-test-only'],
            'hourly':{'compute':'0.824608','nat':'0.0056','disks':'0.125','ipv4':'0.020'},
            'planned_hours':'6','build_registry':'21','retained_resources':'0','transfer_storage_upper_bound':'6.210'}

    def test_absent_prior_is_zero_and_old_quote_behavior_is_preserved(self):
        result=self.module.assess(self.config,self.quote)
        self.assertEqual(result['prior_experiment_upper_bound_usd'],'0')
        self.assertEqual(Decimal(result['projected_usd']),Decimal('33.061248'))

    def test_prior_is_counted_once_and_changes_admission(self):
        self.quote['prior_experiment_upper_bound_usd']='6'
        result=self.module.assess(self.config,self.quote)
        self.assertEqual(result['status'],'admit');self.assertEqual(Decimal(result['projected_usd']),Decimal('39.061248'))
        self.quote['prior_experiment_upper_bound_usd']='7'
        self.assertEqual(self.module.assess(self.config,self.quote)['status'],'refuse')
        self.assertEqual(self.quote['prior_experiment_upper_bound_usd'],'7')

    def test_elapsed_and_remaining_checks_keep_prior(self):
        self.quote['prior_experiment_upper_bound_usd']='6'
        result=self.module.assess(self.config,self.quote,elapsed_hours='1',remaining_hours='2',spent_transfer_storage='0.5')
        self.assertEqual(Decimal(result['projected_usd']),Decimal('6')+Decimal('0.975208')*3+Decimal('0.5')+Decimal('27.210'))
        self.assertEqual(result['prior_experiment_upper_bound_usd'],'6')

    def test_invalid_prior_is_rejected(self):
        for value in [None,True,False,-1,'-0.01','NaN','Infinity',float('nan'),'not-a-cost']:
            with self.subTest(value=value):
                self.quote['prior_experiment_upper_bound_usd']=value
                with self.assertRaises(ValueError):self.module.assess(self.config,self.quote)

    def test_runtime_envelope_fixed_total_includes_prior(self):
        # Execute the exact two candidate statements without importing launcher.
        lines=self.changed['launch.py'].splitlines()
        index=next(i for i,line in enumerate(lines) if 'fixed=sum(float(self.quote[k])' in line)
        statements='\n'.join(line.strip() for line in lines[index:index+2])
        self.quote['prior_experiment_upper_bound_usd']='6'
        dummy=type('Envelope',(),{'quote':self.quote})()
        scope={'self':dummy,'budget':self.module};exec(statements,scope)
        self.assertEqual(scope['fixed'],33.21)

if __name__=='__main__':unittest.main(verbosity=2)
