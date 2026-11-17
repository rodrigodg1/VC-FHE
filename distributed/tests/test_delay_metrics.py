import json
from pathlib import Path
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from delay_metrics import distribution,export,network_rows

class DelayTests(unittest.TestCase):
    def test_small_samples_do_not_claim_tail_latency_and_invalid_values_fail(self):
        self.assertEqual(distribution([1,3,2])['median_seconds'],2)
        self.assertIsNone(distribution([1,3,2])['observed_p95_seconds'])
        self.assertAlmostEqual(distribution(list(range(20)))['observed_p95_seconds'],18.05)
        for value in [-1,float('nan'),True]:
            with self.assertRaises(ValueError):distribution([value])
    def test_export_separates_handler_inclusive_rpc_from_tcp_and_retains_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp);samples=run/'distributed/samples/host-1';samples.mkdir(parents=True)
            (run/'distributed/supplement').mkdir()
            base={'kind':'network_probe','host':'host-1','target_host':'host-2','port':8545,'elapsed_seconds':.02}
            (samples/'host-observations.jsonl').write_text('\n'.join(json.dumps({**base,'status':s}) for s in ['connected','unavailable']))
            roles={'coordinator-1':{'role':'coordinator','host':'host-1'},'auditor-1':{'role':'auditor','host':'host-2'}}
            result=export(run,roles,[{'node':'coordinator-1','cross_host':True,'roundTripSeconds':2}])
            self.assertEqual(result['tcpObservations'],2)
            self.assertIn('processing',result['applicationScope'])
            import csv
            out=run/'distributed/supplement'
            rows=list(csv.DictReader((out/'network-delay-summary.csv').open()))
            self.assertEqual((rows[0]['attempts'],rows[0]['failures'],rows[0]['observations']),('2','1','1'))
            rows=list(csv.DictReader((out/'application-delay-summary.csv').open()))
            self.assertEqual(next(r for r in rows if r['role']=='coordinator')['median_seconds'],'2')
        with self.assertRaises(ValueError):network_rows([base],{'host-1'})

if __name__=='__main__':unittest.main()
