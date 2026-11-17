"""Structural exporter tests only; these temporary fixtures are not experiments."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('campaign_export',Path(__file__).with_name('export.py'))
exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)

class ExportTests(unittest.TestCase):
    def fixture(self,root):
        values={
            'config/campaign.json':{'parameters':'Test','smoke':True,'half':'linear','linearSizes':[2],'repeats':1,'chainId':'46853'},
            'keyset/ready.json':{'status':'passed','parameters':'Test','fullPreprocessing':True,'preloadedFheKey':False},
            'owner/expected.json':{'unit-only':7},
            'reports/application.json':{'status':'passed','kmsCalls':1,'chain':{'consensus':'QBFT','validators':['a','b','c','d'],'observedBlock':1,'advancedBlock':2},
              'cases':[{'name':'unit-only','half':'linear','dataset':{'id':'UNIT-FIXTURE-NOT-EVIDENCE'},'metrics':{'aggregateMs':10},
                'n':2,'repeat':0,'ownerPreparationMs':1,'releaseMs':2,'endToEndMs':3,'gasUsed':'4','transactionCount':5,'calldataBytes':6,'outputDigest':'digest'}]},
            'recipient/result-0.json':{'name':'unit-only','actual':7,'outputDigest':'digest','responses':3,'directUserAndPublicDenied':4,
              'negativeResponseChecks':4,'directAdministrativeDenied':28,'changedReservedWireDenied':4,'kmsSeconds':.01,'recipientSeconds':.02,'requestBytes':101,
              'submitSeconds':.003,'polls':3,'responseBytes':202}}
        for name,value in values.items():
            path=root/name;path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(value))
        return values
    def test_explicit_byte_units_and_smoke_classification(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):exporter.export(root)
            result=json.loads((root/'reports/results.json').read_text());row=result['rows'][0]
            self.assertEqual(result['classification'],'smoke-not-evaluation')
            self.assertEqual(row['request_json_bytes'],101);self.assertNotIn('request_bytes',row)
            self.assertEqual(row['aggregate_ms'],10);self.assertIsNone(row['operator_fhe_ms'])
    def test_failed_recipient_or_ingress_cannot_export(self):
        for field,value in [('actual',8),('responses',2),('directAdministrativeDenied',0),('negativeResponseChecks',0)]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);values=self.fixture(root);result=values['recipient/result-0.json'];result[field]=value
                (root/'recipient/result-0.json').write_text(json.dumps(result))
                with self.assertRaises(ValueError):exporter.export(root)
                self.assertFalse((root/'reports/results.csv').exists())
    def test_new_comparative_profile_cannot_export_missing_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);values=self.fixture(root)
            values['config/campaign.json']['comparativeMetricsVersion']='comparative-metrics-v1'
            (root/'config/campaign.json').write_text(json.dumps(values['config/campaign.json']))
            with self.assertRaisesRegex(ValueError,'missing linear communication'):
                exporter.export(root)
            self.assertFalse((root/'reports/results.csv').exists())
    def test_readiness_does_not_generate_evaluation_decryption_tables(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);values=self.fixture(root)
            cfg=values['config/campaign.json'];cfg.update(readinessOnly=True,classification='test-insecure-readiness-not-evaluation')
            (root/'config/campaign.json').write_text(json.dumps(cfg))
            with contextlib.redirect_stdout(io.StringIO()):exporter.export(root)
            self.assertTrue((root/'reports/results.csv').exists())
            self.assertTrue((root/'reports/READINESS-ONLY.txt').exists())
            self.assertFalse(list((root/'reports').glob('*.tex')))
    def test_single_workload_readiness_requires_exact_case_and_cannot_publish(self):
        for wrong in [False,True]:
            with self.subTest(wrong=wrong),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);values=self.fixture(root)
                name='regional_qoe_compliance-0'
                cfg=values['config/campaign.json'];cfg.update(half='nonlinear',readinessOnly=True,
                    nonlinearWorkloads=['regional'],classification='test-insecure-readiness-not-evaluation')
                case=values['reports/application.json']['cases'][0];case.update(name=name,half='nonlinear')
                case['metrics']['disputes']=[{'structural_unit_test':True}]
                values['recipient/result-0.json']['name']=name
                values['owner/expected.json']={name:7}
                if wrong:case['name']='regulatory_qoe_compliance-0'
                for file,value in values.items():(root/file).write_text(json.dumps(value))
                if wrong:
                    with self.assertRaisesRegex(ValueError,'coverage'):exporter.export(root)
                    continue
                with contextlib.redirect_stdout(io.StringIO()):exporter.export(root)
                self.assertTrue((root/'reports/READINESS-ONLY.txt').exists())
                self.assertFalse(list((root/'reports').glob('*.tex')))
                cfg['readinessOnly']=False;(root/'config/campaign.json').write_text(json.dumps(cfg))
                with self.assertRaisesRegex(ValueError,'readiness-only'):exporter.export(root)

if __name__=='__main__':unittest.main()
