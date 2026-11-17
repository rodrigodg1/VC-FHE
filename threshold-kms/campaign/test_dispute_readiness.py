import copy
import json
from pathlib import Path
import tempfile
import unittest
from dispute_readiness import validate, PROFILE, CLASSIFICATION
from run import parser, selection
from test_bounty_route import fixture


class DisputeReadinessTests(unittest.TestCase):
    def files(self, root):
        cfg, app = fixture()
        cfg.update(readinessOnly=True, smoke=True, half='nonlinear', parameters='Test', records=50,
                   repeats=1, nonlinearWorkloads=['regulatory'], readinessDisputesOnly=PROFILE,
                   classification=CLASSIFICATION)
        keys = dict(status='passed', parameters='Test', fullPreprocessing=True, preloadedFheKey=False)
        case = app['cases'][0]
        case.update(name='regulatory_qoe_compliance-0', n=50,
                    readinessScope='dispute-only-no-output-release')
        case['metrics']['disputes'][0].update(faultIndex=case['metrics']['leaves']-1)
        case['metrics']['disputes'][0]['settlement']['certificates'] = [dict(plaintextOpenings=0)]*2
        app.update(status='passed', config=cfg, keys=keys, kmsCalls=0, policyEvents=[],
                   protectedRecordBaselines={}, protectedRecords={})
        prepared = dict(keys=keys, cases=[dict(name=case['name'])])
        for name, value in [('config/campaign.json', cfg), ('reports/application.json', app),
                            ('fixtures/prepared.json', prepared), ('keyset/ready.json', keys)]:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value))
        return cfg, app

    def test_dispute_profile_is_never_a_full_campaign(self):
        args=['--readiness-disputes-only','--poc-readiness','--smoke','--fhe-params','Test',
              '--allow-insecure-test','--nonlinear-protocol','bounty-v2','--half','nonlinear',
              '--kms-threads','1','--kms-tokio-threads','1']
        self.assertEqual(selection(parser().parse_args(args))['readinessDisputesOnly'], PROFILE)
        for flags in (['--poc'], ['--half','both'], ['--fhe-params','Default']):
            with self.assertRaises(ValueError):selection(parser().parse_args(args+flags))

    def test_valid_dispute_pilot_remains_unpublishable(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.files(root);result=validate(root)
            self.assertEqual(result['status'],'passed');self.assertEqual(result['kmsCalls'],0)
            self.assertFalse(result['analysisComplete'])

    def test_actual_release_or_policy_change_is_rejected(self):
        for field,value in [('kmsCalls',1),('policyEvents',[{}]),('protectedRecords',{'record':{}})]:
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);_,app=self.files(root);app[field]=value
                (root/'reports/application.json').write_text(json.dumps(app))
                with self.assertRaisesRegex(ValueError,'release-policy changes'):validate(root)

    def test_preserved_request_or_result_is_rejected(self):
        for name in ['exchange/request-0.json','recipient/result-0.json','release-evidence/evidence.json']:
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);self.files(root);path=root/name;path.parent.mkdir(exist_ok=True);path.write_text('{}')
                with self.assertRaisesRegex(ValueError,'decryption request or result'):validate(root)

    def test_plaintext_leaf_opening_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);_,app=self.files(root)
            app['cases'][0]['metrics']['disputes'][0]['settlement']['certificates'][0]['plaintextOpenings']=1
            (root/'reports/application.json').write_text(json.dumps(app))
            with self.assertRaisesRegex(ValueError,'plaintext opening'):validate(root)


if __name__=='__main__':unittest.main()
