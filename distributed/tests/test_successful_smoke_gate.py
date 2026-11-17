"""Failed or mismatched smoke evidence must not authorize the full campaign."""
from pathlib import Path
import sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results.common import write
from cloud_results.smoke_gate import validate
import topology

class SuccessfulSmokeGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.record={'synthetic':'source closure'}
        self.digest='example/research/campaign@sha256:'+'a'*64
        write(self.root/'published-image.json',{'digest':self.digest})
        self.proof={'schema':'source-matched-successful-smoke-v1','status':'passed','sourceSha256':topology.digest(self.record),
            'imageDigest':self.digest,'evaluationPublishable':False,'fullCases':1,'privateCloudBackupVerified':True,
            'ownedInfrastructureRemoved':True,'sealSha256':'b'*64}
    def put(self):write(self.root/'successful-smoke.local.json',self.proof)
    def test_missing_or_failed_smoke_is_refused(self):
        with self.assertRaises(ValueError):validate(self.root,self.record)
        self.proof['status']='failed';self.put()
        with self.assertRaisesRegex(ValueError,'successful'):validate(self.root,self.record)
    def test_changed_image_or_source_is_refused(self):
        for field in ('sourceSha256','imageDigest'):
            previous=self.proof[field];self.proof[field]='different';self.put()
            with self.assertRaisesRegex(ValueError,'different'):validate(self.root,self.record)
            self.proof[field]=previous
    def test_incomplete_preservation_or_cleanup_is_refused(self):
        for field in ('privateCloudBackupVerified','ownedInfrastructureRemoved'):
            self.proof[field]=False;self.put()
            with self.assertRaisesRegex(ValueError,'incomplete'):validate(self.root,self.record)
            self.proof[field]=True
    def test_source_matched_regional_proof_passes_without_claiming_full_measurements(self):
        self.put();self.assertEqual(validate(self.root,self.record)['fullCases'],1)
    def test_explicit_postcollection_proof_never_claims_an_original_seal(self):
        from cloud_results.postcollection import SCHEMA
        attestation={'schema':SCHEMA,'status':'passed','evaluationPublishable':False,'originalSealVerified':False,
            'originalRunnerStatus':'failed','originalStateStatus':'validating','protocolRequestsRepeated':0,
            'sourceSha256':self.proof['sourceSha256'],'imageDigest':self.digest,
            'privateCloudBackupVerified':True,'ownedInfrastructureRemoved':True,'fullCases':1}
        self.proof.update(schema='source-matched-postcollection-functional-smoke-v1',sealSha256=None,
            originalSealVerified=False,attestationSha256=topology.digest(attestation))
        write(self.root/'postcollection-smoke-attestation.local.json',attestation);self.put()
        self.assertFalse(validate(self.root,self.record)['originalSealVerified'])
        for field,value in [('protocolRequestsRepeated',1),('originalRunnerStatus','passed'),
                            ('originalSealVerified',True),('evaluationPublishable',True)]:
            changed=dict(attestation);changed[field]=value
            write(self.root/'postcollection-smoke-attestation.local.json',changed)
            with self.assertRaises(ValueError):validate(self.root,self.record)
        write(self.root/'postcollection-smoke-attestation.local.json',attestation)
        self.proof['sealSha256']='c'*64;self.put()
        with self.assertRaises(ValueError):validate(self.root,self.record)

    def test_full_measurements_cannot_be_mislabelled_as_smoke(self):
        self.proof['fullCases']=27;self.put()
        with self.assertRaises(ValueError):validate(self.root,self.record)
if __name__=='__main__':unittest.main()
