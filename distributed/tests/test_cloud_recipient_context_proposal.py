"""Tiny isolated context fixtures. No Docker, compilation, SDK or network."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import cloud_build
import image
import topology

PROPOSAL=ROOT/'maintenance/proposals/recipient-result-transport'
spec=importlib.util.spec_from_file_location('cloud_context_candidate',PROPOSAL/'cloud_context.py')
candidate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
audit_spec=importlib.util.spec_from_file_location('original_smoke_source_audit',ROOT/'maintenance/smoke_audit.py')
audit=importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(audit)


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class CloudRecipientContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.context=Path(self.temporary.name)/'fresh-distributed-copy'
        for name,data in {
            'app/'+candidate.TRANSPORT:(PROPOSAL/'fixtures/original-transport.rs').read_bytes(),
            'app/'+candidate.VALIDATOR:(ROOT.parent/candidate.VALIDATOR).read_bytes(),
            'app/distributed/worker.mjs':b'export {};\n',
            'Dockerfile':b'FROM an-existing-original-base\n',
        }.items():
            path=self.context/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        native=self.context/'upstream'/candidate.NATIVE
        native.parent.mkdir(parents=True)
        native.write_text('// original upstream prefix kept unchanged\n'+(self.context/'app'/candidate.TRANSPORT).read_text())
        metadata={'upstreamCommit':'original-pin','files':{candidate.NATIVE:{'original':'a'*64,'adapted':sha(native)}}}
        (self.context/'upstream/vcfhe-adapter.json').write_text(json.dumps(metadata))
        self.local={name:sha(self.context/'app'/name) for name in [candidate.TRANSPORT,candidate.VALIDATOR]}
        self.original_inputs=image.inputs(self.context)

    def tearDown(self):self.temporary.cleanup()

    def record(self,proof=None):
        value={'schema':'vcfhe-distributed-build-v1','localSource':self.local,
               'distributedSource':{'worker.mjs':sha(self.context/'app/distributed/worker.mjs')},
               'dockerfileSha256':sha(self.context/'Dockerfile'),'buildInputs':image.inputs(self.context),
               'buildCommand':['docker','build',str(self.context)]}
        if proof:value['nativeRecipientTransport']=proof
        return value

    def test_only_copied_native_view_changes_and_original_app_source_remains_exact(self):
        original=sha(self.context/'app'/candidate.TRANSPORT)
        proof=candidate.transform(self.context,self.local)
        self.assertEqual(sha(self.context/'app'/candidate.TRANSPORT),original)
        self.assertEqual(sha(self.context/'app'/candidate.VALIDATOR),candidate.EXPECTED_VALIDATOR)
        after=(self.context/'upstream'/candidate.NATIVE).read_text()
        self.assertTrue(after.startswith('// original upstream prefix kept unchanged\n'))
        self.assertIn('let (responses,poll_count)=acquire_accepted_user_results',after)
        metadata=json.loads((self.context/'upstream/vcfhe-adapter.json').read_text())
        self.assertEqual(metadata['files'][candidate.NATIVE]['adapted'],sha(self.context/'upstream'/candidate.NATIVE))
        self.assertEqual(metadata['files'][candidate.NATIVE]['original'],'a'*64)
        self.assertEqual(metadata['distributedRecipientTransport'],proof['compiled'])
        self.assertEqual(proof['compiled']['acquisitionFunctionSha256'],sha(PROPOSAL/'acquire-accepted-results.rs'))
        self.assertEqual(proof['compiled']['loopbackTestSourceSha256'],sha(PROPOSAL/'transport-regressions.rs'))

    def test_original_smoke_source_context_accepts_complete_new_closure(self):
        proof=candidate.transform(self.context,self.local)
        record=self.record(proof)
        (self.context/'distributed-source.json').write_text(json.dumps(record))
        self.assertEqual(audit.source_context(record,self.context),self.context.resolve())
        staged=self.context/'app'/candidate.STAGED/'acquire-accepted-results.rs'
        staged.write_text(staged.read_text()+'\n')
        with self.assertRaises(ValueError):audit.source_context(record,self.context)

    def test_real_native_cache_formula_and_image_receipt_identity_change(self):
        before=self.record()
        proof=candidate.transform(self.context,self.local);after=self.record(proof)
        config={'project_id':'example-project','campaign':'vcfhe-candidate-smoke','registry_region':'us-central1',
                'images':{'campaign':'','besu':''},'regions':[{'name':'us-central1','zone':'us-central1-a'}]}
        resources={'project':'example-project','region':'us-central1','repository':'vcfhe-candidate-smoke',
                   'builderServiceAccount':'projects/example-project/serviceAccounts/example',
                   'bucket':'gs://example-placeholder'}
        old_spec,old_tag,_=cloud_build.specification(config,before,resources,'hyperledger/besu@sha256:'+'1'*64)
        new_spec,new_tag,_=cloud_build.specification(config,after,resources,'hyperledger/besu@sha256:'+'1'*64)
        old_script=old_spec['steps'][0]['args'][1];new_script=new_spec['steps'][0]['args'][1]
        self.assertNotEqual(old_tag,new_tag)
        self.assertNotEqual(topology.digest(before),topology.digest(after))
        old_cache=old_script.split('docker pull ',1)[1].split(' ',1)[0]
        new_cache=new_script.split('docker pull ',1)[1].split(' ',1)[0]
        self.assertNotEqual(old_cache,new_cache)
        self.assertEqual(before['localSource'],after['localSource'])

    def test_proposal_source_drift_must_be_checked_before_build(self):
        proof=candidate.transform(self.context,self.local)
        candidate.verify_source_inputs(proof)
        changed=dict(proof['sourceFiles']);changed['acquire-accepted-results.rs']='0'*64
        with mock.patch.object(candidate,'source_inputs',return_value=changed):
            with self.assertRaises(ValueError):candidate.verify_source_inputs(proof)

    def test_sealed_or_original_shared_context_cannot_be_mutated(self):
        native=self.context/'upstream'/candidate.NATIVE;before=sha(native)
        (self.context/'complete.json').write_text('{}')
        with self.assertRaises(ValueError):candidate.transform(self.context,self.local)
        self.assertEqual(sha(native),before)
        self.assertFalse((self.context/'app'/candidate.STAGED).exists())

    def test_wrong_original_app_hash_or_native_evidence_fails_closed(self):
        metadata=self.context/'upstream/vcfhe-adapter.json'
        value=json.loads(metadata.read_text());value['files'][candidate.NATIVE]['adapted']='0'*64
        metadata.write_text(json.dumps(value));before=sha(self.context/'upstream'/candidate.NATIVE)
        with self.assertRaises(ValueError):candidate.transform(self.context,self.local)
        self.assertEqual(sha(self.context/'upstream'/candidate.NATIVE),before)


if __name__=='__main__':unittest.main()
