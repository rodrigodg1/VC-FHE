import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import image
from image_test_fixtures import copy_native_recipient_sources,native_recipient_proof

class ImageInputTests(unittest.TestCase):
    def test_added_changed_or_removed_adapter_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(image,'HERE',Path(tmp)):
            proposal=copy_native_recipient_sources(tmp)
            source=Path(tmp)/'adapter.py';source.write_text('original')
            record={'distributedSource':{'adapter.py':hashlib.sha256(source.read_bytes()).hexdigest()},
                    'nativeRecipientTransport':native_recipient_proof(proposal)}
            image.verify_adapter_sources(record)
            for name in ['new.py','new.mjs','new.sh']:
                added=Path(tmp)/name;added.write_text('new adapter')
                with self.assertRaisesRegex(ValueError,'stale adapters'):image.verify_adapter_sources(record)
                added.unlink()
            source.write_text('changed')
            with self.assertRaisesRegex(ValueError,'stale adapters'):image.verify_adapter_sources(record)
            source.unlink()
            with self.assertRaisesRegex(ValueError,'stale adapters'):image.verify_adapter_sources(record)

    def test_nonsource_files_do_not_change_adapter_closure(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(image,'HERE',Path(tmp)):
            proposal=copy_native_recipient_sources(tmp)
            (Path(tmp)/'report.json').write_text('{}')
            (Path(tmp)/'generated').mkdir()
            (Path(tmp)/'generated/helper.py').write_text('not a copied adapter')
            image.verify_adapter_sources({'distributedSource':{},
                'nativeRecipientTransport':native_recipient_proof(proposal)})

    def test_missing_native_proof_is_refused_before_loading_helper(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(image,'HERE',Path(tmp)):
            copy_native_recipient_sources(tmp)
            for proof in [None,{}, {'sourceFiles':{}}]:
                record={'distributedSource':{}}
                if proof is not None:record['nativeRecipientTransport']=proof
                with self.subTest(proof=proof),patch.object(image.types,'ModuleType') as load:
                    with self.assertRaisesRegex(ValueError,'recipient adapter changed or is missing'):
                        image.verify_adapter_sources(record)
                    load.assert_not_called()

    def test_changed_helper_source_is_refused_before_loading_it(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(image,'HERE',Path(tmp)):
            proposal=copy_native_recipient_sources(tmp)
            record={'distributedSource':{},'nativeRecipientTransport':native_recipient_proof(proposal)}
            # Real source proof passes the production verifier before tampering.
            image.verify_adapter_sources(record)
            (proposal/'cloud_context.py').write_text('raise RuntimeError("must never execute")\n')
            with patch.object(image.types,'ModuleType') as load:
                with self.assertRaisesRegex(ValueError,'recipient adapter changed or is missing'):
                    image.verify_adapter_sources(record)
                load.assert_not_called()

    def test_changed_nonloader_proposal_source_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(image,'HERE',Path(tmp)):
            proposal=copy_native_recipient_sources(tmp)
            record={'distributedSource':{},'nativeRecipientTransport':native_recipient_proof(proposal)}
            image.verify_adapter_sources(record)
            (proposal/'acquire-accepted-results.rs').write_text('changed result-acquisition source')
            with self.assertRaisesRegex(ValueError,'stale proposal inputs'):
                image.verify_adapter_sources(record)

    def test_changed_or_added_build_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'app').mkdir()
            (root/'upstream').mkdir()
            (root/'Dockerfile').write_text('FROM fixture-only\n')
            source=root/'app/source.mjs';source.write_text('original')
            record={'dockerfileSha256':hashlib.sha256((root/'Dockerfile').read_bytes()).hexdigest(),
                    'buildInputs':image.inputs(root)}
            image.verify_inputs(root,record)
            source.write_text('changed')
            with self.assertRaises(ValueError):image.verify_inputs(root,record)
            source.write_text('original')
            (root/'upstream/extra.rs').write_text('added input')
            with self.assertRaises(ValueError):image.verify_inputs(root,record)

if __name__=='__main__':unittest.main()
