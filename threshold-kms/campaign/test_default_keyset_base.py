import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('default_keyset_base',HERE/'default_keyset_base.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

class DefaultKeysetBaseTests(unittest.TestCase):
    def material(self,root):
        for folder in base.FOLDERS:(root/folder).mkdir(parents=True,exist_ok=True)
        ready={'status':'passed','parameters':'Default','parties':4,'corruptionThreshold':1,'preloadedFheKey':False,'fullPreprocessing':True,'upstreamCommit':base.campaign.PIN};(root/'keyset/ready.json').write_text(json.dumps(ready))
        for name in ['encryption-key.bin','evaluation-key.bin','prss.json']:(root/'keyset'/name).write_bytes(b'x')
        manifest={'format':base.FORMAT,'status':'passed','parameters':'Default','upstreamCommit':base.campaign.PIN,'parties':4,'corruptionThreshold':1,'network':'isolated-docker-kms','files':base.files(root)};manifest['manifestSha256']=base.payload_digest(manifest);base.write(root/'base.json',manifest)
    def test_validate_and_restore_copy_the_sealed_vaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'source';source.mkdir();self.material(source);manifest=base.validate(source);self.assertEqual(manifest['parameters'],'Default');target=root/'target';record=base.restore(source,target);self.assertEqual(record['baseFiles'],base.files(target));self.assertEqual(base.files(target),base.files(source))
    def test_changed_private_share_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.material(root);(root/'private-1/share').write_text('changed')
            with self.assertRaisesRegex(ValueError,'changed or is incomplete'):base.validate(root)
