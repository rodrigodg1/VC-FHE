import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import controller_inputs

class ControllerInputTests(unittest.TestCase):
    def fixture(self):
        return {'queries':[{'query_id':'stav360_session_mos_sum','dataset':'STAV360','values':[1]*16}]}
    def test_missing_fixture_is_prepared_before_paid_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            file=root/'datasets/outputs/linear-inputs.json'
            calls=[]
            def ensure(half):calls.append(('datasets',half));return {'public-input':{'sha256':'a'*64}}
            def generate(args,**kwargs):
                calls.append(('prepare-fixture',args));file.parent.mkdir(parents=True);file.write_text(json.dumps(self.fixture()))
            with patch.object(controller_inputs,'ROOT',root),patch('deployment.campaign_module',return_value=SimpleNamespace(ensure_datasets=ensure)),patch('subprocess.run',side_effect=generate):
                result=controller_inputs.prepare()
            self.assertEqual(calls[0],('datasets','both'))
            self.assertEqual(len(calls),2)
            self.assertEqual(len(result['linearFixtureSha256']),64)
    def test_existing_bad_input_is_preserved_instead_of_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);file=root/'datasets/outputs/linear-inputs.json';file.parent.mkdir(parents=True)
            content=json.dumps({'queries':[]});file.write_text(content)
            with patch.object(controller_inputs,'ROOT',root),patch('deployment.campaign_module',return_value=SimpleNamespace(ensure_datasets=lambda _:{})),patch('subprocess.run') as call:
                with self.assertRaises(ValueError):controller_inputs.prepare()
                call.assert_not_called()
            self.assertEqual(file.read_text(),content)

if __name__=='__main__':unittest.main()
