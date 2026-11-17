import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parents[1]
ROOT=HERE.parent
sys.path.insert(0,str(HERE))
import runtime

class RuntimeTests(unittest.TestCase):
    def test_guarded_image_adapter_preserves_security_source(self):
        with tempfile.TemporaryDirectory() as folder:
            app=Path(folder)/'app'
            campaign=app/'threshold-kms/campaign'
            campaign.mkdir(parents=True)
            names=['common.mjs','owner.mjs','paired.mjs','paired-linear.mjs','evaluate.mjs','linear.mjs','policy-init.mjs','workflow-auth.mjs','poc_evidence.py']
            before={name:(ROOT/'threshold-kms/campaign'/name).read_bytes() for name in names}
            for name,content in before.items():(campaign/name).write_bytes(content)
            # Exercise the actual preceding image-build step, without building
            # Rust, starting containers or executing an experiment.
            subprocess.run([sys.executable,str(ROOT/'threshold-kms/campaign/build-profile.py'),
                            '--runtime',str(campaign/'runtime')],check=True,capture_output=True)
            generated=campaign/'runtime/scripts'
            for file in generated.glob('*.mjs'):
                file.write_text(file.read_text().replace(ROOT.as_uri(),'file:///app'))
            report=runtime.adapt(app)
            self.assertFalse(report['protocolRulesChanged'])
            self.assertNotIn('HDNodeWallet.fromPhrase',(campaign/'evaluate.mjs').read_text())
            self.assertNotIn('identities[i].privateKey',(generated/'canonical-game-driver.mjs').read_text())
            owner=(campaign/'owner.mjs').read_text()
            self.assertNotIn("json('/owner-identity/identities.json')",owner)
            for guard in ['OwnerChainQuorum','authenticateNonlinearWorkflow','releaseRequestFromWire',
                          'request addressed to another owner','assertExpectedWorkflow']:
                self.assertIn(guard,owner)
            for file in campaign.rglob('*.mjs'):
                subprocess.run(['node','--check',str(file)],check=True,capture_output=True)
            for name,content in before.items():self.assertEqual((ROOT/'threshold-kms/campaign'/name).read_bytes(),content)
            with self.assertRaises(ValueError):runtime.adapt(app)

    def test_source_drift_fails_closed(self):
        with self.assertRaises(ValueError):runtime.once('duplicated duplicated','duplicated','changed')
        with self.assertRaises(ValueError):runtime.once('different','missing','changed')

if __name__=='__main__':unittest.main()
