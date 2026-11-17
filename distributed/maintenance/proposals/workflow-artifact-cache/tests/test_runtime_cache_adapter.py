import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROPOSAL=Path(__file__).resolve().parents[1]
DISTRIBUTED=next(p for p in [PROPOSAL,*PROPOSAL.parents] if (p/'deployment.py').is_file())
ROOT=DISTRIBUTED.parent
spec=importlib.util.spec_from_file_location('proposed_cache_runtime',PROPOSAL/'runtime.py')
runtime=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class WorkflowArtifactAdapterTests(unittest.TestCase):
    def test_cache_changes_only_the_compilation_entry_and_preserves_every_verification_check(self):
        names=['common.mjs','owner.mjs','paired.mjs','paired-linear.mjs','evaluate.mjs',
               'linear.mjs','policy-init.mjs','workflow-auth.mjs','poc_evidence.py']
        before={name:(ROOT/'threshold-kms/campaign'/name).read_bytes() for name in names}
        with tempfile.TemporaryDirectory() as folder:
            campaign=Path(folder)/'app/threshold-kms/campaign'
            campaign.mkdir(parents=True)
            for name,value in before.items():(campaign/name).write_bytes(value)
            subprocess.run([sys.executable,str(ROOT/'threshold-kms/campaign/build-profile.py'),
                            '--runtime',str(campaign/'runtime')],check=True,capture_output=True)
            for file in (campaign/'runtime/scripts').glob('*.mjs'):
                file.write_text(file.read_text().replace(ROOT.as_uri(),'file:///app'))
            record=runtime.adapt(campaign.parents[1])
            old=before['workflow-auth.mjs'].decode()
            new=(campaign/'workflow-auth.mjs').read_text()
            start='async function compileCanonicalWorkflowArtifactsOnce(){'
            end='export function compileCanonicalWorkflowArtifacts(){'
            self.assertEqual(old[old.index(start):old.index(end)],new[new.index(start):new.index(end)])
            checks='const lower=value=>String(value).toLowerCase();'
            self.assertEqual(old[old.index(checks):],new[new.index(checks):])
            self.assertIn('export const WORKFLOW_AUTH_CLI_DEADLINE_MS=120_000;',new)
            self.assertIn('export const WORKFLOW_RPC_QUORUM=3;',new)
            self.assertIn('compileWorkflowArtifactsForImageBuild',new)
            wrapper=new[new.index(end):new.index(checks)]
            self.assertIn('loadWorkflowArtifactCache',wrapper)
            self.assertNotIn('compileCanonicalWorkflowArtifactsOnce()',wrapper)
            self.assertNotIn('process.env',wrapper)
            self.assertEqual(record['files']['threshold-kms/campaign/workflow-auth.mjs']['sourceSha256'],
                             hashlib.sha256(before['workflow-auth.mjs']).hexdigest())
            subprocess.run(['node','--check',str(campaign/'workflow-auth.mjs')],check=True,capture_output=True)
        for name,value in before.items():self.assertEqual((ROOT/'threshold-kms/campaign'/name).read_bytes(),value)

    def test_image_build_compiles_cache_after_adapter_and_before_inventory(self):
        source=(PROPOSAL/'image.py').read_text()
        self.assertLess(source.index('python3 /app/distributed/runtime.py --app /app'),
                        source.index('await buildWorkflowArtifactCache("/app")'))
        self.assertIn("+anchor)",source[source.index('await buildWorkflowArtifactCache("/app")'):])
        helper=(PROPOSAL/'workflow-artifact-cache.mjs').read_text()
        self.assertIn('assert.deepStrictEqual(loaded,artifacts',helper)
        self.assertNotIn('process.env',helper)
        self.assertNotIn('process.stdin',helper)
        self.assertNotIn('process.argv',helper)

if __name__=='__main__':unittest.main()
