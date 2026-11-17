import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parents[1]

class CloudEntrypointTests(unittest.TestCase):
    def fixture(self,tmp,fail=False):
        root=Path(tmp);d=root/'distributed';d.mkdir()
        shutil.copy2(HERE.parent/'run-distributed.sh',root/'run-distributed.sh')
        (d/'controller-bootstrap.sh').write_text(
            'printf "bootstrap\\n" >> "$CHECK_LOG"\n'+('return 7\n' if fail else 'export CHECK_TOOL_PATH=ready\n'))
        (d/'cli.py').write_text('import json,os,sys\nfrom pathlib import Path\nPath(os.environ["CLI_LOG"]).write_text(json.dumps(dict(args=sys.argv[1:],tool=os.environ.get("CHECK_TOOL_PATH"))))\n')
        env={**os.environ,'CHECK_LOG':str(root/'bootstrap.log'),'CLI_LOG':str(root/'cli.json')}
        # Use the already running interpreter without invoking a package manager.
        binary=root/'bin';binary.mkdir();(binary/'python3').symlink_to(sys.executable)
        env['PATH']=str(binary)+os.pathsep+env['PATH']
        return root,env
    def test_cloud_prerequisites_run_first_and_export_tool_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,env=self.fixture(tmp)
            p=subprocess.run(['bash',str(root/'run-distributed.sh'),'cloud-run','--config','private.local.json'],env=env,capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr)
            value=json.loads((root/'cli.json').read_text())
            self.assertEqual(value['tool'],'ready')
            self.assertEqual(value['args'],['cloud-run','--config','private.local.json'])
    def test_failed_dependency_setup_cannot_dispatch_cloud_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,env=self.fixture(tmp,fail=True)
            p=subprocess.run(['bash',str(root/'run-distributed.sh'),'cloud-run'],env=env,capture_output=True)
            self.assertEqual(p.returncode,7)
            self.assertFalse((root/'cli.json').exists())
    def test_inspection_and_help_do_not_install(self):
        for args in [['plan'],['cloud-run','--help']]:
            with tempfile.TemporaryDirectory() as tmp:
                root,env=self.fixture(tmp,fail=True)
                p=subprocess.run(['bash',str(root/'run-distributed.sh'),*args],env=env,capture_output=True)
                self.assertEqual(p.returncode,0,p.stderr)
                self.assertFalse((root/'bootstrap.log').exists())

if __name__=='__main__':unittest.main()
