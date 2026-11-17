"""Mocked controller prerequisite checks. No package manager or cloud is used."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parents[1]

class ControllerBootstrapTests(unittest.TestCase):
    def fixture(self,tmp):
        root=Path(tmp)/'VC-FHE';distributed=root/'distributed';distributed.mkdir(parents=True)
        script=distributed/'controller-bootstrap.sh';shutil.copy2(HERE/'controller-bootstrap.sh',script)
        binary=Path(tmp)/'bin';binary.mkdir();log=Path(tmp)/'commands.log'
        for name in ['python3','git','ssh','scp','tar','openssl','node','npm']:
            self.tool(binary,name,'exit 0',log)
        for name in ['apt-get','brew','docker','gcloud','terraform']:
            self.tool(binary,name,'exit 93',log)
        env={**os.environ,'PATH':str(binary)+':/usr/bin:/bin','BOOTSTRAP_TEST_LOG':str(log)}
        plot=root/'threshold-kms/.cache/postprocess-python/bin/python';plot.parent.mkdir(parents=True)
        plot.write_text('#!/bin/sh\nexit 0\n');plot.chmod(0o755)
        return script,binary,log,env
    def tool(self,binary,name,body,log):
        file=binary/name
        file.write_text('#!/bin/sh\nprintf "%s\\n" "'+name+' $*" >> "$BOOTSTRAP_TEST_LOG"\n'+body+'\n')
        file.chmod(0o755)
    def run_script(self,script,env,*args):
        return subprocess.run(['/bin/bash',str(script),*args],env=env,capture_output=True,text=True,timeout=15)
    def test_check_does_not_install_start_or_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            script,binary,log,env=self.fixture(tmp)
            # Expose-path lookup can read brew's prefix but may not install.
            result=self.run_script(script,env,'--check')
            self.assertEqual(result.returncode,0,result.stderr)
            commands=log.read_text()
            for forbidden in ['apt-get ','brew install','docker ','gcloud ','terraform ','npm --prefix']:
                self.assertNotIn(forbidden,commands)
            self.assertIn('No Docker daemon',result.stdout)
    def test_missing_node_in_check_mode_is_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            script,binary,log,env=self.fixture(tmp)
            self.tool(binary,'node','exit 1',log)
            result=self.run_script(script,env,'--check')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Node.js >=22.10 <23',result.stderr)
            self.assertNotIn('brew install',log.read_text())
            self.assertNotIn('apt-get ',log.read_text())
    def test_admin_requirement_is_reported_without_privilege_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            script,binary,log,env=self.fixture(tmp)
            self.tool(binary,'uname','echo Linux',log)
            self.tool(binary,'id','echo 1000',log)
            self.tool(binary,'sudo','exit 1',log)
            self.tool(binary,'python3','exit 1',log)
            result=self.run_script(script,env,'--install')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('administrator authorization',result.stderr)
            self.assertNotIn('apt-get update',log.read_text())
    def test_sourcing_returns_to_wrapper_instead_of_dispatching_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            script,binary,log,env=self.fixture(tmp)
            # Source arguments are scoped by bash. Success must return to caller.
            command='source "$1" --check; printf "WRAPPER_CONTINUES\\n"'
            result=subprocess.run(['/bin/bash','-c',command,'fixture',str(script)],env=env,
                                  capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('WRAPPER_CONTINUES',result.stdout)
    def test_unknown_flags_cannot_become_an_evaluator_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            script,binary,log,env=self.fixture(tmp)
            result=self.run_script(script,env,'cloud-run')
            self.assertEqual(result.returncode,2)
            self.assertNotIn('gcloud ',log.read_text() if log.exists() else '')
    def test_broken_plotting_imports_receive_one_pinned_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            script,binary,log,env=self.fixture(tmp)
            self.tool(binary,'python3','exec '+shlex_quote(sys.executable)+' "$@"',log)
            root=script.parent.parent;post=root/'threshold-kms/postprocess';post.mkdir()
            (post/'requirements.txt').write_text('matplotlib==3.10.8\n')
            python=root/'threshold-kms/.cache/postprocess-python/bin/python'
            (post/'refresh.py').write_text('from pathlib import Path\ndef plotting_python():return Path('+repr(str(python))+')\n')
            marker=Path(tmp)/'plot-repaired'
            python.write_text('#!/bin/sh\nprintf "plot %s\\n" "$*" >> "$BOOTSTRAP_TEST_LOG"\n'
                'if [ "$1" = "-c" ]; then test -f '+shlex_quote(str(marker))+'; exit $?; fi\n'
                'if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then touch '+shlex_quote(str(marker))+'; fi\nexit 0\n')
            python.chmod(0o755)
            result=self.run_script(script,env,'--install')
            self.assertEqual(result.returncode,0,result.stderr)
            commands=log.read_text()
            self.assertEqual(commands.count('plot -m pip install'),1)
            self.assertIn('--force-reinstall',commands)
            self.assertTrue(marker.exists())
    def test_missing_javascript_modules_use_ci_without_rewriting_locks(self):
        with tempfile.TemporaryDirectory() as tmp:
            script,binary,log,env=self.fixture(tmp)
            # Keep Python as the harmless fixture stub: npm itself is mocked.
            self.tool(binary,'node','case "$*" in *createRequire*) test -f "$3/ready" ;; *) exit 0 ;; esac',log)
            self.tool(binary,'npm','if [ "$1" = --version ]; then exit 0; fi\ntest "$1" = --prefix && test "$3" = ci && touch "$2/ready"',log)
            root=script.parent.parent
            for name in ('fhe-pod','BN254-Signatures'):
                directory=root/name;directory.mkdir();(directory/'package-lock.json').write_text('fixture-lock\n')
            result=self.run_script(script,env,'--install')
            self.assertEqual(result.returncode,0,result.stderr)
            commands=log.read_text()
            self.assertEqual(commands.count('npm --prefix'),2)
            self.assertNotIn('npm install',commands)
            for name in ('fhe-pod','BN254-Signatures'):
                self.assertEqual((root/name/'package-lock.json').read_text(),'fixture-lock\n')



def shlex_quote(value):
    import shlex
    return shlex.quote(value)

if __name__=='__main__':unittest.main()
