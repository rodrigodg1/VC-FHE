"""The controller uses the existing Linux correction without modifying sources."""
from pathlib import Path
import copy,json,os,subprocess,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results import controller_js
from cloud_results.common import write,sha
from cloud_results.cli import controller_script

class ControllerLinuxJsTests(unittest.TestCase):
    def raw(self):
        return (json.dumps({'packages':{controller_js.ENTRY:{'version':'2.3.2','os':['darwin'],
            'extraneous':True,'integrity':'synthetic-fixed-integrity'}}},indent=2)+'\n').encode()
    def test_only_the_reviewed_optional_flag_changes(self):
        raw=self.raw();adapted,changed=controller_js.linux_lock(raw);self.assertTrue(changed)
        x=json.loads(adapted);self.assertIs(x['packages'][controller_js.ENTRY].pop('optional'),True)
        self.assertEqual((json.dumps(x,indent=2)+'\n').encode(),raw)
    def test_other_locks_remain_byte_identical(self):
        raw=b'{"packages":{}}\n';self.assertEqual(controller_js.linux_lock(raw),(raw,False))
    def test_unreviewed_version_or_platform_is_refused(self):
        for field,value in [('version','9.0.0'),('os',['linux']),('extraneous',False)]:
            x=json.loads(self.raw());x['packages'][controller_js.ENTRY][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):controller_js.linux_lock(json.dumps(x).encode())
    def test_install_is_isolated_and_original_lock_stays_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repo';project=root/'fhe-pod';project.mkdir(parents=True)
            (project/'package-lock.json').write_bytes(self.raw());write(project/'package.json',{'name':'synthetic-controller'})
            build=Path(tmp)/'build';write(build/'distributed-source.json',{'localSource':{f'fhe-pod/{n}':sha(project/n) for n in ['package.json','package-lock.json']}})
            cache=Path(tmp)/'cache';report=Path(tmp)/'report.local.json';calls=[]
            def invoke(args,**kwargs):
                calls.append(args)
                if args[0]=='npm':
                    target=Path(args[2]);(target/'node_modules').mkdir();write(target/'node_modules/.package-lock.json',{'synthetic':'installed'})
            original=sha(project/'package-lock.json')
            with patch.object(controller_js.subprocess,'run',side_effect=invoke):
                controller_js.install(root,build,project,cache,report)
                controller_js.install(root,build,project,cache,report)
            self.assertEqual(sha(project/'package-lock.json'),original);self.assertTrue((project/'node_modules').is_symlink())
            self.assertEqual(sum(c[0]=='npm' for c in calls),1)
            self.assertFalse(read_json(report)['projects']['fhe-pod']['versionsChanged'])
    def test_failed_install_cannot_create_a_success_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repo';project=root/'fhe-pod';project.mkdir(parents=True)
            (project/'package-lock.json').write_bytes(self.raw());write(project/'package.json',{})
            build=Path(tmp)/'build';write(build/'distributed-source.json',{'localSource':{f'fhe-pod/{n}':sha(project/n) for n in ['package.json','package-lock.json']}})
            cache=Path(tmp)/'cache'
            with patch.object(controller_js.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['npm'])):
                with self.assertRaises(subprocess.CalledProcessError):controller_js.install(root,build,project,cache,Path(tmp)/'report')
            self.assertFalse(list(cache.rglob('complete.local.json')));self.assertFalse((project/'node_modules').exists())
    def test_rendered_wrapper_is_valid_bash_and_preserves_quoting(self):
        script=controller_script('/synthetic/path with spaces')
        result=subprocess.run(['/bin/bash','-n'],input=script,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('"${1:-}"',script);self.assertIn('else command npm "$@"',script)
        self.assertNotIn('\\"',script)
    def test_actual_wrapper_intercepts_only_locked_installation(self):
        with tempfile.TemporaryDirectory(prefix='controller test ') as tmp:
            base=Path(tmp);root=base/'job with spaces';repo=root/'input/repository/VC-FHE'
            (repo/'distributed').mkdir(parents=True);tools=base/'bin';tools.mkdir();log=base/'commands'
            (repo/'distributed/controller-bootstrap.sh').write_text(
                'npm --version >/dev/null\nnpm --prefix "'+str(repo/'fhe-pod')+'" ci --ignore-scripts\n')
            for name,body in [('python3','printf "%s\\n" "$@" >> "$WRAPPER_TEST_LOG"'),
                              ('npm','test "$1" = --version || exit 91')]:
                file=tools/name;file.write_text('#!/bin/sh\n'+body+'\n');file.chmod(0o755)
            worker=repo/'threshold-kms/.cache/postprocess-python/bin/python';worker.parent.mkdir(parents=True)
            worker.write_text('#!/bin/sh\nexit 0\n');worker.chmod(0o755)
            result=subprocess.run(['/bin/bash','-c',controller_script(str(root))],text=True,capture_output=True,
                env={**os.environ,'PATH':str(tools)+os.pathsep+os.environ['PATH'],'WRAPPER_TEST_LOG':str(log)})
            self.assertEqual(result.returncode,0,result.stderr)
            arguments=log.read_text().splitlines()
            self.assertEqual(arguments[-2:],['--project',str(repo/'fhe-pod')])
            self.assertEqual(arguments[0],str(repo/'distributed/cloud_results/controller_js.py'))

def read_json(path):return json.loads(Path(path).read_text())
if __name__=='__main__':unittest.main()
