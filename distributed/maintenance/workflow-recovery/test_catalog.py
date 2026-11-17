from pathlib import Path
import importlib.util
import unittest

spec=importlib.util.spec_from_file_location('continued_catalog',Path(__file__).with_name('catalog.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class CatalogConsistency(unittest.TestCase):
    def setUp(self):
        self.names=['case-'+str(i) for i in range(27)]
        self.prepared={'keys':{'digest':'unchanged'},'owners':['unchanged'],
            'cases':[{'name':n,'fullCase':True,'ciphertextDigest':n} for n in self.names]+
                    [{'name':'paired-only-'+str(i),'fullCase':False} for i in range(471)]}
    def test_reproduce_missing_paths_in_unfiltered_manifest(self):
        self.assertTrue(any(c['name'] not in self.names for c in self.prepared['cases']))
        value=m.select_full_catalog(self.prepared,self.names,self.names)
        self.assertTrue(all(c['name'] in self.names for c in value['cases']))
        self.assertEqual(len(self.prepared['cases']),498)
        self.assertEqual(value['keys'],self.prepared['keys'])
        self.assertEqual(value['owners'],self.prepared['owners'])
        self.assertEqual(value['cases'],self.prepared['cases'][:27])
    def test_refuse_missing_full_case(self):
        with self.assertRaises(ValueError):m.select_full_catalog(self.prepared,self.names,self.names[:-1])
    def test_refuse_changed_order_or_duplicate(self):
        with self.assertRaises(ValueError):m.select_full_catalog(self.prepared,list(reversed(self.names)),self.names)
        with self.assertRaises(ValueError):m.select_full_catalog({**self.prepared,'cases':self.prepared['cases']+[self.prepared['cases'][0]]},self.names,self.names)
    def test_allow_already_filtered_catalog_without_modifying_ciphertexts(self):
        first=m.select_full_catalog(self.prepared,self.names,self.names)
        self.assertEqual(m.select_full_catalog(first,self.names,self.names),first)
    def test_remote_preparation_scripts_compile_before_any_vm_start(self):
        import ast,textwrap,inspect
        count=0
        for filename in ['prepare_next.py','prepare_third.py']:
            source=Path(__file__).with_name(filename).read_text()
            for node in ast.walk(ast.parse(source)):
                if isinstance(node,ast.Assign):
                    names=[t.id for t in node.targets if isinstance(t,ast.Name)]
                    if names==['node_prepare']:
                        value=inspect.getsource(m.select_full_catalog)+textwrap.dedent(node.value.right.args[0].value)
                    elif names==['move_scratch']:
                        value=textwrap.dedent(node.value.args[0].value)
                    else:continue
                    compile(value,names[0],'exec');count+=1
        self.assertEqual(count,4)
    def test_large_configuration_uses_file_input_with_bounded_argv(self):
        import tempfile,json,subprocess,sys
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'input.json'
            p.write_text(json.dumps({'config':{'metadata':'x'*(1024**2)},'full':self.names}))
            result=subprocess.run([sys.executable,'-c',
                "import json,sys;from pathlib import Path;v=json.loads(Path(sys.argv[1]).read_text());print(len(v['full']))",
                str(p)],check=True,capture_output=True,text=True)
            self.assertEqual(result.stdout.strip(),'27')
        source=Path(__file__).with_name('prepare_next.py').read_text()
        self.assertNotIn("'-c',node_prepare,json.dumps(info)",source)

if __name__=='__main__':unittest.main()
