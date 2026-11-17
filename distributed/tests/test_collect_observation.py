"""Derived collector safeguards. Every remote operation and validator is mocked."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE/'maintenance'))
import collect_observation as collector

class DerivedCollectionTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve();self.output=self.root/'derived'/'original-run';self.output.mkdir(parents=True,mode=0o700)
  self.original=self.root/'original-run';self.original.mkdir(mode=0o700)
  self.original_state=self.original/'launch-state.json';self.original_state.write_text('{"status":"failed"}')
  self.exits={n:{'node':n,'role':n.rsplit('-',1)[0],'exitCode':0}for n in ['coordinator-1','recipient-1']}
  self.report={'status':'participants-exited-zero','participantExits':self.exits}
  self.o=SimpleNamespace(config={'images':{'campaign':'example.test/image@sha256:'+'a'*64}},
      base='/srv/vcfhe/example-smoke',plan={'hosts':[{'id':'host-1'}],'nodes':[{'id':'coordinator-1','host':'host-1','state_directory':'/srv/vcfhe/example-smoke/coordinator-1'}]},
      remaining=Mock(return_value=3600),guard=Mock(),original=self.original)
  self.c=collector.Collector.__new__(collector.Collector);self.c.output=self.output;self.c.observer=self.o;self.c.guard=Mock()
  self.remote=collector.CollectionRemote(self.c,{'id':'host-1'});self.remote.native=Mock()
 def test_only_both_exact_zero_exits_allow_collection(self):
  collector.require_zero(self.report)
  for code in [1,None,True]:
   bad=json.loads(json.dumps(self.report));bad['participantExits']['coordinator-1']['exitCode']=code
   with self.assertRaises(ValueError):collector.require_zero(bad)
  bad=json.loads(json.dumps(self.report));bad['status']='failed-observation'
  with self.assertRaises(ValueError):collector.require_zero(bad)
  bad=json.loads(json.dumps(self.report));bad['participantExits'].pop('recipient-1')
  with self.assertRaises(ValueError):collector.require_zero(bad)
 def test_protocol_and_role_lifecycle_commands_are_refused(self):
  for args in [['sudo','docker','start','role'],['sudo','docker','restart','role'],['sudo','docker','compose','up','-d'],
               ['sudo','touch','/srv/vcfhe/example-smoke/coordinator-1/config/start-role.json'],['curl','-X','POST','https://node/transaction'],
               ['python3','-c','run_release()']]:
   with self.assertRaises(ValueError):self.remote.run(args)
  self.remote.native.run.assert_not_called()
 def test_only_a_new_unstarted_image_holder_may_be_removed(self):
  holder='a'*64
  self.remote.native.run.return_value=subprocess.CompletedProcess([],0,stdout=holder+'\n')
  self.assertEqual(self.remote.text(['sudo','docker','create',self.o.config['images']['campaign']]),holder)
  self.assertIn(holder,self.remote.holders)
  with self.assertRaises(ValueError):self.remote.run(['sudo','docker','start',holder])
  with self.assertRaises(ValueError):self.remote.run(['sudo','docker','rm','b'*64])
  self.remote.run(['sudo','docker','rm',holder]);self.assertNotIn(holder,self.remote.holders)
 def test_image_copy_is_restricted_to_fixed_binary_sources_and_export_targets(self):
  holder='a'*64;self.remote.holders.add(holder)
  self.remote.native.run.return_value=subprocess.CompletedProcess([],0)
  self.remote.run(['sudo','docker','cp',holder+':/usr/local/bin/kms-campaign',self.remote.extract+'/bin/kms-campaign'])
  for source,target in [(holder+':/private/shares',self.remote.extract+'/bin/kms-campaign'),
                        (holder+':/usr/local/bin/kms-campaign','/srv/vcfhe/another-run/private/key')]:
   with self.assertRaises(ValueError):self.remote.run(['sudo','docker','cp',source,target])
 def test_export_cannot_download_private_keys_or_write_original_run(self):
  with self.assertRaises(ValueError):self.remote.download(self.o.base+'/coordinator-1',['identity/key'],self.output)
  with self.assertRaises(ValueError):self.remote.download(self.o.base+'/coordinator-1',['reports'],self.original)
  self.remote.native.run.assert_not_called()
 def test_readonly_profile_and_sampler_stop_cannot_be_generalized(self):
  self.remote.native.run.return_value=subprocess.CompletedProcess([],0,stdout='{}')
  self.remote.json(['python3','-c',collector.PROFILE_SCRIPT])
  self.remote.run(['sudo','touch',self.o.base+'/host-1/stop-sampler'])
  with self.assertRaises(ValueError):self.remote.run(['sudo','touch',self.o.base+'/host-4/stop-sampler'])
 def test_parent_and_descriptor_guards_run_before_each_export_command(self):
  self.c.guard.side_effect=ValueError('parent resumed or descriptor changed')
  with self.assertRaises(ValueError):self.remote.run(['sudo','touch',self.o.base+'/host-1/stop-sampler'])
  self.remote.native.run.assert_not_called()
 def test_descriptor_copy_is_byte_exact_and_never_overwrites(self):
  source=self.original/'descriptor.json';source.write_bytes(b'{"runId":"original-run"}\r\n')
  destination=self.output/'config'/'descriptor.json';collector.copy_exact(source,destination)
  self.assertEqual(source.read_bytes(),destination.read_bytes())
  with self.assertRaises(ValueError):collector.copy_exact(source,destination)
  link=self.original/'escape.json';link.symlink_to(source)
  with self.assertRaises(ValueError):collector.copy_exact(link,self.output/'escape.json')
 def test_original_collector_failure_cannot_become_validated_or_rewrite_failed_launch(self):
  self.o.nodes={n:{'host':'host-1','state_directory':self.o.base+'/'+n}for n in self.exits};self.o.exits=self.exits
  fake_remote=Mock();fake_remote.json.side_effect=[self.exits['coordinator-1'],self.exits['recipient-1']]
  self.o.remotes={'host-1':fake_remote};self.o.campaign=Mock(return_value=SimpleNamespace())
  self.c.copy_roots=[];self.c.descriptors={};self.c.report={'status':'prepared'}
  fake_module=SimpleNamespace(collect=Mock(side_effect=ValueError('original verifier rejects execution')))
  fake_spec=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
  before=self.original_state.read_bytes()
  with patch.object(collector.importlib.util,'spec_from_file_location',return_value=fake_spec),patch.object(collector.importlib.util,'module_from_spec',return_value=fake_module):
   with self.assertRaisesRegex(ValueError,'original verifier rejects'):self.c.collect()
  self.assertEqual(self.original_state.read_bytes(),before)
  self.assertEqual(json.loads((self.output/'derived-collection.local.json').read_text())['status'],'failed-derived-collection')
  self.assertFalse((self.output/'seal.json').exists())

if __name__=='__main__':unittest.main()
