"""No cloud or protocol actions. Tests exercise the original wait via strict proxies."""
from datetime import datetime,timezone,timedelta
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('observe_running',HERE/'maintenance/observe_running.py')
observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)

class WaitObservationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve();self.output=self.root/'derived';self.output.mkdir(mode=0o700)
  self.node_roots={'coordinator-1':'/srv/vcfhe/example-smoke/coordinator-1','recipient-1':'/srv/vcfhe/example-smoke/recipient-1'}
  self.o=observer.Observer.__new__(observer.Observer)
  self.o.config={'campaign':'example-smoke'};self.o.base='/srv/vcfhe/example-smoke'
  self.o.nodes={n:{'role':n.rsplit('-',1)[0],'host':'host-1' if n.startswith('coordinator') else 'host-4','state_directory':p}for n,p in self.node_roots.items()}
  self.o.guard=Mock();self.o.remaining=Mock(return_value=3600);self.o.monitor_error=Mock();self.o.exits={}
  self.o.output=self.output;self.o.plan={'nodes':[]};self.o.container_names=Mock(return_value=[])
  self.calls=[];self.codes={'coordinator-1':0,'recipient-1':0};self.log_fail=True;self.bad_node=False;self.missing=0
  def remote(host):
   result=observer.ReadOnlyRemote(self.o,{'id':host})
   result.remote=Mock()
   def run(args,**kwargs):
    self.calls.append(args)
    if 'logs'in args:
     if self.log_fail:raise subprocess.CalledProcessError(255,args)
     return subprocess.CompletedProcess(args,0,stdout='logs')
    if 'tail'in args:raise subprocess.CalledProcessError(1,args)
    if 'cat'in args:
     if self.missing:
      self.missing-=1;raise subprocess.CalledProcessError(255,args)
     node=next(n for n,p in self.node_roots.items()if args[-1]==p+'/reports/participant-exit.json')
     return subprocess.CompletedProcess(args,0,stdout=json.dumps({'node':'another-node'if self.bad_node else node,'role':self.o.nodes[node]['role'],'exitCode':self.codes[node]}))
    raise AssertionError('Unexpected remote action')
   result.remote.run.side_effect=run
   return result
  self.remotes={h:remote(h)for h in ['host-1','host-4']}
  self.o.remotes=self.remotes
  self.c=observer.launch.Campaign.__new__(observer.launch.Campaign)
  self.c.nodes=self.o.nodes;self.c.remotes=self.remotes;self.c.base=self.o.base
  self.c.run=self.output;self.c.started=time.monotonic();self.c.quote={'planned_hours':1}
 def test_logs_and_progress_transport_failures_cannot_fail_a_successful_application(self):
  observer.launch.Campaign.wait(self.c)
  self.assertEqual(set(self.o.exits),{'coordinator-1','recipient-1'})
  self.assertTrue(self.o.monitor_error.called)
  self.assertTrue(all('up'not in args and 'run'not in args and 'exec'not in args for args in self.calls))
 def test_true_coordinator_failure_is_not_converted_to_monitor_failure(self):
  self.codes['coordinator-1']=7
  with self.assertRaises(observer.ProtocolFailure):observer.launch.Campaign.wait(self.c)
  self.assertEqual(self.o.exits['recipient-1']['exitCode'],0)
 def test_true_recipient_failure_and_signal_exit_are_not_masked(self):
  for code in [3,None,True]:
   self.codes['recipient-1']=code
   with self.assertRaises(observer.ProtocolFailure):observer.launch.Campaign.wait(self.c)
 def test_foreign_exit_record_is_never_success(self):
  self.bad_node=True
  with self.assertRaises(observer.ProtocolFailure):observer.launch.Campaign.wait(self.c)
 def test_missing_exit_reports_are_observation_reads_only(self):
  self.missing=2
  with patch.object(observer.launch.time,'sleep'):
   observer.launch.Campaign.wait(self.c)
  self.assertEqual(len(self.o.exits),2)
  self.assertFalse(any('transaction'in str(c)or 'release'in str(c)for c in self.calls))
 def test_mutating_commands_are_rejected_before_transport(self):
  for command in [['sudo','docker','compose','up','-d'],['sudo','touch','/config/start-role.json'],['curl','-X','POST','https://role/transaction'],['sudo','docker','restart','role']]:
   with self.assertRaises(ValueError):self.remotes['host-1'].run(command)
  self.assertFalse(self.calls)
 def test_parent_resume_or_original_file_change_stops_before_network(self):
  self.o.guard.side_effect=ValueError('parent resumed')
  with self.assertRaises(ValueError):self.remotes['host-1'].json(['sudo','cat',self.node_roots['coordinator-1']+'/reports/participant-exit.json'])
  self.assertFalse(self.calls)
 def test_deadline_is_original_creation_plus_six_hours(self):
  self.assertEqual(observer.deadline('2026-10-27T20:44:24+00:00','6'),datetime(2026,10,28,2,44,24,tzinfo=timezone.utc))
  self.o.expires=datetime.now(timezone.utc)-timedelta(seconds=1)
  with self.assertRaises(observer.ObservationDeadline):observer.Observer.remaining(self.o)
 def test_campaign_reconstruction_never_calls_initializer_or_mutates_original_state(self):
  for name,value in {'quote':{'planned_hours':'6'},'record':{'original':True},'compose':{},'identities':{},'datasets':{},'started':123,
                     'state':{'status':'failed','stages':[{'name':'Full evaluation','status':'failed'}]}}.items():setattr(self.o,name,value)
  with patch.object(observer.launch.Campaign,'__init__',side_effect=AssertionError('initializer forbidden')):
   c=self.o.campaign()
  self.assertEqual(c.state,self.o.state);self.assertIsNot(c.state,self.o.state)
  c.state['stages'][0]['status']='changed-only-copy'
  self.assertEqual(self.o.state['stages'][0]['status'],'failed')
  self.assertEqual(c.run,self.output)
 def test_outer_observer_records_protocol_failure_without_collecting_or_rewriting_launch(self):
  self.o.preflight=Mock();self.o.campaign=Mock(return_value=self.c);self.o.report={'status':'prepared'}
  original=self.root/'launch-state.json';original.write_text('{"status":"failed"}')
  before=original.read_bytes()
  with patch.object(observer.launch.Campaign,'wait',side_effect=observer.ProtocolFailure('real operator failure')):
   with self.assertRaises(observer.ProtocolFailure):self.o.wait()
  self.assertEqual(original.read_bytes(),before)
  self.assertEqual(json.loads((self.output/'observation.local.json').read_text())['status'],'failed-observation')
  self.assertFalse((self.output/'state.json').exists())

if __name__=='__main__':unittest.main()
