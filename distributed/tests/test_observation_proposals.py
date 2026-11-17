"""Review-only changes are executed on temporary source copies, never live A9."""
import hashlib
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
sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE/'maintenance/proposals'))
import wait_proposal
import service_account_absence as sa_absence

class WaitProposalTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve();self.source=HERE/'launch.py';self.before=self.source.read_bytes()
  proposed=self.root/'launch_proposed.py';self.record=wait_proposal.write_copy(self.source,proposed)
  spec=importlib.util.spec_from_file_location('temporary_proposed_launch',proposed)
  self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
  self.c=self.module.Campaign.__new__(self.module.Campaign)
  self.c.run=self.root;self.c.base='/srv/vcfhe/example-smoke';self.c.started=100;self.c.quote={'planned_hours':1}
  self.c.nodes={n:{'host':'host-1'if n.startswith('coordinator')else'host-4','state_directory':self.c.base+'/'+n}for n in ['coordinator-1','recipient-1']}
  self.calls=[];self.codes={'coordinator-1':0,'recipient-1':0};self.fail_logs=True;self.progress='unavailable';self.missing_recipient=0;self.missing_coordinator=0;self.wrong_role=False;self.exit_payload=None
  def run(args,**kwargs):
   self.calls.append((args,kwargs))
   if 'logs'in args:
    if self.fail_logs:raise subprocess.CalledProcessError(255,args,stderr='IAP4033')
    return subprocess.CompletedProcess(args,0,stdout='logs')
   if 'tail'in args:
    if self.progress=='unavailable':raise subprocess.CalledProcessError(1,args)
    return subprocess.CompletedProcess(args,0,stdout=json.dumps(self.progress))
   if 'cat'in args:
    node=next(n for n,v in self.c.nodes.items()if args[-1]==v['state_directory']+'/reports/participant-exit.json')
    if node=='recipient-1'and self.missing_recipient:
     self.missing_recipient-=1;raise subprocess.CalledProcessError(255,args,stderr='IAP4033')
    if node=='coordinator-1'and self.missing_coordinator:
     self.missing_coordinator-=1;raise subprocess.CalledProcessError(1,args,stderr='participant exit pending')
    value=self.exit_payload if self.exit_payload is not None else {'node':node,'role':'wrong-role'if self.wrong_role else node.rsplit('-',1)[0],'exitCode':self.codes[node]}
    return subprocess.CompletedProcess(args,0,stdout=json.dumps(value))
   raise AssertionError('Unexpected protocol operation')
  self.c.remotes={h:SimpleNamespace(run=run)for h in ['host-1','host-4']}
  self.clock=patch.object(self.module.time,'monotonic',return_value=500);self.clock.start();self.addCleanup(self.clock.stop)
  self.sleep=patch.object(self.module.time,'sleep');self.sleep.start();self.addCleanup(self.sleep.stop)
 def tearDown(self):
  self.assertEqual(self.source.read_bytes(),self.before)
 def test_iap_logs_and_missing_progress_do_not_abort_zero_exit(self):
  self.c.wait()
  self.assertTrue(self.record['originalUnchanged']);self.assertFalse(self.record['appliedToOriginal'])
  self.assertEqual(self.record['originalSha256'],hashlib.sha256(self.before).hexdigest())
  self.assertTrue(all(kwargs.get('timeout',0)<=45 for _,kwargs in self.calls))
 def test_nonzero_coordinator_is_not_swallowed_by_read_exception_handler(self):
  self.codes['coordinator-1']=9
  with self.assertRaisesRegex(ValueError,'participant failed'):self.c.wait()
  self.assertEqual(sum('/recipient-1/'in str(args)for args,_ in self.calls),1)
 def test_nonzero_recipient_aborts_and_does_not_replay(self):
  self.codes['recipient-1']=1
  with self.assertRaisesRegex(ValueError,'participant failed'):self.c.wait()
  self.assertFalse(any(any(action in args for action in ['up','restart','exec','run','transaction','release'])for args,_ in self.calls))
 def test_malformed_role_and_boolean_exit_are_real_failures(self):
  self.wrong_role=True
  with self.assertRaisesRegex(ValueError,'misassigned'):self.c.wait()
  self.wrong_role=False;self.codes['coordinator-1']=False
  with self.assertRaisesRegex(ValueError,'misassigned'):self.c.wait()
 def test_valid_json_null_is_not_confused_with_transport_unavailable(self):
  self.exit_payload=[]
  with self.assertRaisesRegex(ValueError,'malformed'):self.c.wait()
 def test_recipient_read_failures_only_repeat_status_reads(self):
  self.missing_recipient=31
  self.c.wait()
  count=sum(args[-1].endswith('recipient-1/reports/participant-exit.json')for args,_ in self.calls if args and isinstance(args[-1],str))
  self.assertEqual(count,32)
  self.assertFalse(any('start-role.json'in str(args)for args,_ in self.calls))
 def test_original_deadline_cannot_be_reset_by_monitor_errors(self):
  self.c.started=0
  with patch.object(self.module.time,'monotonic',side_effect=[3599,3601]):
   with self.assertRaisesRegex(ValueError,'duration exhausted'):self.c.wait()
 def test_host_progress_write_error_does_not_mask_a_real_exit(self):
  self.progress={'phase':'active'}
  with patch.object(self.module,'write',side_effect=OSError('disk unavailable')):self.c.wait()
  self.codes['coordinator-1']=1
  with patch.object(self.module,'write',side_effect=OSError('disk unavailable')):
   with self.assertRaisesRegex(ValueError,'participant failed'):self.c.wait()
 def test_pending_coordinator_and_failed_recipient_abort_immediately_without_actions(self):
  self.missing_coordinator=1000;self.codes['recipient-1']=1
  with self.assertRaisesRegex(ValueError,'participant failed'):self.c.wait()
  self.assertEqual(len(self.calls),1)
  self.assertIn('/recipient-1/',self.calls[0][0][-1])
  self.module.time.sleep.assert_not_called()
 def test_missing_recipient_is_pending_and_zero_recipient_waits_for_coordinator(self):
  self.missing_recipient=1;self.missing_coordinator=2
  self.c.wait()
  self.assertEqual(sum('/recipient-1/'in str(args)for args,_ in self.calls),2)
  self.assertEqual(sum(args[-1].endswith('coordinator-1/reports/participant-exit.json')for args,_ in self.calls),3)
  self.assertFalse(any(any(action in args for action in ['up','restart','exec','run','transaction','release'])for args,_ in self.calls))
 def test_malformed_recipient_status_fails_closed_while_coordinator_pending(self):
  self.missing_coordinator=1000;self.codes['recipient-1']=None
  with self.assertRaisesRegex(ValueError,'malformed'):self.c.wait()
  self.assertEqual(len(self.calls),1)
  self.module.time.sleep.assert_not_called()

class ServiceAccountPollProposalTests(unittest.TestCase):
 def setUp(self):
  self.row={'type':'google_service_account','identity':{'uniqueId':'12345'},'attributes':{'email':'node@example-project.iam.gserviceaccount.com'}}
  self.live={'uniqueId':'12345','email':self.row['attributes']['email']}
  self.now=0
  self.clock=lambda:self.now
  self.pause=lambda seconds:setattr(self,'now',self.now+seconds)
 def test_same_id_staleness_repeats_only_reads_until_absent(self):
  reader=Mock(side_effect=[self.live,self.live,None])
  result=sa_absence.confirm_absence({},self.row,reader,clock=self.clock,pause=self.pause)
  self.assertEqual(result,{'status':'absent','attempts':3,'deletionRetried':False})
  self.assertEqual(reader.call_count,3)
 def test_permission_denial_is_never_absence_or_retry(self):
  reader=Mock(side_effect=ValueError('PERMISSION_DENIED'))
  with self.assertRaisesRegex(ValueError,'PERMISSION_DENIED'):sa_absence.confirm_absence({},self.row,reader,clock=self.clock,pause=self.pause)
  self.assertEqual(reader.call_count,1);self.assertEqual(self.now,0)
 def test_replacement_is_refused_without_waiting(self):
  for changed in [dict(self.live,uniqueId='99999'),dict(self.live,email='foreign@example.test')]:
   reader=Mock(return_value=changed)
   with self.assertRaisesRegex(ValueError,'identity changed'):sa_absence.confirm_absence({},self.row,reader,clock=self.clock,pause=self.pause)
   self.assertEqual(reader.call_count,1)
 def test_polling_window_is_bounded_and_has_no_mutation_callback(self):
  reader=Mock(return_value=self.live)
  with self.assertRaises(TimeoutError):sa_absence.confirm_absence({},self.row,reader,timeout_seconds=5,clock=self.clock,pause=self.pause)
  self.assertLessEqual(self.now,5);self.assertLessEqual(reader.call_count,4)
 def test_incomplete_identity_or_extended_bound_is_rejected_before_read(self):
  reader=Mock()
  with self.assertRaises(ValueError):sa_absence.confirm_absence({},dict(self.row,identity={}),reader)
  with self.assertRaises(ValueError):sa_absence.confirm_absence({},self.row,reader,timeout_seconds=46)
  reader.assert_not_called()

if __name__=='__main__':unittest.main()
