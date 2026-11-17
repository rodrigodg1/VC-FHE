"""Mocked exact empty-directory cleanup. No containers or cloud are touched."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock

HERE=Path(__file__).resolve().parents[1]
PROPOSAL=HERE/'maintenance/transport_proposal'
sys.path.insert(0,str(PROPOSAL));sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('isolated_wan_probe',PROPOSAL/'wan_probe.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class EmptyProbeParentTests(unittest.TestCase):
 def setUp(self):
  self.remote=Mock();self.remote.run.return_value=subprocess.CompletedProcess([],0,stdout='',stderr='')
  self.path='/srv/vcfhe/maintenance-probes/transport-probe-0123456789ab'
 def test_parent_removed_only_after_unique_child_absence_and_without_recursion(self):
  probe.remove_empty_probe_parent(self.remote,self.path)
  args=[c.args[0]for c in self.remote.run.call_args_list]
  self.assertEqual(args,[['sudo','test','!','-e',self.path],['sudo','rmdir','--','/srv/vcfhe/maintenance-probes'],['sudo','test','!','-e','/srv/vcfhe/maintenance-probes']])
  self.assertFalse(any('-r'in a or '-rf'in a for a in args))
 def test_existing_unique_child_prevents_parent_removal(self):
  self.remote.run.side_effect=subprocess.CalledProcessError(1,['test'])
  with self.assertRaises(subprocess.CalledProcessError):probe.remove_empty_probe_parent(self.remote,self.path)
  self.assertEqual(self.remote.run.call_count,1)
 def test_nonempty_or_symlink_parent_failure_is_not_swallowed(self):
  self.remote.run.side_effect=[subprocess.CompletedProcess([],0),subprocess.CalledProcessError(1,['rmdir'])]
  with self.assertRaises(subprocess.CalledProcessError):probe.remove_empty_probe_parent(self.remote,self.path)
  self.assertEqual(self.remote.run.call_count,2)
 def test_foreign_or_traversal_path_is_rejected_before_network(self):
  for path in ['/srv/vcfhe/campaign/private','/srv/vcfhe/maintenance-probes/../private',self.path+'/child']:
   with self.assertRaises(ValueError):probe.remove_empty_probe_parent(self.remote,path)
  self.remote.run.assert_not_called()

if __name__=='__main__':unittest.main()
