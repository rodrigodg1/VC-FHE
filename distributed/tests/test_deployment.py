import json
from pathlib import Path
import sys
import unittest
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import deployment
import topology
class DeploymentTests(unittest.TestCase):
    def setUp(self):self.cfg=json.loads((HERE/'config.example.json').read_text())
    def test_original_full_grid_and_protocol_are_retained(self):
        cfg=deployment.campaign_config(self.cfg,'synthetic-test-only')
        self.assertEqual(cfg['pocPlan']['measuredPairs'],480)
        self.assertEqual(cfg['pocPlan']['fullCases'],27)
        self.assertEqual(len([j for j in cfg['pocPlan']['jobs'] if j['warmup']]),18)
        self.assertEqual(cfg['windowSeconds'],120)
        self.assertEqual(cfg['ownerReleaseLimit'],18)
        self.assertFalse(cfg['smoke'])
    def test_kms_vaults_not_mounted_by_other_roles(self):
        plans=deployment.manifests(self.cfg,'synthetic-test-only')
        self.assertEqual(len(plans),4)
        cores=[]
        for plan in plans.values():
            for name,service in plan['services'].items():
                private=[m for m in service['volumes'] if m['target']=='/private']
                if private:
                    self.assertTrue(name.endswith('-core'));self.assertEqual(len(private),1);cores.append(private[0]['source'])
                if name.startswith(('operator','auditor','adjudicator')):
                    self.assertEqual(len([m for m in service['volumes'] if m['target']=='/worker-rpc']),1)
                    self.assertNotIn('/owner',[m['target'] for m in service['volumes']])
                    self.assertNotIn('/recipient',[m['target'] for m in service['volumes']])
        self.assertEqual(len(set(cores)),4)
    def test_kms_transport_port_does_not_collide(self):
        seen=set()
        for node in topology.inventory(self.cfg):
            for port in node['ports']:
                identity=(node['host'],port)
                self.assertNotIn(identity,seen);seen.add(identity)
    def test_besu_native_libraries_have_executable_tmp_with_other_guards_retained(self):
        validators=[]
        for plan in deployment.manifests(self.cfg,'synthetic-test-only').values():
            for name,service in plan['services'].items():
                if not name.startswith('validator-'):continue
                validators.append(service)
                self.assertEqual(service['user'],'10001:10001')
                self.assertTrue(service['read_only'])
                self.assertEqual(service['cap_drop'],['ALL'])
                self.assertIn('no-new-privileges:true',service['security_opt'])
                options=service['tmpfs'][0].split(':',1)[1].split(',')
                self.assertIn('exec',options)
                self.assertNotIn('noexec',options)
                self.assertIn('nosuid',options)
                self.assertIn('nodev',options)
        self.assertEqual(len(validators),4)
if __name__=='__main__':unittest.main()
