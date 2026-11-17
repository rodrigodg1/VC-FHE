import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import configure
import launch
import topology
from remote import Remote
from supplement import summarize_transport

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.cfg=json.loads((HERE/'config.example.json').read_text())
        self.nodes=topology.inventory(self.cfg)
        self.identities={n['id']:{'node':n['id'],'host':n['host'],'address':'0x'+f'{i+1:040x}',
            'fingerprint256':f'{i+1:064x}','certificate':'SYNTHETIC PUBLIC CERTIFICATE',
            'binarySha256':'a'*64,'setupPublicKey':'02'+'b'*64} for i,n in enumerate(self.nodes)}
    def test_public_configuration_contains_no_participant_private_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'config'
            result=configure.render(self.cfg,self.identities,'0x'+'1'*64,out,'fixture-only')
            self.assertFalse(result['privateKeysWritten'])
            self.assertEqual(len(list(out.iterdir())),21)
            for i in range(1,5):
                cfg=json.loads((out/f'owner-{i}/role.json').read_text())
                self.assertEqual(cfg['ownerIndex'],i-1)
                self.assertEqual(cfg['genesisHash'],'0x'+'1'*64)
                for peer in cfg['peers']:
                    self.assertEqual('transaction' in peer['operations'],peer['node']=='coordinator-1')
            core=(out/'kms-4/core-4.toml').read_text()
            self.assertIn('my_id = 4',core)
            self.assertEqual(core.count('[[threshold.peers]]'),4)
    def test_identity_alias_and_changed_binary_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.identities['owner-2']['address']=self.identities['owner-1']['address']
            with self.assertRaises(ValueError):configure.render(self.cfg,self.identities,'0x'+'1'*64,Path(tmp)/'a','t')
            self.identities['owner-2']['address']='0x'+'a'*40
            self.identities['kms-1']['binarySha256']='b'*64
            with self.assertRaises(ValueError):configure.render(self.cfg,self.identities,'0x'+'1'*64,Path(tmp)/'b','t')
    def test_unconfigured_launch_rejected_before_any_command(self):
        with patch('subprocess.run') as call:
            with self.assertRaises(ValueError):launch.check_launch(self.cfg,{},'/missing')
            call.assert_not_called()
    def test_evidence_export_rejects_private_vaults_before_network(self):
        remote=Remote(self.cfg,topology.hosts(self.cfg)[0])
        with patch.object(remote,'run') as call:
            for name in ['identity/signing.hex','private/key','../secret','/etc/passwd','policy-state/deployment.json']:
                with self.assertRaises(ValueError):remote.download('/srv/test',[name],'/unused')
            call.assert_not_called()
    def test_rpc_times_and_json_bytes_are_not_relabelled_as_wire_bytes(self):
        roles={n['id']:n for n in self.nodes}
        row={'kind':'role_transport','node':'coordinator-1','host':'host-1','target':'auditor-1',
            'id':'sample','requestJsonBytes':10,'responseJsonBytes':20,'elapsedSeconds':1.5}
        result=summarize_transport([row],roles)
        self.assertTrue(result[0]['cross_host']);self.assertEqual(result[0]['roundTripSeconds'],1.5)
        with self.assertRaises(ValueError):summarize_transport([row,row],roles)
        row['elapsedSeconds']=float('nan')
        with self.assertRaises(ValueError):summarize_transport([row],roles)

if __name__=='__main__':unittest.main()
