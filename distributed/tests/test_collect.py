import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import collect as distributed_collect
import deployment


class DistributedSealTests(unittest.TestCase):
    def fixture(self,directory):
        run=Path(directory)
        def write(name,value):
            path=run/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(value))
        cfg={'half':'both','parameters':'Test','smoke':True,
             'classification':'test-insecure-distributed-smoke-not-evaluation'}
        write('config/campaign.json',cfg)
        write('state.json',{'status':'passed','config':cfg,'source':{},'datasets':{}})
        write('distributed-adapter.json',{'protocolRulesChanged':False})
        write('fixtures/prepared.json',{'fixtureOnly':True})
        write('reports/application.json',{'fixtureOnly':True})
        write('recipient/result-0.json',{'fixtureOnly':True})
        hosts=[{'id':f'host-{i}'} for i in range(1,5)]
        compose={h['id']:{'name':h['id'],'services':{}} for h in hosts}
        for host in hosts:write(f'compose/{host["id"]}/compose.json',compose[host['id']])
        identities={f'validator-{i}':{'address':'0x'+f'{i:040x}'} for i in range(1,5)}
        write('distributed/public-identities.json',identities)
        write('network/validators.json',sorted(row['address'].lower() for row in identities.values()))
        for i in range(1,5):
            write(f'validator-config/validator-{i}/genesis.json',{'config':{'chainId':46853}})
            write(f'validator-config/validator-{i}/static-nodes.json',[f'enode-{j}' for j in range(1,5)])
        module=deployment.campaign_module()
        campaign=SimpleNamespace(run=run,plan={'hosts':hosts},compose=compose,identities=identities)
        return campaign,module,cfg

    def seal(self,campaign,module,cfg,files):
        seal={'version':module.VERSION,'source':{},'files':files,
              'parameters':cfg['parameters'],'classification':cfg['classification'],
              'halves':['linear','nonlinear']}
        (campaign.run/'seal.json').write_text(json.dumps(seal))
        return seal

    def test_seals_real_distributed_descriptors_without_local_topology_placeholders(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign,module,cfg=self.fixture(directory)
            files=distributed_collect.collect_seal_files(campaign,module)
            for i in range(1,5):
                self.assertIn(f'compose/host-{i}/compose.json',files)
                self.assertIn(f'validator-config/validator-{i}/genesis.json',files)
                self.assertIn(f'validator-config/validator-{i}/static-nodes.json',files)
            self.assertIn('recipient/result-0.json',files)
            self.assertIn('state.json',files)
            self.assertIn('config/campaign.json',files)
            for name in ['compose.json','setup-compose.json','besu.json']:
                self.assertNotIn(name,files)
                self.assertFalse((campaign.run/name).exists())
            record=json.loads((campaign.run/'distributed/deployment.json').read_text())
            self.assertEqual(len(record['hosts']),4)
            self.assertEqual(len(record['validators']),4)
            references=[row['compose'] for row in record['hosts']]
            references += [row[k] for row in record['validators'] for k in ['genesis','staticPeers']]
            references += [record['validatorSet'],record['publicIdentities']]
            for ref in references:self.assertEqual(ref['sha256'],files[ref['path']])
            seal=self.seal(campaign,module,cfg,files)
            self.assertNotIn('sealPayloadSha256',seal)
            # Source lookup is the only environment-dependent input replaced.
            # The original format, file-hash and state/config checks run intact.
            with patch.object(module,'source_manifest',return_value={}):
                self.assertEqual(module.verify(campaign.run),seal)

    def test_original_verifier_rejects_tampered_distributed_compose(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign,module,cfg=self.fixture(directory)
            files=distributed_collect.collect_seal_files(campaign,module)
            self.seal(campaign,module,cfg,files)
            path=campaign.run/'compose/host-2/compose.json'
            path.write_text(path.read_text()+' ')
            with patch.object(module,'source_manifest',return_value={}):
                with self.assertRaisesRegex(ValueError,'changed/missing artifact'):
                    module.verify(campaign.run)

    def test_missing_real_host_descriptor_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign,module,cfg=self.fixture(directory)
            (campaign.run/'compose/host-4/compose.json').unlink()
            with self.assertRaises(FileNotFoundError):
                distributed_collect.collect_seal_files(campaign,module)

    def test_changed_compose_cannot_be_presented_as_launched_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign,module,cfg=self.fixture(directory)
            (campaign.run/'compose/host-1/compose.json').write_text(json.dumps({'name':'foreign','services':{}}))
            with self.assertRaisesRegex(ValueError,'differs from launched host'):
                distributed_collect.collect_seal_files(campaign,module)

    def test_disagreeing_validator_configs_are_rejected(self):
        for field in ['genesis.json','static-nodes.json']:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                campaign,module,cfg=self.fixture(directory)
                path=campaign.run/f'validator-config/validator-3/{field}'
                value={'config':{'chainId':46853},'foreign':True} if field=='genesis.json' else ['foreign-peer']
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError,'disagree on genesis or static peers'):
                    distributed_collect.collect_seal_files(campaign,module)

    def test_changed_validator_set_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign,module,cfg=self.fixture(directory)
            (campaign.run/'network/validators.json').write_text('[]')
            with self.assertRaisesRegex(ValueError,'differs from enrolled identities'):
                distributed_collect.collect_seal_files(campaign,module)


if __name__=='__main__':
    unittest.main()
