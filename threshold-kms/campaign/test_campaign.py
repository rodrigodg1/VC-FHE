import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('campaign',HERE/'run.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)
profile_spec=importlib.util.spec_from_file_location('profile_adapter',HERE/'build-profile.py')
profile_adapter=importlib.util.module_from_spec(profile_spec);profile_spec.loader.exec_module(profile_adapter)

class CampaignTests(unittest.TestCase):
    def test_verify_dispatches_legacy_v1_without_using_current_source_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            run=Path(temporary);(run/'seal.json').write_text(json.dumps({
                'version':'dataset-threshold-campaign-v1'}))
            with patch('legacy_v1_seal.verify',return_value={'version':'dataset-threshold-campaign-v1'}) as legacy, \
                 patch.object(campaign,'source_manifest',side_effect=AssertionError('V1 used current source')):
                self.assertEqual(campaign.verify(run)['version'],'dataset-threshold-campaign-v1')
                legacy.assert_called_once()
            (run/'seal.json').write_text(json.dumps({'version':'dataset-threshold-campaign-v2'}))
            with self.assertRaisesRegex(ValueError,'unsupported campaign seal version'):
                campaign.verify(run)

    def test_largest_test_readiness_requires_explicit_insecure_smoke(self):
        for argv in [['--poc-readiness'],['--poc-readiness','--smoke'],['--poc-readiness','--fhe-params','Test','--allow-insecure-test']]:
            with self.assertRaisesRegex(ValueError,'requires'):campaign.selection(campaign.parser().parse_args(argv))
        args=campaign.parser().parse_args(['--poc-readiness','--smoke','--fhe-params','Test','--allow-insecure-test'])
        selected=campaign.selection(args)
        self.assertEqual(selected['records'],50);self.assertEqual(selected['linearSizes'],[27]);self.assertEqual(selected['repeats'],1)
        self.assertEqual(selected['windowSeconds'],120);self.assertTrue(selected['readinessOnly'])
        self.assertEqual(selected['disclosureBatchSize'],64)
        self.assertEqual(selected['classification'],'test-insecure-readiness-not-evaluation')
    def test_internal_mpc_thread_limits_are_explicit_and_positive(self):
        try:
            import tomllib
        except ModuleNotFoundError:  # Python 3.10 in the supported WSL test host.
            import tomli as tomllib
        for threads in [1,2,4]:
            cfg=tomllib.loads(campaign.core_config(1,threads,1))
            self.assertEqual(cfg['internal_config'],{'num_rayon_threads':threads,'num_tokio_threads':1})
            self.assertEqual(cfg['threshold']['threshold'],1)
            self.assertEqual(len(cfg['threshold']['peers']),4)
        for rayon,tokio in [(0,1),(1,0),(-1,1)]:
            with self.assertRaisesRegex(ValueError,'positive'):campaign.core_config(1,rayon,tokio)
        with patch('sys.argv',['run.py','--kms-tokio-threads','0','--list']),self.assertRaisesRegex(ValueError,'resource limits'):
            campaign.main()
    def test_workload_filter_is_only_a_labelled_readiness_tool(self):
        for argv in [['--readiness-workload','regional'],['--poc-readiness','--half','linear','--readiness-workload','regional']]:
            with self.assertRaisesRegex(ValueError,'nonlinear --poc-readiness'):
                campaign.selection(campaign.parser().parse_args(argv))
        selected=campaign.selection(campaign.parser().parse_args(['--half','nonlinear','--poc-readiness','--smoke','--fhe-params','Test','--allow-insecure-test','--readiness-workload','regional']))
        self.assertEqual(selected['nonlinearWorkloads'],['regional'])
        self.assertEqual(selected['auditorFunding'],'deployed-challenge-bond-v1')
        self.assertEqual(selected['records'],50);self.assertEqual(selected['windowSeconds'],120)
    def test_besu_and_adminless_policy_start_before_kms_and_application_roles(self):
        run=Path('/exact/run');compose=['docker','compose','-f',str(run/'compose.json')]
        stages=campaign.infrastructure_stages(run,compose);names=[name for name,_ in stages]
        self.assertEqual(names[:6],['besu','identities','release-policy','kms-cores','prss','dkg'])
        self.assertLess(names.index('release-policy'),names.index('kms-cores'))
        for name in ['owner-start','worker-start','recipient-start']:
            self.assertGreater(names.index(name),names.index('release-policy'))
        for name in ['identities','kms-cores','prss','dkg']:
            cmd=dict(stages)[name];self.assertEqual(cmd[3],str(run/'setup-compose.json'))
        self.assertEqual(dict(stages)['release-policy'],compose+['run','--rm','policy-init'])
        for _,cmd in stages:
            for forbidden in ['down','--volumes','--force-recreate']:self.assertNotIn(forbidden,cmd)
        reused=campaign.infrastructure_stages(run,compose,True);reused_names=[name for name,_ in reused]
        self.assertNotIn('prss',reused_names);self.assertNotIn('dkg',reused_names)
    def test_secure_default_and_explicit_halves(self):
        for half in ['linear','nonlinear','both']:
            args=campaign.parser().parse_args(['--half',half]);self.assertEqual(args.half,half)
            self.assertEqual(args.fhe_params,'Default');self.assertFalse(args.allow_insecure_test)
    def test_keyset_base_is_default_only_and_never_a_test_shortcut(self):
        base=Path('/sealed/default-base')
        args=campaign.parser().parse_args(['--keyset-base',str(base)])
        campaign.validate_execution_profile(args)
        for argv in [['--keyset-base',str(base),'--fhe-params','Test'],
                     ['--keyset-base',str(base),'--smoke'],
                     ['--keyset-base',str(base),'--poc','--fhe-params','Test','--allow-insecure-test']]:
            with self.assertRaisesRegex(ValueError,'keyset-base'):
                campaign.validate_execution_profile(campaign.parser().parse_args(argv))
    def test_test_parameter_cannot_publish_or_silently_downgrade(self):
        for argv in [['--fhe-params','Test','--list'],['--fhe-params','Test','--smoke','--list']]:
            with patch('sys.argv',['run.py',*argv]),self.assertRaisesRegex(ValueError,'Test requires'):campaign.main()
    def test_public_query_does_not_depend_on_private_records(self):
        self.assertEqual(campaign.parser().parse_args([]).target_cell,474859250)
        for value in [-1,648000000]:
            with patch('sys.argv',['run.py','--target-cell',str(value),'--list']),self.assertRaisesRegex(ValueError,'outside the admitted grid'):
                campaign.main()
    def test_timeout_accounts_for_real_chain_windows_before_starting(self):
        with patch('sys.argv',['run.py','--timeout','14400']),self.assertRaisesRegex(ValueError,'cumulative nonlinear phase-clock allowance'):
            campaign.main()
    def test_timeout_cleanup_targets_only_own_oneshots(self):
        with tempfile.TemporaryDirectory() as temp:
            compose=Path(temp)/'compose.json';campaign.write(compose,{'name':'owned-run'})
            with patch.object(campaign,'output',return_value='abc\ndef'),patch.object(campaign,'command') as cmd:
                campaign.stop_oneshots(compose)
                cmd.assert_called_once_with(['docker','stop','--time','15','abc','def'],stdout=campaign.subprocess.DEVNULL)
    def test_administrative_guard_precedes_request_consumption(self):
        source='        async fn new_mpc_epoch(&self, request: Request<X>) -> Result<Response<X>, Status> {\nlet inner = request.into_inner();\n}'
        guarded=profile_adapter.at_method(source,'new_mpc_epoch',profile_adapter.administrative_guard('new_mpc_epoch'))
        self.assertLess(guarded.index('verify_prehash'),guarded.index('request.into_inner'))
        self.assertIn('setup-public.hex',guarded);self.assertNotIn('setup-identity/signing.hex',guarded)
        self.assertIn('insecure_key_gen',profile_adapter.DISABLED_METHODS)
        self.assertIn('new_mpc_context',profile_adapter.DISABLED_METHODS)
        self.assertIn('custodian_recovery_init',profile_adapter.DISABLED_METHODS)
        self.assertFalse(set(profile_adapter.SETUP_METHODS)&set(profile_adapter.DISABLED_METHODS))
    def test_onchain_release_guards_precede_mpc_and_result_access(self):
        cases={
            'USER_DECRYPT_REQUEST':'authorize_user_decrypt',
            'USER_DECRYPT_RESULT':'authorize_user_decryption_result',
        }
        for operation,function in cases.items():
            marker=f'            METRICS.increment_request_counter(OP_{operation});'
            guarded=profile_adapter.once(marker,marker,profile_adapter.onchain_guard(operation)+marker)
            self.assertLess(guarded.index(function),guarded.index('METRICS.increment_request_counter'))
            self.assertIn('request.get_ref()',guarded)
            self.assertNotIn('gateway',guarded.lower())
            self.assertNotIn('metadata()',guarded)
        with self.assertRaisesRegex(ValueError,'unsupported'):
            profile_adapter.onchain_guard('PUBLIC_DECRYPT_REQUEST')
    def test_onchain_release_helper_binds_exact_request_and_explicit_block(self):
        source=profile_adapter.onchain_release_source()
        for required in ['/config/release-policy.json','VCFHE_POLICY_RPC_URLS',
                         '/private/release-policy-consumed','create_new(true)',
                         'file.sync_all()','sync_directory(directory)',
                         'vcfhe-release-policy-config-v3','genesis_block_hash',
                         'deployment_block_hash','last_verified_block_hash',
                         'require_anchored_block',
                         'isSubmitAuthorized((bytes32,bytes32,bytes32',
                         'isResultAuthorized(bytes32,bytes32,bytes32)',
                         'serde_json::to_vec(request_id_message)','serde_json::to_vec(request)',
                         'eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call',
                         'runtime_code_hash','hash_bytes(&code)','EXPECTED_POLICY_VERSION',
                         'policy_domain','domain_separator']:
            self.assertIn(required,source)
        self.assertIn('json!([config.contract.as_str(), block.as_str()])',source)
        self.assertIn('json!([{"to":config.contract.as_str(), "data":calldata}, block.as_str()])',source)
        calldata_guard=source.split('async fn authorize_calldata',1)[1].split(
            'pub(super) async fn authorize_user_decrypt',1)[0]
        self.assertLess(calldata_guard.index('if !allowed'),
                        calldata_guard.index('let confirmed = quorum_rpc'))
        submit_guard=source.split('pub(super) async fn authorize_user_decrypt',1)[1].split(
            'pub(super) async fn authorize_user_decryption_result',1)[0]
        self.assertLess(submit_guard.index('authorize_calldata('),
                        submit_guard.index('consume_submit_authorization('))
        self.assertLess(submit_guard.index('authorize_calldata('),
                        submit_guard.index('verify_workflow_before_release('))
        self.assertLess(submit_guard.index('verify_workflow_before_release('),
                        submit_guard.index('verify_linear_before_release('))
        self.assertLess(submit_guard.index('verify_linear_before_release('),
                        submit_guard.index('consume_submit_authorization('))
        for forbidden in ['gateway-public.hex','x-vcfhe-signature','VCFHE_GATEWAY_V1']:
            self.assertNotIn(forbidden,source)
    def test_lock_dependency_injection_is_package_scoped(self):
        lock=('[[package]]\nname = "kms"\ndependencies = [\n "rcgen",\n "rsa",\n]\n\n'
              '[[package]]\nname = "other"\ndependencies = [\n "rsa",\n]\n')
        changed=profile_adapter.add_locked_dependency(lock,'kms','reqwest','rsa')
        kms,other=changed.split('[[package]]\nname = "other"')
        self.assertIn(' "reqwest",\n "rsa",',kms)
        self.assertNotIn('reqwest',other)
        with self.assertRaisesRegex(ValueError,'already present'):
            profile_adapter.add_locked_dependency(changed,'kms','reqwest','rsa')
    def test_runtime_adapter_has_no_gateway_storage_dependency(self):
        source=(HERE/'build-profile.py').read_text()
        self.assertIn('/tmp/vcfhe-attesters',source)
        self.assertNotIn('/gateway/attesters',source)
    def test_cleanup_stops_own_cores_without_deleting_keys_or_chain(self):
        compose=['docker','compose','-f','/exact/run/compose.json']
        with patch.object(campaign,'command') as cmd:
            campaign.stop_campaign_services(compose)
        called=cmd.call_args.args[0]
        self.assertEqual(called[:4],compose)
        for role in ['kms1','kms2','kms3','kms4','owner','recipient','worker','public-store']:self.assertIn(role,called)
        for forbidden in ['down','rm','--volumes','node1','node2','node3','node4']:self.assertNotIn(forbidden,called)
    def test_failed_core_aborts_instead_of_waiting_for_quorum_forever(self):
        with patch.object(campaign,'output',side_effect=['dead-core',json.dumps({'Running':False,'ExitCode':137,'OOMKilled':True})]),self.assertRaisesRegex(RuntimeError,'OOM=True'):
            campaign.require_running(['docker','compose'],['kms1'])
    def test_compose_private_vault_and_role_separation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);run=root/'run-test';run.mkdir();module=root/'module';module.mkdir()
            with patch.object(campaign,'MODULE',module):
                campaign.configuration(run,campaign.parser().parse_args([]),'image:immutable')
            c=json.loads((run/'compose.json').read_text());services=c['services']
            setup=json.loads((run/'setup-compose.json').read_text())
            self.assertEqual(set(setup['networks']),{'kms','besu'});self.assertEqual(setup['name'],c['name'])
            self.assertEqual(set(setup['services']),{'kms1','kms2','kms3','kms4','public-store','identities','init','setup'})
            for role,service in setup['services'].items():self.assertEqual(service,services[role])
            self.assertTrue(c['networks']['kms']['internal'])
            for i in range(1,5):
                core=services['kms'+str(i)];self.assertNotIn('ports',core)
                self.assertEqual(core['networks'],['kms','besu'])
                self.assertEqual(core['environment']['VCFHE_POLICY_RPC_URLS'],','.join(campaign.OWNER_RPC_URLS))
                self.assertNotIn('VCFHE_POLICY_RPC_URL',core['environment'])
                self.assertEqual(core['environment']['VCFHE_RELEASE_POLICY_CONFIG'],'/config/release-policy.json')
                private=[m for m in core['volumes'] if '/private'==m['target']]
                self.assertEqual([m['source'] for m in private],[str(run/('private-'+str(i)))])
                for target in ['/release-evidence','/release-keyset']:
                    mounted=[m for m in core['volumes'] if m['target']==target]
                    self.assertEqual(len(mounted),1);self.assertTrue(mounted[0]['read_only'])
                self.assertFalse(any(m['target']=='/gateway' for m in core['volumes']))
            worker=services['worker'];self.assertEqual(worker['network_mode'],'none')
            self.assertEqual({m['target'] for m in worker['volumes']},{'/keyset','/fixtures','/worker-rpc'})
            evaluator=services['evaluate'];self.assertFalse(any(m['target'].startswith(('/datasets','/owner-identity','/recipient-identity','/private','/gateway')) for m in evaluator['volumes']))
            release_evidence=[m for m in evaluator['volumes'] if m['target']=='/release-evidence']
            self.assertEqual(len(release_evidence),1);self.assertFalse(release_evidence[0]['read_only'])
            self.assertEqual(evaluator['networks'],['besu']);self.assertEqual(services['owner']['networks'],['besu'])
            owner_reports=[m for m in services['owner']['volumes'] if m['target']=='/reports']
            self.assertEqual(len(owner_reports),1);self.assertFalse(owner_reports[0]['read_only'])
            exchange=[m for m in services['owner']['volumes'] if m['target']=='/exchange']
            self.assertEqual(len(exchange),1);self.assertTrue(exchange[0]['read_only'])
            policy=services['policy-init'];self.assertEqual(policy['networks'],['besu'])
            self.assertEqual(policy['environment']['VCFHE_POLICY_RPC_URL'],'http://node1:8545')
            self.assertEqual(policy['environment']['VCFHE_POLICY_VERSION'],'3')
            self.assertTrue(any(m['target']=='/policy-state' and not m['read_only'] for m in policy['volumes']))
            identity_targets={m['target'] for m in services['identities']['volumes']}
            self.assertNotIn('/provision/gateway',identity_targets)
            for role in ['owner','evaluate','recipient','worker','kms1','kms2','kms3','kms4']:
                self.assertFalse(any(m['target']=='/setup-identity' for m in services[role]['volumes']))
            for role in ['init','setup']:
                self.assertTrue(any(m['target']=='/setup-identity' and m['read_only'] for m in services[role]['volumes']))
            self.assertTrue(all(m['read_only'] for m in services['public-store']['volumes']))
            self.assertTrue(all(s['read_only'] and s['cap_drop']==['ALL'] for s in services.values()))
    def test_half_wrappers_reject_scope_override_before_dispatch(self):
        for name,fixed in [('run-linear.sh','linear'),('run-nonlinear.sh','nonlinear')]:
            source=(campaign.ROOT/name).read_text()
            self.assertIn('--half|--half=*',source)
            self.assertIn(f'fixes --half={fixed}',source)
            self.assertLess(source.index('for arg in "$@"'),source.index('exec "$HERE/run-poc.sh"'))
        alias=(campaign.ROOT/'non-linear.sh').read_text()
        self.assertIn('exec "$HERE/run-nonlinear.sh" "$@"',alias)
    def test_legacy_gateway_ledger_is_only_read_only_migration_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);run=root/'run-test';run.mkdir();module=root/'module';module.mkdir()
            legacy=module/'.policy-state/gateway/ledger.json';legacy.parent.mkdir(parents=True)
            legacy.write_text('{"version":2,"records":{}}')
            with patch.object(campaign,'MODULE',module):
                campaign.configuration(run,campaign.parser().parse_args([]),'image:immutable')
            services=json.loads((run/'compose.json').read_text())['services']
            mounts=[m for m in services['policy-init']['volumes'] if m['target']=='/migration/ledger.json']
            self.assertEqual(len(mounts),1);self.assertTrue(mounts[0]['read_only'])
            for role,service in services.items():
                if role!='policy-init':self.assertFalse(any(m['target']=='/migration/ledger.json' for m in service.get('volumes',[])))
    def test_campaign_v3_has_no_live_gateway_or_ledger_preflight(self):
        self.assertEqual(campaign.VERSION,'dataset-threshold-campaign-v3')
        source=(HERE/'run.py').read_text()
        self.assertNotIn(".policy-state/gateway/ledger.json.lock",source)
        self.assertNotIn("'/preflight-ledger.json'",source)
    def test_policy_lineage_is_fail_closed_and_new_genesis_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            module=Path(temp)/'module';module.mkdir()
            with patch.object(campaign,'MODULE',module):
                with self.assertRaisesRegex(ValueError,'lineage is unavailable'):
                    campaign.policy_lineage(campaign.parser().parse_args([]))
                self.assertEqual(campaign.policy_lineage(campaign.parser().parse_args(['--new-policy-lineage'])),
                                 'explicit-new-lineage')
                owners=module/'.policy-state/owner/identities.json';owners.parent.mkdir(parents=True);owners.write_text('[]')
                self.assertEqual(campaign.policy_lineage(campaign.parser().parse_args(['--new-policy-lineage'])),
                                 'explicit-new-lineage')
                deployment=module/'.policy-state/onchain/deployment.json';deployment.parent.mkdir(parents=True)
                deployment.write_text('{}')
                with self.assertRaisesRegex(ValueError,'cannot replace'):
                    campaign.policy_lineage(campaign.parser().parse_args(['--new-policy-lineage']))
    def test_each_validator_exposes_internal_http_rpc_without_new_host_ports(self):
        self.assertEqual(campaign.OWNER_RPC_URLS,[f'http://node{i}:8545' for i in range(1,5)])
        compose=(campaign.ROOT/'network/validators-besu/docker-compose.besu.yml').read_text()
        for index in [2,3,4]:
            block=compose.split(f'  node{index}:',1)[1].split('\n  node',1)[0]
            self.assertIn('--rpc-http-enabled',block);self.assertIn('--rpc-http-port=8545',block)
            self.assertNotIn('\n    ports:',block)
    def test_owner_authorization_reads_use_validator_quorum(self):
        source=(HERE/'owner.mjs').read_text()
        self.assertIn('rpcUrls:cfg.ownerRpcUrls',source)
        self.assertNotIn('new ethers.JsonRpcProvider(cfg.rpcUrl)',source)
        self.assertIn("from './runtime/scripts/evm-lib.mjs'",source)
        self.assertNotIn("from '/app/fhe-pod/scripts/evm-lib.mjs'",source)
        self.assertLess(source.index('function same('),
                        source.index("await ownerChain.withView('release-policy identity'"))
        for label in ['release-policy identity','protected-record baseline','nonlinear workflow binding',
                      'consent approval','exact release','linear accepted output',
                      'nonlinear finality and result binding']:
            self.assertIn(label,source)
        for direct_read in ['registry.protectedRecords(','registry.getConsent(','registry.getRelease(',
                            'registry.isConsentOwner(','registry.getConsentRecord(','registry.getConsentInput(']:
            self.assertNotIn(direct_read,source)
    def test_incomplete_run_never_replays_release(self):
        with tempfile.TemporaryDirectory() as temp,patch('sys.argv',['run.py','--resume','--run-dir',temp]),self.assertRaisesRegex(ValueError,'Automatic replay'):
            campaign.main()
    def test_seal_detects_changed_file(self):
        with tempfile.TemporaryDirectory() as temp:
            run=Path(temp);artifact=run/'output';artifact.write_text('valid');(run/'config').mkdir()
            cfg={'half':'linear','parameters':'Default','smoke':False}
            campaign.write(run/'config/campaign.json',cfg)
            campaign.write(run/'state.json',{'status':'passed','source':{},'config':cfg,'datasets':{}})
            files={name:campaign.sha(run/name) for name in ['output','config/campaign.json','state.json']}
            campaign.write(run/'seal.json',{'version':campaign.VERSION,'source':{},'files':files,
                'parameters':'Default','classification':'dataset-real-threshold-besu','halves':['linear']})
            with patch.object(campaign,'source_manifest',return_value={}):
                campaign.verify(run);artifact.write_text('modified')
                with self.assertRaisesRegex(ValueError,'changed/missing'):campaign.verify(run)

    def test_seal_inventory_includes_owner_validation_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            run=Path(temp)
            for folder in (*campaign.SEALED_ARTIFACT_FOLDERS,'recipient'):(run/folder).mkdir()
            (run/'owner/expected.json').write_text('{}')
            (run/'owner/case').mkdir();(run/'owner/case/approved-context.json').write_text('{}')
            (run/'config/release-policy.json').write_text('{}')
            (run/'recipient/result-0.json').write_text('{}')
            for name in ['state.json','compose.json','setup-compose.json','besu.json']:
                (run/name).write_text('{}')
            files=campaign.collect_seal_files(run)
            self.assertIn('owner/expected.json',files)
            self.assertIn('owner/case/approved-context.json',files)
            self.assertIn('config/release-policy.json',files)
            self.assertIn('recipient/result-0.json',files)

if __name__=='__main__':unittest.main()
