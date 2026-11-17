"""Offline adversarial delivery, real loopback TLS and no-launch regressions."""
import base64
import copy
from datetime import datetime,timezone
import hashlib
import http.client
import io
import json
from pathlib import Path
import ssl
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE/'tests'))
from cloud_results import common,package,infra,cleanup,bundle,cli,quote,preservation,worker
from cloud_results.storage import Store
from cloud_results.extract_source import extract
import test_cloud_archive as tls_fixture
import budget
import topology


def config():
    v=json.loads((HERE/'config.example.json').read_text())
    v.update(project_id='example-research-project',operator_principal='user:operator@example.test',maximum_vm_runtime_seconds=50400)
    v['images']={key:'us-central1-docker.pkg.dev/example-research-project/retained/'+key+'@sha256:'+n*64
                 for key,n in [('campaign','a'),('besu','b')]}
    return v


def synthetic_quote(cfg,cost='0.1'):
    return {'currency':'USD','campaign':cfg['campaign'],'layout':cfg['layout'],'planned_hours':'14',
        'hourly':{'compute':cost,'nat':'0.01','disks':'0.01','ipv4':'0.01'},'build_registry':'1',
        'retained_resources':'1','transfer_storage_upper_bound':'1','case_allowance_hours':2,
        'prior_experiment_upper_bound_usd':'0','quoted_at':datetime.now(timezone.utc).isoformat(),
        'source_urls':['https://example.test/synthetic-price-only']}


class TLSResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):tls_fixture.ArchiveTLSRoundtrip.setUpClass.__func__(cls)
    @classmethod
    def tearDownClass(cls):tls_fixture.ArchiveTLSRoundtrip.tearDownClass.__func__(cls)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()
        type(self).objects.clear();type(self).forbidden=False;type(self).corrupt=False
        ctx=ssl.create_default_context(cafile=str(self.cert));ctx.check_hostname=False
        self.store=Store('vcfhe-evidence-'+'a'*20,'example-research-project')
        self.connection=lambda:http.client.HTTPSConnection('127.0.0.1',self.server.server_port,context=ctx)
        def api(path,method='GET',body=None):
            c=self.connection()
            c.request(method,'/storage/v1/b/'+self.store.bucket+path)
            response=c.getresponse();data=response.read();status=response.status;c.close()
            if status!=200:raise ValueError('HTTP '+str(status))
            return json.loads(data)
        self.patchers=[patch.object(self.store,'connection',self.connection),patch.object(self.store,'token',return_value='synthetic-token'),patch.object(self.store,'api',side_effect=api)]
        for p in self.patchers:p.start();self.addCleanup(p.stop)
        self.source=self.root/'results.tar';self.source.write_bytes(b'synthetic bounded evaluation results')
    def upload(self):return self.store.upload(self.source,'runs/test/evaluation-results.tar')
    def test_actual_tls_roundtrip_checks_exact_generation_and_sha(self):
        receipt=self.upload();returned=self.store.download(receipt,self.root/'returned.tar',maximum=1000)
        self.assertEqual(returned.read_bytes(),self.source.read_bytes());self.assertEqual(receipt['generation'],'1001')
    def test_create_only_refuses_second_write(self):
        self.upload()
        with self.assertRaisesRegex(ValueError,'412'):self.upload()
    def test_wrong_generation_has_no_latest_fallback(self):
        receipt=self.upload();receipt['generation']='999'
        with self.assertRaisesRegex(ValueError,'404'):self.store.download(receipt,self.root/'returned.tar')
    def test_size_guard_precedes_media_download(self):
        receipt=self.upload()
        with patch.object(self.store,'connection') as c:
            with self.assertRaisesRegex(ValueError,'oversized'):self.store.download(receipt,self.root/'returned.tar',maximum=1)
            c.assert_not_called()
        self.assertFalse((self.root/'returned.tar').exists())
    def test_corrupted_tls_readback_is_not_success(self):
        receipt=self.upload();type(self).corrupt=True
        with self.assertRaisesRegex(ValueError,'mismatch'):self.store.download(receipt,self.root/'returned.tar')
    def test_denied_upload_is_not_missing_or_success(self):
        type(self).forbidden=True
        with self.assertRaisesRegex(ValueError,'403'):self.upload()
    def test_wrong_sha_metadata_blocks_download(self):
        receipt=self.upload();receipt['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'checksum'):self.store.download(receipt,self.root/'returned.tar')
    def test_existing_local_file_is_never_overwritten(self):
        receipt=self.upload();out=self.root/'returned.tar';out.write_bytes(b'previous results')
        with self.assertRaisesRegex(ValueError,'exists'):self.store.download(receipt,out)
        self.assertEqual(out.read_bytes(),b'previous results')


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()
        self.files={'proof/seal.json':b'{"synthetic":true}',
                    'proof/cloud-preservation.json':b'{"status":"verified-cloud-preservation"}',
                    'composite/observations.csv':b'case,value\n0,1\n'}
        h=lambda value:hashlib.sha256(value).hexdigest()
        self.files['composite/provenance.json']=b'{"synthetic":true}'
        generated={name:b'fixture' for name in ['workflow/observations.csv','workflow/summary.json','metrics.csv','METRICS.md',
            *('figures/'+n+s for n in ('linear-cost','nonlinear-work','workflow-gas') for s in ('.pdf','.png','.svg','.csv','.json'))]}
        self.files.update({'composite/'+name:value for name,value in generated.items()})
        self.files['composite/analysis-package.json']=json.dumps(dict(schema='poc-analysis-package-v1',half='both',preliminary=False,
            provenanceSha256=h(self.files['composite/provenance.json']),files={n:h(v) for n,v in generated.items()})).encode()
        self.files['composite/distributed-results.json']=b'{"status":"results-ready"}'
        self.files['proof/cloud-validation.json']=json.dumps(dict(status='passed',measuredPairs=480,warmups=18,fullCases=27,
            sourceSealSha256=h(self.files['proof/seal.json']),provenanceSha256=h(self.files['composite/provenance.json']))).encode()
    def archive(self,mutate=None,extra=None,link=False):
        m={'schema':'cloud-results-delivery-v1','measuredPairs':480,'warmups':18,'fullCases':27,
           'files':{k:{'sha256':hashlib.sha256(v).hexdigest(),'bytes':len(v)} for k,v in self.files.items()}}
        m['validationSha256']=hashlib.sha256(self.files['proof/cloud-validation.json']).hexdigest()
        m['preservationSha256']=hashlib.sha256(self.files['proof/cloud-preservation.json']).hexdigest()
        if mutate:mutate(m)
        raw=json.dumps(m).encode();path=self.root/'result.tar'
        with tarfile.open(path,'w') as tar:
            for name,data in [('manifest.json',raw),*self.files.items(),*([extra] if extra else [])]:
                item=tarfile.TarInfo(name);item.size=len(data)
                if link and name=='composite/observations.csv':item.type=tarfile.SYMTYPE;item.linkname='/tmp/forbidden';item.size=0
                tar.addfile(item,io.BytesIO(data))
        expected={'bytes':path.stat().st_size,'sha256':common.sha(path),'manifestSha256':hashlib.sha256(raw).hexdigest()}
        return path,expected
    def test_valid_delivery_preserves_results_without_raw(self):
        path,e=self.archive();package.unpack(path,self.root/'delivery',e)
        result=package.verify_local(self.root/'delivery');self.assertFalse(result['rawEvidenceDownloaded'])
        self.assertEqual((self.root/'delivery/composite/observations.csv').read_bytes(),self.files['composite/observations.csv'])
    def test_omitted_or_changed_local_result_blocks_verification(self):
        path,e=self.archive();package.unpack(path,self.root/'delivery',e)
        (self.root/'delivery/composite/observations.csv').write_bytes(b'mutated')
        with self.assertRaises(ValueError):package.verify_local(self.root/'delivery')
    def test_wrong_design_cannot_publish_smoke(self):
        for count in (1,3,45):
            path,e=self.archive(lambda m:m.update(fullCases=count))
            with self.assertRaisesRegex(ValueError,'design'):package.unpack(path,self.root/('bad'+str(count)),e)
    def test_extra_member_rejected_before_extraction(self):
        path,e=self.archive(extra=('evaluation/extra.json',b'{}'))
        with self.assertRaisesRegex(ValueError,'Unexpected'):package.unpack(path,self.root/'delivery',e)
        self.assertFalse((self.root/'delivery').exists())
    def test_traversal_rejected_before_extraction(self):
        self.files['../escaped.json']=b'{}';path,e=self.archive()
        with self.assertRaisesRegex(ValueError,'Unsafe'):package.unpack(path,self.root/'delivery',e)
        self.assertFalse((self.root/'escaped.json').exists())
    def test_link_rejected_before_extraction(self):
        path,e=self.archive(link=True)
        with self.assertRaisesRegex(ValueError,'linked'):package.unpack(path,self.root/'delivery',e)
    def test_raw_key_material_cannot_enter_local_package(self):
        for name in ('composite/fixtures/raw.json','evaluation/private/share.json','evaluation/node.pem','evaluation/keys.local.json','composite/bin/info.json'):
            with self.assertRaises(ValueError):package.allowed(name)
    def test_changed_file_hash_rejected(self):
        path,e=self.archive(lambda m:m['files']['composite/observations.csv'].update(sha256='0'*64))
        with self.assertRaisesRegex(ValueError,'hash'):package.unpack(path,self.root/'delivery',e)
    def test_oversized_download_metadata_rejected(self):
        path,e=self.archive();e['bytes']=package.MAX_PACKAGE_BYTES+1
        with self.assertRaisesRegex(ValueError,'differs'):package.unpack(path,self.root/'delivery',e)
    def test_repeated_extraction_does_not_replace_previous_results(self):
        path,e=self.archive();package.unpack(path,self.root/'delivery',e)
        with self.assertRaisesRegex(ValueError,'exists'):package.unpack(path,self.root/'delivery',e)
    def test_missing_verified_local_copy_blocks_every_cleanup_mutation(self):
        with patch.object(cleanup,'run') as action,patch.object(cleanup,'gcloud') as cloud:
            with self.assertRaises(ValueError):cleanup.complete(self.root,self.root/'missing',{})
            action.assert_not_called();cloud.assert_not_called()
    def test_missing_cloud_preservation_blocks_delete(self):
        with patch.object(cleanup,'run') as action:
            with self.assertRaisesRegex(ValueError,'preservation'):cleanup.validate_preservation(None,{'rawPreservation':{}})
            action.assert_not_called()




class TeardownPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()
        self.cfg=config();self.declarations={'resource':{'google_compute_instance':{'controller':{'name':'synthetic','deletion_protection':True}},
            'google_storage_bucket':{'controller':{'name':'vcfhe-evidence-synthetic','lifecycle':{'prevent_destroy':True}}}}}
        self.state={'resources':[{'type':kind,'name':'controller','instances':[{'attributes':{}}]} for kind in self.declarations['resource']]}
    def invoke(self,actions):
        planned={'resource_changes':actions}
        with patch.object(cleanup,'run') as commands,patch.object(cleanup.subprocess,'check_output',return_value=json.dumps(planned)),patch.object(cleanup.smoke_cleanup,'_require_live',return_value=None):
            try:
                cleanup.destroy_copy(self.cfg,self.root/'teardown',self.declarations,self.state,[],preserve_addresses=['google_storage_bucket.controller'])
            finally:self.commands=commands.call_args_list
    def test_evidence_bucket_is_state_removed_and_never_destroyed(self):
        before=copy.deepcopy(self.declarations)
        self.invoke([{'address':'google_compute_instance.controller','change':{'actions':['delete']}}])
        self.assertEqual(before,self.declarations)
        self.assertTrue(any(c.args[0][-3:]==['state','rm','google_storage_bucket.controller'] for c in self.commands))
        self.assertTrue((self.root/'teardown/completed.local.json').exists())
    def test_create_replace_update_and_unknown_address_never_apply(self):
        for i,(address,actions) in enumerate([('google_compute_instance.controller',['create']),('google_compute_instance.controller',['delete','create']),
                ('google_compute_instance.controller',['update']),('google_compute_instance.foreign',['delete'])]):
            with self.subTest(actions=actions):
                self.root=self.root/str(i);self.root.mkdir()
                with self.assertRaisesRegex(ValueError,'unexpected'):self.invoke([{'address':address,'change':{'actions':actions}}])
                self.assertFalse(any('apply' in c.args[0] for c in self.commands))
    def test_incomplete_delete_plan_is_refused(self):
        with self.assertRaisesRegex(ValueError,'omits'):self.invoke([])
        self.assertFalse(any('apply' in c.args[0] for c in self.commands))
    def test_replaced_resource_fails_before_creating_teardown_or_running_terraform(self):
        with patch.object(cleanup,'run') as command,patch.object(cleanup.smoke_cleanup,'_require_live',side_effect=ValueError('replaced')):
            with self.assertRaisesRegex(ValueError,'replaced'):cleanup.destroy_copy(self.cfg,self.root/'teardown',self.declarations,self.state,[{}],preserve_addresses=[])
            command.assert_not_called()
        self.assertFalse((self.root/'teardown').exists())


class ComputeStopHookTests(unittest.TestCase):
    def hook(self,foreign=False,archive_error=False):
        from cloud_results import stop_compute
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'job').mkdir();c=config();n=infra.names(c)
            common.write(root/'job/config.local.json',c)
            common.write(root/'source-manifest.json',{'names':n,'jobId':'synthetic'})
            calls=[]
            def response(request,timeout):
                url=request.full_url;calls.append((request.get_method(),url))
                if url.startswith('http://metadata.google.internal/'):
                    return io.BytesIO(b'{"access_token":"synthetic-ephemeral-token"}')
                self.assertTrue(url.startswith('https://compute.googleapis.com/'))
                if request.get_method()=='POST':
                    self.assertTrue(url.endswith('/stop'));return io.BytesIO(b'{"name":"synthetic-operation"}')
                labels={'experiment':'foreign' if foreign and '-host-2' in url else c['campaign']}
                return io.BytesIO(json.dumps({'labels':labels,'status':'RUNNING'}).encode())
            with patch.object(stop_compute.urllib.request,'urlopen',side_effect=response),patch.object(Store,'upload',side_effect=ValueError('upload failed') if archive_error else None):
                if foreign:
                    with self.assertRaisesRegex(RuntimeError,'stop hook'):stop_compute.stop(root)
                else:stop_compute.stop(root)
            return c,n,calls,json.loads((root/'stop-hook.local.json').read_text())
    def test_all_protocol_hosts_then_controller_receive_only_stop_requests(self):
        c,n,calls,result=self.hook()
        stops=[url for method,url in calls if method=='POST']
        self.assertEqual(len(stops),5);self.assertIn(n['controller'],stops[-1])
        self.assertFalse(result['dataDeleted']);self.assertTrue(all(v.get('stopRequested') for v in result['hosts']))
    def test_failure_report_upload_does_not_prevent_compute_stop(self):
        c,n,calls,result=self.hook(archive_error=True)
        self.assertEqual(sum(method=='POST' for method,url in calls),5)
    def test_foreign_vm_is_skipped_and_failure_reported(self):
        c,n,calls,result=self.hook(foreign=True)
        self.assertEqual(sum(method=='POST' for method,url in calls),4)
        self.assertTrue(any('errorType' in row for row in result['hosts']))


class ControllerGuards(unittest.TestCase):
    def test_complete_controller_uses_plotting_runtime_for_original_validators(self):
        script=cli.controller_script('/srv/vcfhe-controller/synthetic')
        self.assertIn('source distributed/controller-bootstrap.sh --install',script)
        self.assertIn('/threshold-kms/.cache/postprocess-python/bin/python distributed/cloud_results/worker.py',script)
        self.assertNotIn('python3 distributed/cloud_results/worker.py',script)
    def test_original_grid_deadlines_thresholds_and_roles_preserved(self):
        c=config();inner=infra.inner_config(c)
        self.assertEqual({k:v for k,v in c.items() if k!='operator_principal'},{k:v for k,v in inner.items() if k!='operator_principal'})
        self.assertEqual(len(topology.inventory(inner)),21);self.assertEqual(len(topology.hosts(inner)),4)
        self.assertEqual(inner['window_seconds'],120)
    def test_smoke_cannot_use_full_publication_route(self):
        c=config();c['execution_mode']='smoke'
        with self.assertRaises(ValueError):common.check_full(c)
    def test_controller_is_off_path_with_explicit_lifetime_and_disk(self):
        c=config();r=infra.terraform(c)['resource'];vm=r['google_compute_instance']['controller']
        self.assertEqual(vm['machine_type'],'e2-standard-2');self.assertEqual(vm['boot_disk']['initialize_params']['size'],200)
        self.assertEqual(vm['scheduling']['max_run_duration']['seconds'],c['maximum_vm_runtime_seconds']+7200)
        self.assertNotIn('attached_disk',vm)
    def test_no_project_owner_or_iam_admin_or_sa_keys(self):
        r=infra.terraform(config())['resource']
        roles={v['role'] for v in r['google_project_iam_member'].values()}
        self.assertFalse(roles&{'roles/owner','roles/editor','roles/resourcemanager.projectIamAdmin','roles/storage.admin','roles/iam.serviceAccountAdmin'})
        self.assertIn('roles/serviceusage.serviceUsageConsumer',roles)
        self.assertNotIn('roles/artifactregistry.admin',roles)
        self.assertEqual(r['google_artifact_registry_repository_iam_member']['controller']['role'],
                         'roles/artifactregistry.admin')
        self.assertNotIn('google_service_account_key',r)
        self.assertTrue(r['google_storage_bucket']['controller']['lifecycle']['prevent_destroy'])
    def test_actor_accounts_are_fresh_and_refuse_existing_identity(self):
        c=config();account=next(iter(infra.actor_accounts(c).values()))
        with patch.object(infra,'gcloud',return_value=[account]),patch.object(infra,'run') as mutate:
            with self.assertRaisesRegex(ValueError,'already exists'):infra.allocate_accounts(c,'/unused')
            mutate.assert_not_called()
    def test_only_management_methods_are_overridden(self):
        self.assertEqual({n for n in worker.CloudCampaign.__dict__ if not n.startswith('__')},{'initialize','collect','stop','enrollment','kms'})
    def test_kms_wrapper_calls_original_sequence_once_without_replay(self):
        from contextlib import contextmanager
        from cloud_results import public_tls
        observed=[]
        @contextmanager
        def transfer(instance):
            observed.append('public-transfer-guard')
            yield
            observed.append('restored')
        instance=object.__new__(worker.CloudCampaign)
        with patch.object(public_tls,'readable_public_exchange',side_effect=transfer),patch.object(worker.launch.Campaign,'kms',return_value='original-result') as original:
            self.assertEqual(instance.kms(),'original-result')
            original.assert_called_once_with()
        self.assertEqual(observed,['public-transfer-guard','restored'])
    def test_explicit_execution_required_before_any_read_or_cloud_action(self):
        with patch.object(cli,'verify_prepared') as check:
            for fn in (cli.start,cli.finish):
                with self.assertRaisesRegex(ValueError,'--execute'):fn('/unused')
            check.assert_not_called()
    def test_status_before_start_does_not_query_or_create_cloud_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=config();q=synthetic_quote(c)
            with patch.object(cli,'verify_prepared',return_value=(c,c,{},{})),patch.object(cli,'read',return_value=q),patch.object(cli,'gcloud') as cloud,patch.object(cli,'Store') as store:
                self.assertEqual(cli.status(tmp)['status'],'prepared-not-started')
                cloud.assert_not_called();store.assert_not_called()
    def test_terminal_before_start_never_queries_bucket(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=config()
            with patch.object(cli,'verify_prepared',return_value=(c,c,{}, {'jobId':'synthetic'})),patch.object(cli,'Store') as store:
                self.assertEqual(cli.terminal(tmp)['status'],'not-started');store.assert_not_called()
    def test_budget_refusal_precedes_cloud_resource_calls(self):
        c=config();q=synthetic_quote(c,cost='50')
        with patch.object(cli,'verify_prepared',return_value=(c,c,{},{})),patch.object(cli,'read',return_value=q),patch.object(cli,'gcloud') as cloud:
            with self.assertRaisesRegex(ValueError,'budget refuses'):cli.start('/unused',execute=True)
            cloud.assert_not_called()
    def test_quote_duration_cannot_reduce_vm_cost_window(self):
        with self.assertRaisesRegex(ValueError,'duration'):quote.make(config(),hours=8,prior_usd='0')
    def test_cumulative_prior_cost_cannot_be_silently_omitted(self):
        with self.assertRaisesRegex(ValueError,'cumulative'):quote.make(config())
    def test_prior_spending_can_refuse_unchanged_full_grid(self):
        c=config();q=synthetic_quote(c);q['prior_experiment_upper_bound_usd']='40'
        a=budget.assess(c,q);self.assertEqual(a['status'],'refuse');self.assertFalse(a['reduces_repetitions'])
    def test_source_receipt_change_blocks_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'controller-source.tar.gz').write_bytes(b'synthetic')
            with self.assertRaisesRegex(ValueError,'differs'):extract(p,'0'*64,'0'*64)
            self.assertFalse((p/'input').exists())
    def test_private_paths_must_stay_ignored(self):
        with self.assertRaises(ValueError):common.private(HERE/'cloud_results/credentials.json')
    def test_public_reproduction_contains_no_credentials(self):
        import privacy
        self.assertEqual(privacy.audit()['findings'],[])

if __name__=='__main__':unittest.main()
