"""Deleted-image recovery tests. No cloud, compiler, container or protocol action."""
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import cloud_build
import gce_image
import image
import image_recovery as recovery
import topology
from image_test_fixtures import native_recipient_proof

class RecoveryRulesTests(unittest.TestCase):
    def setUp(self):self.config=json.loads((HERE/'config.example.json').read_text())
    def test_only_explicit_absence_can_trigger_replacement(self):
        for error,missing in [('ERROR: NOT_FOUND: image absent',True),
                              ('ERROR: PERMISSION_DENIED: image absent',False),
                              ('ERROR: NOT_FOUND: does not exist or no permission',False),
                              ('Connection timed out',False)]:
            with self.subTest(error=error),patch('image_recovery.subprocess.run',return_value=
                    subprocess.CompletedProcess([],1,'',error)):
                if missing:self.assertFalse(recovery.exists(['synthetic-test-only']))
                else:
                    with self.assertRaises(ValueError):recovery.exists(['synthetic-test-only'])
    def test_compute_describe_accepts_only_its_explicit_absence_format(self):
        for group in [['instances'],['networks'],['networks','subnets'],['firewall-rules']]:
            args=['compute',*group,'describe','example-builder','--project','example-research-project']
            command='gcloud.compute.'+'.'.join(group)+'.describe'
            error=f"ERROR: ({command}) Could not fetch resource:\n - The resource 'projects/example-research-project/example-builder' was not found\n"
            with self.subTest(group=group),patch('image_recovery.subprocess.run',return_value=subprocess.CompletedProcess([],1,'',error)):
                self.assertFalse(recovery.exists(args))
            for ambiguous in [error+'Permission denied\n',error+'Connection timed out\n',
                              error.replace('was not found','was not found or access is denied'),
                              error.replace(command,'gcloud.compute.other.describe'),
                              'The resource was not found']:
                with self.subTest(error=ambiguous),patch('image_recovery.subprocess.run',return_value=subprocess.CompletedProcess([],1,'',ambiguous)):
                    with self.assertRaises(ValueError):recovery.exists(args)
            with patch('image_recovery.subprocess.run',return_value=subprocess.CompletedProcess([],1,'',error)):
                with self.assertRaises(ValueError):recovery.exists(['artifacts','docker','images','describe','example-image'])
    def test_archive_keeps_successful_records_and_stops_after_interrupted_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'published-image.json').write_text('original receipt')
            work=root/'gce-builder';work.mkdir();(work/'build.log').write_text('preserved build evidence')
            history=recovery.archive(root,['published-image.json','gce-builder'],['synthetic-image'])
            self.assertEqual((history/'published-image.json').read_text(),'original receipt')
            self.assertEqual((history/'gce-builder/build.log').read_text(),'preserved build evidence')
            self.assertFalse((root/'image-recovery-pending.json').exists())
            (root/'image-recovery-pending.json').write_text('{}')
            with self.assertRaises(ValueError):recovery.require_no_pending(root)
    def test_ambiguous_submission_and_failed_build_are_not_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'ambiguous-cloud-build-submission.json').write_text('{}')
            with self.assertRaises(ValueError):recovery.archive(root,[],[])
            self.assertFalse((root/'history').exists())
        for row in [{'buildStatus':'FAILURE','sourceSha256':'x'},
                    {'buildStatus':'SUCCESS','sourceSha256':'changed'}]:
            with self.assertRaises(ValueError):recovery.require_success(row,'x')
        for row in [{'status':'WORKING'},{'status':'STATUS_UNKNOWN'},
                    {'status':'SUCCESS','startTime':'2026-01-01T00:00:00Z'}]:
            with self.assertRaises(ValueError):recovery.no_active([row])
    def test_cleanup_requires_empty_managed_state_and_real_named_resource_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp);(work/'terraform').mkdir();(work/'terraform/terraform.tfstate').write_text('{}')
            def run(args,**kwargs):
                if args[0]=='terraform':return subprocess.CompletedProcess(args,0,json.dumps({'values':{'root_module':{'resources':[{'mode':'data'}]}}}),'')
                command='gcloud.'+'.'.join(args[1:args.index('describe')+1])
                error=f"ERROR: ({command}) Could not fetch resource:\n - The resource 'projects/example/disposable-builder' was not found\n"
                return subprocess.CompletedProcess(args,1,'',error)
            with patch('image_recovery.subprocess.run',side_effect=run) as call:
                result=recovery.prove_gce_cleanup(self.config,work)
                self.assertEqual(result['status'],'passed');self.assertTrue(result['namedResourcesAbsent'])
                self.assertEqual(call.call_count,5)
            managed={'values':{'root_module':{'child_modules':[{'resources':[{'mode':'managed','address':'instance.builder'}]}]}}}
            with patch('image_recovery.subprocess.run',return_value=subprocess.CompletedProcess([],0,json.dumps(managed),'')):
                with self.assertRaises(ValueError):recovery.prove_gce_cleanup(self.config,work)
            (work/'cleanup.local.json').write_text('{"status":"failed"}')
            with patch('image_recovery.subprocess.run') as call:
                with self.assertRaises(ValueError):recovery.prove_gce_cleanup(self.config,work)
                call.assert_not_called()
    def test_completed_result_observations_do_not_replace_original_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);original=recovery.retain_result(root,{'old':'preserved'})
            observation=recovery.retain_result(root,{'new':'observation'})
            self.assertEqual(json.loads(original.read_text()),{'old':'preserved'})
            self.assertNotEqual(original,observation)
    def test_cleanup_uses_builder_override_without_moving_protocol_nodes(self):
        selected=self.config['regions'][1]
        self.config['builder_zone']=selected['zone']
        with patch('image_recovery.exists',return_value=False) as inspect:
            report=recovery.prove_gce_cleanup(self.config)
        calls=[call.args[0] for call in inspect.call_args_list]
        instance=next(args for args in calls if args[:2]==['compute','instances'])
        subnet=next(args for args in calls if args[:3]==['compute','networks','subnets'])
        self.assertEqual(instance[instance.index('--zone')+1],selected['zone'])
        self.assertEqual(subnet[subnet.index('--region')+1],selected['name'])
        self.assertEqual(report['builderZone'],selected['zone'])
    def test_backend_switch_keeps_prior_gce_cost_reservations(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger=Path(tmp)/'ledger.local.json'
            rows=[{'project':self.config['project_id'],'campaign':self.config['campaign'],'upperUsd':'2.00'},
                  {'project':self.config['project_id'],'campaign':'another-campaign','upperUsd':'9.00'}]
            ledger.write_text(json.dumps({'reservations':rows}))
            self.assertEqual(recovery.gce_reservations(self.config,ledger),2)
            rows[0]['upperUsd']='-2';ledger.write_text(json.dumps({'reservations':rows}))
            with self.assertRaises(ValueError):recovery.gce_reservations(self.config,ledger)
    def test_upload_contains_public_sources_without_private_recovery_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for directory in ['app','upstream','history','gce-builder']:(root/directory).mkdir()
            (root/'app/source.py').write_text('public source')
            (root/'upstream/lib.rs').write_text('public source')
            (root/'Dockerfile').write_text('FROM fixture-only\n')
            (root/'history/private-record.json').write_text('must remain local')
            (root/'gce-builder/terraform.tfstate').write_text('must remain local')
            record={'dockerfileSha256':hashlib.sha256((root/'Dockerfile').read_bytes()).hexdigest(),
                    'buildInputs':image.inputs(root)}
            (root/'distributed-source.json').write_text(json.dumps(record))
            upload=recovery.prepare_upload(root,record)
            self.assertEqual({p.name for p in upload.iterdir()},
                             {'app','upstream','Dockerfile','distributed-source.json','.gcloudignore'})
            image.verify_inputs(upload,record)
            self.assertTrue((root/'history/private-record.json').is_file())
            self.assertFalse((upload/'gce-builder').exists())

class BuilderRecoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.config=json.loads((HERE/'config.example.json').read_text())
        self.config['project_id']='example-research-project'
        self.quote={'build_registry':'8.00','rateEvidence':[{'region':self.config['regions'][0]['name'],
            'computeHourlyUsd':'.01','diskHourlyUsd':'.01'}]}
        self.record={'localSource':{'original':'unchanged'},'distributedSource':{},
            'nativeRecipientTransport':native_recipient_proof()}
        (self.root/'distributed-source.json').write_text(json.dumps(self.record))
        self.receipt={'sourceSha256':topology.digest(self.record),'buildStatus':'SUCCESS',
            'digest':'example.test/project/campaign@sha256:'+'a'*64,
            'besuDigest':'example.test/project/besu@sha256:'+'b'*64,'builder':'temporary GCE VM'}
        self.resources={'region':self.config['regions'][0]['name'],
            'builderServiceAccount':'projects/example/serviceAccounts/build@example.test','bucket':'gs://synthetic-build'}
        self.patches=[patch('budget.assess',return_value={'status':'admit'}),
            patch('cloud_setup.inspect',return_value={}),patch('image.verify_inputs'),
            patch('image.adapter_sources',return_value=[]),
            patch('image.deployment.campaign_module',return_value=Mock(source_manifest=lambda:self.record['localSource'])),
            patch('cloud_setup.ensure_build_resources',return_value=self.resources)]
        for item in self.patches:item.start();self.addCleanup(item.stop)
    def test_new_adapter_blocks_both_builders_before_resource_creation(self):
        adapter=self.root/'new-adapter.py';adapter.write_text('new source after preparation')
        for backend in [gce_image,cloud_build]:
            with self.subTest(backend=backend.__name__),patch('image.adapter_sources',return_value=[adapter]),patch('cloud_setup.ensure_build_resources') as create:
                with self.assertRaisesRegex(ValueError,'stale adapters'):
                    backend.build(self.config,self.quote,self.root)
                create.assert_not_called()
    def test_gce_price_guard_uses_selected_builder_region(self):
        selected=self.config['regions'][1]
        self.config['builder_zone']=selected['zone']
        with patch('cloud_setup.ensure_build_resources') as create:
            with self.assertRaisesRegex(ValueError,'regional catalog price evidence'):
                gce_image.build(self.config,self.quote,self.root)
            self.quote['rateEvidence'].append({'region':selected['name'],'computeHourlyUsd':'1.00','diskHourlyUsd':'.01'})
            with self.assertRaisesRegex(ValueError,'exceeds the conservative attempt reservation'):
                gce_image.build(self.config,self.quote,self.root)
            self.quote['rateEvidence'][0]['computeHourlyUsd']='1.00'
            self.quote['rateEvidence'][1]['computeHourlyUsd']='.01'
            (self.root/'gce-builder').mkdir()
            with self.assertRaisesRegex(ValueError,'Prior builder state retained'):
                gce_image.build(self.config,self.quote,self.root)
            create.assert_not_called()
    def test_gce_missing_successful_image_archives_only_after_cleanup_proof(self):
        receipt=self.root/'published-image.json';receipt.write_text(json.dumps(self.receipt))
        (self.root/'gce-builder').mkdir();(self.root/'gce-builder/build.log').write_text('kept')
        real=gce_image.build
        with (patch('gce_image.build',return_value={'rebuilt':True}) as restart,
             patch('image_recovery.missing_images',return_value=[self.receipt['digest']]),
             patch('image_recovery.prove_gce_cleanup',return_value={'status':'passed'}) as cleanup,
             patch('cloud_setup.gcloud',return_value=[])):
            result=real(self.config,self.quote,self.root)
            self.assertEqual(result,{'rebuilt':True});cleanup.assert_called_once()
            restart.assert_called_once_with(self.config,self.quote,self.root,_recovering=True)
        self.assertFalse(receipt.exists())
        archives=list((self.root/'history').iterdir());self.assertEqual(len(archives),1)
        self.assertEqual((archives[0]/'gce-builder/build.log').read_text(),'kept')
    def test_gce_cleanup_failure_prevents_a_duplicate_attempt(self):
        (self.root/'published-image.json').write_text(json.dumps(self.receipt));(self.root/'gce-builder').mkdir()
        real=gce_image.build
        with (patch('gce_image.build') as restart,patch('image_recovery.missing_images',return_value=['missing']),
             patch('image_recovery.prove_gce_cleanup',side_effect=ValueError('live prior builder'))):
            with self.assertRaises(ValueError):real(self.config,self.quote,self.root)
            restart.assert_not_called()
        self.assertTrue((self.root/'published-image.json').exists())
    def cloud_result(self):
        besu='hyperledger/besu@sha256:'+'c'*64
        _,tag,besu_tag=cloud_build.specification(self.config,self.record,self.resources,besu)
        completed={'status':'SUCCESS','results':{'images':[{'name':tag,'digest':'sha256:'+'a'*64},
                    {'name':besu_tag,'digest':'sha256:'+'b'*64}]}}
        return besu,completed
    def test_cloud_build_success_submission_with_deleted_images_is_not_accepted(self):
        besu,completed=self.cloud_result()
        (self.root/'cloud-build-submission.json').write_text(json.dumps({'id':'old-success','besuSource':besu}))
        (self.root/'cloud-build-result.json').write_text(json.dumps({'original':'retained result'}))
        def inspect(*args):return completed if args[:2]==('builds','describe') else []
        real=cloud_build.build
        with (patch('cloud_build.build',return_value={'rebuilt':True}) as restart,
             patch('image_recovery.missing_images',return_value=['missing']),patch('cloud_setup.gcloud',side_effect=inspect)):
            self.assertEqual(real(self.config,self.quote,self.root),{'rebuilt':True})
            restart.assert_called_once_with(self.config,self.quote,self.root,_recovering=True)
        history=next((self.root/'history').iterdir())
        self.assertEqual(json.loads((history/'cloud-build-result.json').read_text()),{'original':'retained result'})
        self.assertFalse((self.root/'published-image.json').exists())
    def test_failed_cloud_build_is_not_recompiled(self):
        (self.root/'cloud-build-submission.json').write_text('{"id":"failed"}')
        real=cloud_build.build
        with patch('cloud_build.build') as restart,patch('cloud_setup.gcloud',return_value={'status':'FAILURE'}):
            with self.assertRaises(ValueError):real(self.config,self.quote,self.root)
            restart.assert_not_called()
        self.assertFalse((self.root/'history').exists())
    def test_new_success_with_missing_images_does_not_start_a_second_build(self):
        besu,completed=self.cloud_result()
        def inspect(*args):
            if args[:2]==('builds','list'):return []
            if args[:2]==('builds','submit'):return {'id':'new-success'}
            if args[:2]==('builds','describe'):return completed
            raise AssertionError('unexpected cloud request')
        real=cloud_build.build
        with (patch('cloud_build.build') as restart,patch('cloud_build.docker_manifest',return_value=besu),
              patch('image_recovery.missing_images',return_value=['missing']),
              patch('image_recovery.prepare_upload',return_value=self.root/'synthetic-public-upload'),
              patch('cloud_setup.gcloud',side_effect=inspect),patch('cloud_build.subprocess.run')):
            with self.assertRaisesRegex(ValueError,'No automatic compilation retry'):
                real(self.config,self.quote,self.root)
            restart.assert_not_called()
        self.assertTrue((self.root/'cloud-build-submission.json').is_file())
        self.assertTrue((self.root/'cloud-build-result.json').is_file())
        self.assertFalse((self.root/'history').exists())

if __name__=='__main__':unittest.main()
