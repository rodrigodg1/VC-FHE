"""Real local TLS object-store roundtrips and fail-closed archive guards."""
import base64
import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import archive_worker as worker
import cloud_archive as cloud
import smoke_cleanup as cleanup


class ArchiveTLSRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.cert, cls.key = root/'cert.pem', root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-keyout', str(cls.key), '-out', str(cls.cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.objects = {}
        cls.forbidden = False
        cls.corrupt = False
        outer = cls
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def reply(self, code, data):
                self.send_response(code)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def do_PUT(self):
                if outer.forbidden: return self.reply(403, b'forbidden')
                key = unquote(self.path.lstrip('/'))
                data = self.rfile.read(int(self.headers['Content-Length']))
                if self.headers.get('x-goog-if-generation-match') != '0' or key in outer.objects:
                    return self.reply(412, b'precondition')
                md5 = base64.b64encode(hashlib.md5(data).digest()).decode()
                if md5 != self.headers.get('Content-MD5'): return self.reply(400, b'checksum')
                bucket, name = key.split('/', 1)
                record = {'bucket':bucket,'name':name,'size':str(len(data)), 'generation':'1001',
                          'md5Hash':md5,'metadata':{'vcfhe-sha256':self.headers['x-goog-meta-vcfhe-sha256']}}
                outer.objects[key] = (data, record)
                return self.reply(200, b'')
            def do_GET(self):
                if outer.forbidden: return self.reply(403, b'forbidden')
                url = urlsplit(self.path)
                bucket, name = url.path.split('/b/',1)[1].split('/o/',1)
                key = unquote(bucket) + '/' + unquote(name)
                query = parse_qs(url.query)
                if key not in outer.objects: return self.reply(404,b'missing')
                data, record = outer.objects[key]
                if query.get('generation',[record['generation']])[0] != record['generation']:
                    return self.reply(404,b'wrong generation')
                if query.get('alt') == ['media']:
                    return self.reply(200, data[:-1] + bytes([data[-1]^1]) if outer.corrupt else data)
                return self.reply(200, json.dumps(record).encode())
        cls.server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, cls.key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.tmp.cleanup()
    def setUp(self):
        self.local = tempfile.TemporaryDirectory(); self.addCleanup(self.local.cleanup)
        self.root = Path(self.local.name)
        self.__class__.objects.clear(); self.__class__.forbidden = False; self.__class__.corrupt = False
        ctx = ssl.create_default_context(cafile=str(self.cert)); ctx.check_hostname = False
        self.c = patch.object(worker, 'connection', lambda:http.client.HTTPSConnection('127.0.0.1',self.server.server_port,context=ctx))
        self.c.start(); self.addCleanup(self.c.stop)
        t=patch.object(worker,'token',return_value='synthetic-test-token'); t.start(); self.addCleanup(t.stop)
        self.bucket='vcfhe-evidence-'+'a'*20
        self.name='runs/'+'b'*32+'/host-1/private-state.tar'
        self.source=self.root/'source.tar'
        with tarfile.open(self.source,'w') as tar:
            for name,data in [('scope.txt',b'vcfhe-example-smoke/host-1'),('vcfhe-example-smoke/vault/share',b'synthetic-secret-fixture')]:
                entry=tarfile.TarInfo(name);entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
        self.info=worker.archive_info(self.source,'vcfhe-example-smoke','host-1')
    def test_tls_upload_exact_generation_readback_and_original_inventory(self):
        record=worker.upload(self.source,self.bucket,self.name,self.info)
        target=self.root/'readback.tar';worker.readback(self.bucket,self.name,record['generation'],target)
        self.assertEqual(worker.archive_info(target,'vcfhe-example-smoke','host-1'),self.info)
        original=cleanup._archive_info(target,'vcfhe-example-smoke')
        self.assertEqual(original,{k:v for k,v in self.info.items() if k!='md5Hash'})
    def test_create_only_refuses_overwrite(self):
        worker.upload(self.source,self.bucket,self.name,self.info)
        with self.assertRaisesRegex(ValueError,'412'):worker.upload(self.source,self.bucket,self.name,self.info)
    def test_server_rejects_bad_md5(self):
        bad=dict(self.info,md5Hash=base64.b64encode(b'0'*16).decode())
        with self.assertRaisesRegex(ValueError,'400'):worker.upload(self.source,self.bucket,self.name,bad)
    def test_permission_denied_is_not_absence_or_success(self):
        self.__class__.forbidden=True
        with self.assertRaisesRegex(ValueError,'403'):worker.upload(self.source,self.bucket,self.name,self.info)
    def test_generation_mismatch_is_not_current_object_fallback(self):
        worker.upload(self.source,self.bucket,self.name,self.info)
        with self.assertRaisesRegex(ValueError,'404'):worker.readback(self.bucket,self.name,'999',self.root/'read.tar')
    def test_corrupted_readback_changes_sha_even_if_tar_padding_is_valid(self):
        record=worker.upload(self.source,self.bucket,self.name,self.info);self.__class__.corrupt=True
        target=self.root/'bad.tar';worker.readback(self.bucket,self.name,record['generation'],target)
        self.assertNotEqual(worker.archive_info(target,'vcfhe-example-smoke','host-1'),self.info)
    def test_foreign_scope_is_refused(self):
        with self.assertRaisesRegex(ValueError,'exact host'):worker.archive_info(self.source,'vcfhe-example-smoke','host-2')
    def test_unsafe_and_duplicate_archive_entries_refused(self):
        for mode in ('traversal','symlink','duplicate'):
            path=self.root/(mode+'.tar')
            with tarfile.open(path,'w') as tar:
                a=tarfile.TarInfo('../secret' if mode=='traversal' else 'scope.txt')
                if mode=='symlink':a.type=tarfile.SYMTYPE;a.linkname='/private'
                tar.addfile(a)
                if mode=='duplicate':tar.addfile(a)
            with self.assertRaises(ValueError):worker.archive_info(path,'vcfhe-example-smoke','host-1')


class CloudArchiveGuards(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((cloud.HERE/'config.example.json').read_text())
        self.config.update(project_id='example-research-project',campaign='vcfhe-example-smoke',execution_mode='smoke')
        self.config['cloud_archive']={'backend':'gcs','location':self.config['regions'][0]['name'],'maximum_gib':15,'planning_days':30}
        self.bucket={'name':cloud.bucket_name(self.config),'projectNumber':'123','id':'bucket-id','timeCreated':'2026-10-28T00:00:00Z',
                     'location':self.config['regions'][0]['name'].upper(),'storageClass':'STANDARD',
                     'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True},'publicAccessPrevention':'enforced'},
                     'labels':{'vcfhe-purpose':'private-evidence','vcfhe-campaign':self.config['campaign']}}
    def test_exact_private_bucket_required(self):
        cloud.validate_bucket(self.config,self.bucket,'123')
        for change in ('project','public','acl','lifecycle','campaign','location'):
            value=copy.deepcopy(self.bucket)
            if change=='project':value['projectNumber']='456'
            elif change=='public':value['iamConfiguration']['publicAccessPrevention']='inherited'
            elif change=='acl':value['iamConfiguration']['uniformBucketLevelAccess']['enabled']=False
            elif change=='lifecycle':value['lifecycle']={'rule':[{'action':{'type':'Delete'}}]}
            elif change=='campaign':value['labels']['vcfhe-campaign']='another'
            else:value['location']='ASIA-EAST1'
            with self.assertRaises(ValueError):cloud.validate_bucket(self.config,value,'123')
    def test_cloud_archival_requires_budget_not_legacy_quote(self):
        with self.assertRaises(ValueError):cloud.check_quote(self.config,{'retained_resources':0})
        quote={'retained_resources':0.75,'cloud_archive':{'plan':self.config['cloud_archive'],
            'storage_and_operations_usd':0.75,'network_in_existing_envelope':True,'source_urls':['https://cloud.google.com/storage/pricing']}}
        cloud.check_quote(self.config,quote)
        quote['retained_resources']=0.1
        with self.assertRaises(ValueError):cloud.check_quote(self.config,quote)
    def test_unknown_or_full_profile_not_silently_enabled(self):
        self.config['execution_mode']='evaluation'
        with self.assertRaises(ValueError):cloud.settings(self.config)
    def test_each_host_has_only_own_prefix_create_and_read_without_delete(self):
        plan={'hosts':[{'id':'host-'+str(i)} for i in range(1,5)],'resources':[
            {'key':'host_'+str(i),'type':'google_service_account','attributes':{'email':'host'+str(i)+'@example.test'}} for i in range(1,5)]}
        grants=cloud.grants(self.config,plan,'a'*32)
        self.assertEqual(len(grants),8)
        for i in range(1,5):
            own=[g for g in grants if g['members']==['serviceAccount:host'+str(i)+'@example.test']]
            self.assertEqual({g['role'] for g in own},{'roles/storage.objectCreator','roles/storage.objectViewer'})
            self.assertTrue(all('/host-'+str(i)+'/' in g['condition']['expression'] for g in own))
            self.assertTrue(all('request.time < timestamp' in g['condition']['expression'] for g in own))
    def test_receipt_metadata_changed_fails_before_cleanup(self):
        store={'prefix':'a'*32,'bucket':{'name':cloud.bucket_name(self.config)}}
        receipt={'status':'verified-cloud-readback','host':'host-1','bucket':store['bucket']['name'],
                 'object':'runs/'+'a'*32+'/host-1/private-state.tar','generation':'1234','sha256':'b'*64,
                 'md5Hash':'expected-md5','archiveBytes':100,'files':[{'path':'scope.txt'}]}
        meta={'bucket':receipt['bucket'],'name':receipt['object'],'generation':'1234','md5Hash':'expected-md5',
              'size':'100','metadata':{'vcfhe-sha256':'b'*64}}
        with patch.object(cloud,'api',return_value=meta):cloud.validate_receipt(self.config,store,'host-1',receipt)
        for field,value in [('generation','1235'),('size','101'),('md5Hash','changed')]:
            bad=dict(meta,**{field:value})
            with patch.object(cloud,'api',return_value=bad),self.assertRaises(ValueError):
                cloud.validate_receipt(self.config,store,'host-1',receipt)
        with patch.object(cloud,'api',side_effect=ValueError('HTTP 403')),self.assertRaises(ValueError):
            cloud.validate_receipt(self.config,store,'host-1',receipt)

if __name__=='__main__':unittest.main()


class CloudBackupIntegration(unittest.TestCase):
    def setUp(self):
        import test_smoke_cleanup as fixtures
        self.fixture=fixtures.SmokeCleanupTests('test_plan_is_read_only_and_keeps_shared_registry')
        original=json.loads((cloud.HERE/'config.example.json').read_text())
        self.fixture.config_overrides={'cloud_archive':{'backend':'gcs','location':original['regions'][0]['name'],
                                                      'maximum_gib':15,'planning_days':30}}
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
    def backup(self):
        f=self.fixture; dest=f.run/'private-smoke-backup'
        def prepare(config,plan,destination,unused):
            record={'prefix':'a'*32,'bucket':{'name':cloud.bucket_name(config)}}
            cleanup._write(destination/'cloud-store.local.json',record)
            return record
        def export(config,plan,host,remote,destination,store,maximum):
            receipt={'host':host['id'],'archiveBytes':10240,'status':'verified-cloud-readback'}
            name=host['id']+'-cloud-receipt.local.json';cleanup._write(destination/name,receipt)
            return dict(receipt,receiptFile=name)
        with patch.object(cleanup,'_cloud',side_effect=f.cloud),patch.object(cleanup,'Remote',side_effect=f.remote_factory),\
             patch.object(cloud,'prepare',side_effect=prepare),patch.object(cloud,'export_host',side_effect=export),\
             patch.object(cloud,'verify',side_effect=lambda d,m,p:m) as checked:
            manifest=cleanup.backup(f.config,f.run,dest)
            self.assertEqual(checked.call_count,1)
        return dest,manifest
    def test_real_backup_dispatch_keeps_all_four_receipts_without_local_private_tars(self):
        destination,manifest=self.backup()
        self.assertEqual(manifest['schema'],cloud.SCHEMA)
        self.assertEqual(set(manifest['archives']),{'host-1','host-2','host-3','host-4'})
        self.assertEqual(len(list(destination.glob('*-cloud-receipt.local.json'))),4)
        self.assertFalse(list(destination.glob('host-*-private-state.tar')))
        self.assertTrue((destination/'original-run-evidence.tar').is_file())
    def test_cloud_verification_failure_blocks_all_resource_removal(self):
        destination,manifest=self.backup();f=self.fixture
        with patch.object(cloud,'verify',side_effect=ValueError('cloud generation missing')),\
             patch.object(cleanup,'_cloud',side_effect=f.cloud):
            with self.assertRaisesRegex(ValueError,'generation missing'):
                cleanup.apply(f.config,f.run,destination)
        self.assertEqual(f.mutations,[])
