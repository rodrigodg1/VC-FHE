"""Synthetic images only. Never authenticates or accesses a registry."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
import urllib.request

MODULE = Path(__file__).resolve().parents[1]/'maintenance/registry_evidence_proposal.py'
spec = importlib.util.spec_from_file_location('registry_evidence_proposal', MODULE)
proposal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proposal)


def hashed(value):
    return hashlib.sha256(value).hexdigest()


def raw_json(value):
    return json.dumps(value, sort_keys=True).encode()


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, content, kind in entries:
            item = tarfile.TarInfo(name)
            item.mode, item.uid, item.gid = 0o755 if name.startswith('usr/local/bin/') else 0o644, 0, 0
            if kind == 'file':
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
            elif kind == 'symlink':
                item.type, item.linkname = tarfile.SYMTYPE, content
                archive.addfile(item)
    return output.getvalue()


class FakeRegistry:
    def __init__(self, layers, *, source_record=None, worker=b'kms-campaign'):
        self.blob_calls = []
        self.blobs = {}
        descriptors, diffs = [], []
        for raw in layers:
            blob = gzip.compress(raw)
            key = 'sha256:'+hashed(blob)
            self.blobs[key] = blob
            descriptors.append({'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip', 'size':len(blob), 'digest':key})
            diffs.append('sha256:'+hashed(raw))
        config = raw_json({'architecture':'amd64', 'os':'linux', 'rootfs':{'type':'layers','diff_ids':diffs},
                           'history':[{'created_by':'synthetic fixture'} for _ in layers]})
        key = 'sha256:'+hashed(config)
        self.blobs[key] = config
        self.manifest_data = {'schemaVersion':2, 'mediaType':'application/vnd.oci.image.manifest.v1+json',
            'config':{'mediaType':'application/vnd.oci.image.config.v1+json','size':len(config),'digest':key}, 'layers':descriptors}
        self._rebind()
        self.source_record = source_record or {'targetPlatform':'linux/amd64','localSource':{'original.mjs':hashed(b'original')},
                                             'distributedSource':{'worker.mjs':hashed(b'worker')}}
        self.worker = worker

    def _rebind(self):
        self.raw = raw_json(self.manifest_data)
        self.pinned = 'sha256:'+hashed(self.raw)
        self.reference = 'us-central1-docker.pkg.dev/project-id/smoke-test/campaign@'+self.pinned

    def manifest(self, reference):
        return self.manifest_data, self.pinned, self.raw

    def blob(self, key):
        self.blob_calls.append(key)
        return io.BytesIO(self.blobs[key])


def fixture(extra=(), *, omit_binary=None, skip_link=False, installed=None, adapter=None, source_record=None):
    bins = [('usr/local/bin/'+name, name.encode(),'file') for name in proposal.BINARIES if name != omit_binary]
    installed = installed or {'original.mjs':{'sha256':hashed(b'original')},'distributed/worker.mjs':{'sha256':hashed(b'worker')}}
    evidence = [(proposal.PREFIX+'build-evidence/installed-files.json.gz',gzip.compress(raw_json(installed)),'file'),
                (proposal.PREFIX+'distributed-adapter.json',raw_json(adapter or {'files':{},'protocolRulesChanged':False,'localSourceEdited':False}),'file')]
    if skip_link:
        evidence.append((proposal.PREFIX+'build-evidence/execution-view/contracts/out','/tmp/vcfhe-compiled-contracts','symlink'))
    return FakeRegistry([tar_bytes(bins),tar_bytes(evidence+list(extra))],source_record=source_record)


class RegistryPreservationTests(unittest.TestCase):
    def plan(self, registry):
        return proposal.inspect_image(registry, registry.reference, registry.source_record,
                                      expected_worker_sha256=hashed(b'kms-campaign'))

    def test_metadata_does_not_request_layer_blobs(self):
        registry = fixture()
        plan = self.plan(registry)
        self.assertEqual(registry.blob_calls,[registry.manifest_data['config']['digest']])
        self.assertEqual(plan['compressedDownloadBytes'],sum(row['size'] for row in plan['layers']))
        self.assertIsNone(plan['extractedBytes'])

    def test_explicit_approval_and_new_destination_required_before_download(self):
        registry = fixture()
        plan = self.plan(registry)
        registry.blob_calls.clear()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):proposal.extract(registry,plan,Path(temporary)/'new')
            with self.assertRaises(ValueError):proposal.extract(registry,plan,temporary,approved=True)
        self.assertEqual(registry.blob_calls,[])

    def test_exact_files_and_original_metadata_without_execution(self):
        registry = fixture(skip_link=True)
        plan = self.plan(registry)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)/'export'
            result = proposal.extract(registry,plan,destination,approved=True)
            self.assertEqual(result['status'],'preserved-and-verified')
            self.assertEqual(sorted(p.name for p in (destination/'bin').iterdir()),sorted(proposal.BINARIES))
            self.assertEqual(result['files']['bin/kms-campaign']['uid'],0)
            self.assertEqual((destination/'bin/kms-campaign').stat().st_mode&0o777,0o600)
            self.assertEqual(destination.stat().st_mode&0o777,0o700)
            self.assertEqual(len(result['skippedLinks']),1)
            self.assertEqual((result['cloudMutations'],result['containersStarted'],result['nativeExecutablesInvoked']),(0,0,0))

    def test_changed_pinned_manifest_fails(self):
        registry = fixture()
        registry.raw += b' '
        with self.assertRaises(ValueError):self.plan(registry)

    def test_external_layer_descriptor_is_rejected(self):
        registry = fixture()
        registry.manifest_data['layers'][0]['urls']=['https://untrusted.invalid/layer']
        registry._rebind()
        with self.assertRaises(ValueError):self.plan(registry)

    def test_wrong_platform_is_rejected(self):
        registry = fixture()
        config_descriptor = registry.manifest_data['config']
        config = json.loads(registry.blobs[config_descriptor['digest']]);config['architecture']='arm64'
        raw = raw_json(config);config_descriptor.update(digest='sha256:'+hashed(raw),size=len(raw))
        registry.blobs[config_descriptor['digest']] = raw;registry._rebind()
        with self.assertRaises(ValueError):self.plan(registry)

    def test_unsafe_paths_links_duplicates_and_whiteouts_fail_closed(self):
        bad = [('../../escape',b'x','file'),
               ('usr/local/bin/kms-server','/tmp/copy','symlink'),
               (proposal.PREFIX+'build-evidence/installed-files.json.gz',b'copy','file'),
               ('usr/local/bin/.wh.kms-server',b'','file'),
               ('usr/local','/tmp/parent','symlink')]
        for entry in bad:
            with self.subTest(path=entry[0]):
                registry = fixture([entry]);plan=self.plan(registry)
                with tempfile.TemporaryDirectory() as temporary:
                    destination=Path(temporary)/'export'
                    with self.assertRaises(ValueError):proposal.extract(registry,plan,destination,approved=True)
                    self.assertTrue((destination/'failed-preservation.local.json').exists())
                    self.assertFalse((destination/'preservation.local.json').exists())

    def test_missing_native_executable_never_passes(self):
        registry=fixture(omit_binary='kms-init');plan=self.plan(registry)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):proposal.extract(registry,plan,Path(temporary)/'export',approved=True)

    def test_full_layer_bytes_verified_after_tar_end(self):
        registry=fixture();plan=self.plan(registry)
        first=plan['layers'][0]['digest'];registry.blobs[first] += b'not-in-descriptor'
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises((ValueError,gzip.BadGzipFile)):
                proposal.extract(registry,plan,Path(temporary)/'export',approved=True)

    def test_source_binding_and_worker_binding_cannot_be_bypassed(self):
        for field in ['localSource','expectedWorkerSha256']:
            registry=fixture();plan=self.plan(registry)
            if field=='localSource':plan['sourceRecord']['localSource']['original.mjs']='0'*64
            else:plan[field]='0'*64
            plan['sourceRecordSha256']=proposal.digest(plan['sourceRecord'])
            plan.pop('planSha256');plan['planSha256']=proposal.digest(plan)
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):proposal.extract(registry,plan,Path(temporary)/'export',approved=True)

    def test_actual_adapted_source_requires_both_original_and_installed_hashes(self):
        original, adapted = hashed(b'original'), hashed(b'adapted')
        installed = {'original.mjs':{'sha256':adapted},'distributed/worker.mjs':{'sha256':hashed(b'worker')}}
        adapter = {'files':{'original.mjs':{'sourceSha256':original,'adaptedSha256':adapted}},
                   'protocolRulesChanged':False,'localSourceEdited':False}
        registry=fixture(installed=installed,adapter=adapter);plan=self.plan(registry)
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(proposal.extract(registry,plan,Path(temporary)/'export',approved=True)['status'],'preserved-and-verified')
        adapter['files']['original.mjs']['sourceSha256']='0'*64
        registry=fixture(installed=installed,adapter=adapter);plan=self.plan(registry)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):proposal.extract(registry,plan,Path(temporary)/'export',approved=True)

    def test_history_and_rootfs_must_match_all_layers(self):
        registry=fixture()
        descriptor=registry.manifest_data['config'];value=json.loads(registry.blobs[descriptor['digest']])
        value['history'].pop();raw=raw_json(value);descriptor.update(digest='sha256:'+hashed(raw),size=len(raw))
        registry.blobs[descriptor['digest']]=raw;registry._rebind()
        with self.assertRaises(ValueError):self.plan(registry)

    def test_changed_plan_is_refused_before_layer_download(self):
        registry=fixture();plan=self.plan(registry);registry.blob_calls.clear()
        plan['limits']['selectedTotalBytes'] += 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):proposal.extract(registry,plan,Path(temporary)/'export',approved=True)
        self.assertEqual(registry.blob_calls,[])

    def test_reviewed_same_origin_download_redirect_strips_oauth(self):
        host='us-central1-docker.pkg.dev'
        source='/v2/example-project/smoke/campaign/blobs/sha256:'+'1'*64
        original=urllib.request.Request('https://'+host+source,headers={'Authorization':'Bearer unit-test-only'})
        handler=proposal._BlobRedirect(host,source)
        redirected=handler.redirect_request(original,None,302,'Found',{},'https://'+host+'/artifacts-downloads/unit-test-capability')
        self.assertEqual(redirected.get_method(),'GET')
        self.assertIsNone(redirected.get_header('Authorization'))
        self.assertEqual(redirected.get_header('Accept'),'application/octet-stream')
        with self.assertRaises(ValueError):
            handler.redirect_request(redirected,None,302,'Found',{},'https://'+host+'/artifacts-downloads/another')

    def test_blob_redirect_rejects_other_origins_credentials_paths_and_queries(self):
        host='us-central1-docker.pkg.dev';source='/v2/project/repo/image/blobs/sha256:'+'1'*64
        original=urllib.request.Request('https://'+host+source,headers={'Authorization':'Bearer unit-test-only'})
        handler=proposal._BlobRedirect(host,source)
        for target in ['http://'+host+'/artifacts-downloads/token',
                       'https://other.invalid/artifacts-downloads/token',
                       'https://user:password@'+host+'/artifacts-downloads/token',
                       'https://'+host+'/unreviewed/token',
                       'https://'+host+'/artifacts-downloads/token?key=unit-only',
                       'https://'+host+'/artifacts-downloads/%2e%2e/elsewhere']:
            with self.subTest(target=target),self.assertRaises(ValueError):
                handler.redirect_request(original,None,302,'Found',{},target)

    def test_second_exact_documented_execution_view_link_is_recorded_not_followed(self):
        registry=fixture([(proposal.PREFIX+'build-evidence/execution-view/node_modules',
                           '/app/fhe-pod/node_modules','symlink')],skip_link=True)
        plan=self.plan(registry)
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)/'export'
            report=proposal.extract(registry,plan,destination,approved=True)
            self.assertEqual(len(report['skippedLinks']),2)
            self.assertFalse((destination/'build-evidence/execution-view/node_modules').exists())
            self.assertEqual(len(list(destination.glob('verified-layer-*.local.json'))),2)

    def test_linux_optional_flag_adaptation_reconstructs_exact_original_lock(self):
        original={'packages':{'node_modules/ganache/node_modules/fsevents':
                  {'version':'2.3.2','os':['darwin'],'extraneous':True}}}
        original_bytes=(json.dumps(original,indent=2)+'\n').encode()
        changed=json.loads(original_bytes);changed['packages']['node_modules/ganache/node_modules/fsevents']['optional']=True
        for malicious in [False,True]:
            with self.subTest(unrecorded_change=malicious):
                adapted=json.loads(json.dumps(changed))
                if malicious:adapted['unrecordedDependencyChange']=True
                adapted_bytes=(json.dumps(adapted,indent=2)+'\n').encode()
                adaptation={'entry':'node_modules/ganache/node_modules/fsevents','changedVersions':False,
                            'originalSha256':hashed(original_bytes),'adaptedSha256':hashed(adapted_bytes)}
                installed={'original.mjs':{'sha256':hashed(b'original')},'distributed/worker.mjs':{'sha256':hashed(b'worker')},
                           'fhe-pod/package-lock.json':{'sha256':hashed(adapted_bytes)}}
                record={'targetPlatform':'linux/amd64','localSource':{'original.mjs':hashed(b'original'),
                         'fhe-pod/package-lock.json':hashed(original_bytes)},'distributedSource':{'worker.mjs':hashed(b'worker')}}
                extra=[(proposal.PREFIX+'build-evidence/fhe-pod-package-lock.json',adapted_bytes,'file'),
                       (proposal.PREFIX+'build-evidence/js-lock-adaptation.json',raw_json(adaptation),'file')]
                registry=fixture(extra,installed=installed,source_record=record);plan=self.plan(registry)
                with tempfile.TemporaryDirectory() as temporary:
                    destination=Path(temporary)/'export'
                    if malicious:
                        with self.assertRaises(ValueError):proposal.extract(registry,plan,destination,approved=True)
                        failure=json.loads((destination/'failed-preservation.local.json').read_text())
                        self.assertEqual(len(failure['verifiedLayers']),2)
                        self.assertIn('lastArchiveEntry',failure)
                    else:self.assertEqual(proposal.extract(registry,plan,destination,approved=True)['status'],'preserved-and-verified')


if __name__=='__main__':unittest.main()
