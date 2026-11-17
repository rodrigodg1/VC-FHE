"""Controller-only proposal: preserve selected original image files without execution.

Inspection downloads only manifests and a bounded image configuration. Extraction
requires separate approval. It streams layers without a full-image disk spool,
never launches containers and never creates, changes or removes cloud resources.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = 'vcfhe-registry-evidence-proposal-v1'
MANIFESTS = {'application/vnd.oci.image.manifest.v1+json',
             'application/vnd.docker.distribution.manifest.v2+json'}
INDEXES = {'application/vnd.oci.image.index.v1+json',
           'application/vnd.docker.distribution.manifest.list.v2+json'}
CONFIGS = {'application/vnd.oci.image.config.v1+json',
           'application/vnd.docker.container.image.v1+json'}
LAYERS = {'application/vnd.oci.image.layer.v1.tar': False,
          'application/vnd.oci.image.layer.v1.tar+gzip': True,
          'application/vnd.docker.image.rootfs.diff.tar.gzip': True}
BINARIES = ('kms-campaign', 'kms-server', 'kms-gen-keys', 'kms-init')
PREFIX = 'app/threshold-kms/campaign/'
DEFAULT_LIMITS = {'manifestBytes': 4 * 1024**2, 'configurationBytes': 4 * 1024**2,
                  'layerBytes': 2 * 1024**3, 'uncompressedLayerBytes': 8 * 1024**3,
                  'selectedFileBytes': 512 * 1024**2,
                  'selectedTotalBytes': 2 * 1024**3, 'entries': 500000}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def _write(path, value):
    with Path(path).open('x') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def _descriptor(value, types, limit):
    if (not isinstance(value, dict) or value.get('mediaType') not in types
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', value.get('digest', ''))
            or type(value.get('size')) is not int or not 0 < value['size'] <= limit
            or value.get('urls') or value.get('data')):
        raise ValueError('Unsupported, external or unbounded OCI descriptor')
    return value


def _bytes(raw, descriptor):
    if len(raw) != descriptor['size'] or 'sha256:' + hashlib.sha256(raw).hexdigest() != descriptor['digest']:
        raise ValueError('OCI descriptor bytes do not match their digest and size')


def _reference(value):
    match = re.fullmatch(r'([a-z0-9-]+-docker\.pkg\.dev)/([a-z0-9-]+)/([a-z0-9-]+)/([a-z0-9_./-]+)@(sha256:[a-f0-9]{64})', value)
    if not match or '..' in match[4].split('/'):
        raise ValueError('An immutable Google Artifact Registry image reference is required')
    return match


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('Registry redirects require separate review. No credential is forwarded')


class _BlobRedirect(urllib.request.HTTPRedirectHandler):
    """One reviewed Artifact Registry download redirect, without OAuth forwarding."""
    def __init__(self, host, source_path):
        self.host, self.source_path = host, source_path

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        original, target = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(newurl)
        decoded = urllib.parse.unquote(target.path)
        if (code != 302 or request.get_method() != 'GET'
                or original.scheme != 'https' or original.netloc != self.host or original.path != self.source_path
                or target.scheme != 'https' or target.netloc != self.host
                or not target.path.startswith('/artifacts-downloads/') or target.query or target.fragment
                or any(part in {'.', '..'} for part in decoded.split('/'))):
            raise ValueError('Unreviewed registry blob redirect refused')
        # A signed download path is an in-memory capability. Do not log or
        # persist it. Never forward the initial OAuth Authorization header.
        return urllib.request.Request(newurl, headers={'Accept': 'application/octet-stream'}, method='GET')


class Registry:
    """Authenticated GETs scoped to one image. OAuth credentials stay in memory."""
    def __init__(self, reference, gcloud='gcloud'):
        match = _reference(reference)
        self.reference = reference
        self.host, self.repository = match[1], '/'.join(match.group(i) for i in (2, 3, 4))
        self._token = subprocess.check_output([gcloud, 'auth', 'print-access-token'], text=True).strip()
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _get(self, kind, value):
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
            raise ValueError('Invalid registry digest')
        url = 'https://' + self.host + '/v2/' + self.repository + '/' + kind + '/' + value
        request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + self._token,
            'Accept': ', '.join(sorted(MANIFESTS | INDEXES))})
        opener = (urllib.request.build_opener(_BlobRedirect(self.host, urllib.parse.urlsplit(url).path))
                  if kind == 'blobs' else self._opener)
        try:
            return opener.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            raise ValueError('Registry read failed with HTTP status ' + str(error.code)) from None

    def manifest(self, reference):
        if reference.rsplit('@', 1)[0] != self.reference.rsplit('@', 1)[0]:
            raise ValueError('Manifest reference escapes the scoped image')
        expected = _reference(reference)[5]
        with self._get('manifests', expected) as response:
            raw = response.read(DEFAULT_LIMITS['manifestBytes'] + 1)
        if len(raw) > DEFAULT_LIMITS['manifestBytes'] or 'sha256:' + hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Manifest is too large or its pinned digest differs')
        return json.loads(raw), expected, raw

    def blob(self, value):
        return self._get('blobs', value)


def inspect_image(client, reference, source_record, limits=None, *, expected_worker_sha256=None):
    """Read metadata only. No layer blob is requested by this function."""
    _reference(reference)
    bounds = dict(DEFAULT_LIMITS, **(limits or {}))
    if (set(bounds) != set(DEFAULT_LIMITS) or any(type(value) is not int or not 0 < value <= DEFAULT_LIMITS[key]
                                                for key, value in bounds.items())):
        raise ValueError('Inspection limits may only reduce the admitted bounds')
    if source_record.get('targetPlatform') != 'linux/amd64':
        raise ValueError('Expected source platform is not Linux amd64')
    manifests = []
    manifest, pinned, raw = client.manifest(reference)
    if pinned != reference.rsplit('@', 1)[1] or 'sha256:' + hashlib.sha256(raw).hexdigest() != pinned:
        raise ValueError('Root manifest digest is not the pinned reference')
    manifests.append({'digest': pinned, 'raw': raw.decode()})
    if manifest.get('mediaType') in INDEXES:
        candidates = [row for row in manifest.get('manifests', [])
                      if row.get('platform', {}).get('os') == 'linux'
                      and row.get('platform', {}).get('architecture') == 'amd64']
        if len(candidates) != 1:
            raise ValueError('Exactly one Linux amd64 image is required')
        selected = _descriptor(candidates[0], MANIFESTS, bounds['manifestBytes'])
        manifest, pinned, raw = client.manifest(reference.rsplit('@', 1)[0] + '@' + selected['digest'])
        _bytes(raw, selected)
        if pinned != selected['digest']:
            raise ValueError('Selected platform manifest digest changed')
        manifests.append({'digest': pinned, 'raw': raw.decode()})
    if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') not in MANIFESTS:
        raise ValueError('Unsupported final image manifest')
    config = _descriptor(manifest.get('config'), CONFIGS, bounds['configurationBytes'])
    with client.blob(config['digest']) as stream:
        config_raw = stream.read(bounds['configurationBytes'] + 1)
    _bytes(config_raw, config)
    configuration = json.loads(config_raw)
    if configuration.get('os') != 'linux' or configuration.get('architecture') != 'amd64':
        raise ValueError('Actual image platform is not Linux amd64')
    layers = [_descriptor(row, LAYERS, bounds['layerBytes']) for row in manifest.get('layers', [])]
    rootfs = configuration.get('rootfs', {})
    if (not layers or rootfs.get('type') != 'layers' or len(rootfs.get('diff_ids', [])) != len(layers)
            or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', item) for item in rootfs['diff_ids'])):
        raise ValueError('Image rootfs does not match its layer descriptors')
    history = [row for row in configuration.get('history', []) if not row.get('empty_layer', False)]
    if len(history) != len(layers):
        raise ValueError('Image history does not match its layer descriptors')
    if expected_worker_sha256 is not None and not re.fullmatch(r'[a-f0-9]{64}', expected_worker_sha256):
        raise ValueError('Invalid original worker hash')
    plan = {'schema': SCHEMA, 'image': reference, 'platformManifestDigest': pinned,
            'sourceRecord': source_record, 'sourceRecordSha256': digest(source_record),
            'manifests': manifests, 'configuration': config_raw.decode(), 'configDescriptor': config,
            'layers': layers, 'history': history, 'limits': bounds,
            'compressedDownloadBytes': sum(row['size'] for row in layers),
            'extractedBytes': None,
            'maximumLocalWorkspaceBytes': bounds['selectedTotalBytes'] + bounds['selectedFileBytes'] + 16 * 1024**2,
            'extractedCapacityNote': 'Exact selected-file sizes are unavailable without reading layers. selectedTotalBytes is a fail-closed upper limit, not a measured estimate.',
            'mode': 'all-layer-streaming-selected-files-no-image-spool',
            'expectedWorkerSha256': expected_worker_sha256}
    plan['planSha256'] = digest(plan)
    return plan


class _Counted:
    def __init__(self, stream, maximum):
        self.stream, self.maximum, self.count = stream, maximum, 0
        self.hash = hashlib.sha256()

    def read(self, size=-1):
        block = self.stream.read(min(size if size >= 0 else 1024 * 1024, 1024 * 1024))
        self.count += len(block)
        if self.count > self.maximum:
            raise ValueError('OCI stream exceeds its admitted byte limit')
        self.hash.update(block)
        return block


def _path(name):
    path = PurePosixPath(name)
    if '\\' in name or '\x00' in name or path.is_absolute() or '..' in path.parts:
        raise ValueError('Unsafe OCI archive path')
    return str(path)


def _target(name):
    if name in {'usr/local/bin/' + item for item in BINARIES}:
        return 'bin/' + PurePosixPath(name).name
    if name == PREFIX + 'distributed-adapter.json':
        return 'distributed-adapter.json'
    if name == PREFIX + 'build-evidence' or name.startswith(PREFIX + 'build-evidence/'):
        return name[len(PREFIX):]
    return None


def _whiteout_touches_selected(name):
    path = PurePosixPath(name)
    if not path.name.startswith('.wh.'):
        return False
    parent = str(path.parent)
    affected = parent if path.name == '.wh..wh..opq' else str(path.parent / path.name[4:])
    roots = ['usr/local/bin/' + item for item in BINARIES] + [PREFIX + 'distributed-adapter.json', PREFIX + 'build-evidence']
    return any(affected == '.' or root == affected or root.startswith(affected + '/') or affected.startswith(root + '/') for root in roots)


def _selected_ancestor(name):
    roots = ['usr/local/bin/' + item for item in BINARIES] + [PREFIX + 'distributed-adapter.json', PREFIX + 'build-evidence']
    return name == '.' or any(root.startswith(name + '/') for root in roots)


def _validate_bindings(directory, plan):
    directory = Path(directory)
    record = plan['sourceRecord']
    adapter = json.loads((directory/'distributed-adapter.json').read_text())
    adapted = adapter.get('files', {})
    if adapter.get('protocolRulesChanged') is not False or adapter.get('localSourceEdited') is not False:
        raise ValueError('Unexpected distributed runtime adapter record')
    with gzip.open(directory/'build-evidence/installed-files.json.gz', 'rt') as stream:
        installed = json.load(stream)
    locks = {'fhe-pod/package-lock.json': 'build-evidence/fhe-pod-package-lock.json',
             'BN254-Signatures/package-lock.json': 'build-evidence/BN254-Signatures-package-lock.json'}
    for name, original in record['localSource'].items():
        if name in locks:
            actual = sha(directory/locks[name])
            if name == 'fhe-pod/package-lock.json' and actual != original:
                adaptation = json.loads((directory/'build-evidence/js-lock-adaptation.json').read_text())
                lock_bytes = (directory/locks[name]).read_bytes()
                lock = json.loads(lock_bytes)
                entry_name = 'node_modules/ganache/node_modules/fsevents'
                entry = lock.get('packages', {}).get(entry_name, {})
                if (adaptation.get('entry') != entry_name or adaptation.get('changedVersions') is not False
                        or adaptation.get('originalSha256') != original or adaptation.get('adaptedSha256') != actual
                        or entry.get('version') != '2.3.2' or entry.get('os') != ['darwin']
                        or entry.get('extraneous') is not True or entry.get('optional') is not True
                        or (json.dumps(lock, indent=2)+'\n').encode() != lock_bytes):
                    raise ValueError('Installed Linux lock adaptation differs from its recorded transformation')
                # Reconstruct the exact original file, rather than trusting an
                # adaptation record to authorize arbitrary dependency changes.
                del entry['optional']
                if hashlib.sha256((json.dumps(lock, indent=2)+'\n').encode()).hexdigest() != original:
                    raise ValueError('Linux lock adaptation changed more than the recorded optional flag')
            elif actual != original:
                raise ValueError('Original dependency lock differs from the source record')
            if installed.get(name, {}).get('sha256') != actual:
                raise ValueError('Installed lock inventory differs from its preserved bytes')
        elif name in adapted:
            if (adapted[name].get('sourceSha256') != original
                    or installed.get(name, {}).get('sha256') != adapted[name].get('adaptedSha256')):
                raise ValueError('Installed adapted file differs from its original and adapted binding')
        elif installed.get(name, {}).get('sha256') != original:
            raise ValueError('Installed file differs from the original source binding')
    for name, original in record['distributedSource'].items():
        if installed.get('distributed/' + name, {}).get('sha256') != original:
            raise ValueError('Installed distributed source differs from the original image record')
    original_lock = record.get('buildInputs', {}).get('upstream/Cargo.lock', {}).get('sha256')
    if original_lock and sha(directory/'build-evidence/Cargo.lock') != original_lock:
        raise ValueError('Original Cargo lock differs from the image input')
    original_adapter = record.get('buildInputs', {}).get('upstream/vcfhe-adapter.json', {}).get('sha256')
    if original_adapter and sha(directory/'build-evidence/vcfhe-adapter.json') != original_adapter:
        raise ValueError('Original native adaptation evidence differs from the image input')
    if plan.get('expectedWorkerSha256') and sha(directory/'bin/kms-campaign') != plan['expectedWorkerSha256']:
        raise ValueError('Preserved worker differs from the failed-run enrolled identity')


def extract(client, plan, destination, *, approved=False):
    """Stream all layers, retaining only original bins and build evidence.

    Relevant whiteouts fail closed. A known build-time runtime-cache symlink is
    recorded and omitted exactly as in the original collector. No other selected
    symlink, hardlink, device, non-root file or set-id permission is accepted.
    """
    if approved is not True:
        raise ValueError('Large layer download requires separate explicit approval')
    candidate = dict(plan)
    claimed = candidate.pop('planSha256', None)
    if claimed != digest(candidate) or digest(plan['sourceRecord']) != plan['sourceRecordSha256']:
        raise ValueError('Inspection plan or source record changed')
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Use a fresh private export destination')
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(destination, 0o700)
    _write(destination/'inspection.local.json', plan)
    files, skipped, layer_reports, last_entry = {}, [], [], None
    limits = plan['limits']
    try:
        for index, descriptor in enumerate(plan['layers']):
            seen = set()
            with client.blob(descriptor['digest']) as incoming:
                compressed = _Counted(incoming, descriptor['size'])
                decoded = gzip.GzipFile(fileobj=compressed) if LAYERS[descriptor['mediaType']] else compressed
                uncompressed = _Counted(decoded, limits['uncompressedLayerBytes'])
                with tarfile.open(fileobj=uncompressed, mode='r|') as archive:
                    for ordinal, member in enumerate(archive):
                        if ordinal >= limits['entries']:
                            raise ValueError('OCI layer contains too many entries')
                        last_entry = {'layer': index, 'path': member.name, 'tarType': member.type.decode('ascii', errors='replace'),
                                      'uid': member.uid, 'gid': member.gid, 'mode': member.mode,
                                      'linkTarget': member.linkname, 'sparse': member.sparse is not None}
                        name = _path(member.name)
                        if _whiteout_touches_selected(name):
                            raise ValueError('A whiteout affects selected evidence. Manual overlay review is required')
                        if _selected_ancestor(name) and not member.isdir():
                            raise ValueError('A selected parent path is not an image directory')
                        target = _target(name)
                        if target is None:
                            continue
                        if target == 'build-evidence' and not member.isdir():
                            raise ValueError('The selected build-evidence root is not a directory')
                        if name in seen:
                            raise ValueError('Duplicate selected path within one image layer')
                        seen.add(name)
                        if member.isdir():
                            continue
                        known_links = {PREFIX+'build-evidence/execution-view/contracts/out':'/tmp/vcfhe-compiled-contracts',
                                       PREFIX+'build-evidence/execution-view/node_modules':'/app/fhe-pod/node_modules'}
                        if member.issym() and known_links.get(name) == member.linkname:
                            skipped.append({'path': name, 'target': member.linkname, 'layer': index,
                                'reason': 'Original collector removes this build-time execution-view symlink'})
                            continue
                        if not member.isfile() or member.sparse is not None or member.uid != 0 or member.gid != 0 or member.mode & 0o7000:
                            raise ValueError('Selected image entry has unsupported type, ownership or permissions')
                        if member.size > limits['selectedFileBytes']:
                            raise ValueError('Selected file exceeds the admitted file size')
                        final_total = sum(row['bytes'] for key, row in files.items() if key != target) + member.size
                        if final_total > limits['selectedTotalBytes']:
                            raise ValueError('Selected evidence exceeds the admitted capacity')
                        output = destination/target
                        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        pending = output.with_name(output.name + '.layer-' + str(index) + '.pending')
                        content = hashlib.sha256()
                        count = 0
                        with pending.open('xb') as saved:
                            os.fchmod(saved.fileno(), 0o600)
                            stream = archive.extractfile(member)
                            for block in iter(lambda: stream.read(1024*1024), b''):
                                count += len(block)
                                content.update(block)
                                saved.write(block)
                            saved.flush()
                            os.fsync(saved.fileno())
                        if count != member.size:
                            raise ValueError('Selected file is truncated')
                        os.replace(pending, output)
                        files[target] = {'bytes': count, 'sha256': content.hexdigest(), 'imagePath': name,
                            'uid': member.uid, 'gid': member.gid, 'mode': member.mode, 'localMode': 0o600,
                            'layer': index, 'layerDigest': descriptor['digest']}
                while uncompressed.read(1024*1024):
                    pass
                while compressed.read(1024*1024):
                    pass
                if compressed.count != descriptor['size'] or 'sha256:'+compressed.hash.hexdigest() != descriptor['digest']:
                    raise ValueError('Full compressed layer differs from its descriptor')
                expected_diff = json.loads(plan['configuration'])['rootfs']['diff_ids'][index]
                if 'sha256:'+uncompressed.hash.hexdigest() != expected_diff:
                    raise ValueError('Uncompressed layer differs from the image rootfs')
                layer_reports.append({'digest': descriptor['digest'], 'bytes': compressed.count,
                                      'diffId': expected_diff, 'uncompressedBytes': uncompressed.count})
                _write(destination/('verified-layer-'+str(index)+'.local.json'),
                       {'schema': SCHEMA, 'status': 'layer-verified', 'descriptor': descriptor,
                        'layer': layer_reports[-1], 'selectedFiles': dict(files),
                        'partialFileProvenanceOnly': True})
        if any('bin/'+name not in files for name in BINARIES):
            raise ValueError('Image export lacks an original native executable')
        _validate_bindings(destination, plan)
        report = {'schema': SCHEMA, 'status': 'preserved-and-verified', 'image': plan['image'],
                  'planSha256': claimed, 'sourceRecordSha256': plan['sourceRecordSha256'],
                  'files': files, 'skippedLinks': skipped, 'layers': layer_reports,
                  'selectedBytes': sum(row['bytes'] for row in files.values()),
                  'cloudMutations': 0, 'containersStarted': 0, 'nativeExecutablesInvoked': 0}
        _write(destination/'preservation.local.json', report)
        return report
    except BaseException as error:
        _write(destination/'failed-preservation.local.json', {'schema': SCHEMA, 'status': 'failed',
            'errorType': type(error).__name__, 'planSha256': claimed,
            'passingSealCreated': False, 'partialFilesPreserved': True, 'lastArchiveEntry': last_entry,
            'verifiedLayers': layer_reports, 'selectedFiles': files, 'skippedLinks': skipped})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    inspect = sub.add_parser('inspect')
    inspect.add_argument('--receipt', required=True)
    inspect.add_argument('--source-record', required=True)
    inspect.add_argument('--expected-worker-sha256', required=True)
    inspect.add_argument('--output', required=True)
    inspect.add_argument('--gcloud', default='gcloud')
    copy = sub.add_parser('extract')
    copy.add_argument('--plan', required=True)
    copy.add_argument('--destination', required=True)
    copy.add_argument('--approve-download', action='store_true')
    copy.add_argument('--gcloud', default='gcloud')
    args = parser.parse_args()
    if args.operation == 'inspect':
        receipt = json.loads(Path(args.receipt).read_text())
        record = json.loads(Path(args.source_record).read_text())
        if receipt.get('buildStatus') != 'SUCCESS' or receipt.get('sourceSha256') != digest(record):
            raise ValueError('Receipt is not bound to the original successful image build')
        client = Registry(receipt['digest'], args.gcloud)
        plan = inspect_image(client, receipt['digest'], record, expected_worker_sha256=args.expected_worker_sha256)
        _write(args.output, plan)
        print(json.dumps({'status': 'metadata-inspected-only', 'layers': len(plan['layers']),
            'compressedDownloadBytes': plan['compressedDownloadBytes'], 'extractedBytes': None,
            'extractedUpperLimitBytes': plan['limits']['selectedTotalBytes'], 'largeBlobsDownloaded': 0}))
    else:
        if not args.approve_download:
            raise ValueError('Extraction requires --approve-download after reviewing the metadata plan')
        plan = json.loads(Path(args.plan).read_text())
        report = extract(Registry(plan['image'], args.gcloud), plan, args.destination, approved=True)
        print(json.dumps({'status': report['status'], 'selectedBytes': report['selectedBytes'],
                          'files': len(report['files']), 'cloudMutations': 0}))


if __name__ == '__main__':
    main()
