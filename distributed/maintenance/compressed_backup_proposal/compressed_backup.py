"""Offline compressed-backup primitives. No cloud or cleanup operations.

The receipt is deliberately distinct from the frozen backup.local.json format.
Compression is not encryption. Every output remains private protocol state.
"""
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zlib

SCHEMA = 'vcfhe-private-compressed-recovery-v1'
HOSTS = {f'host-{i}' for i in range(1, 5)}


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def private_file(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError('Use physical private paths without compatibility symlinks')
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError('Private backup file must be regular mode 0600')
    return path


def private_directory(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError('Use physical private paths without compatibility symlinks')
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('Private backup directory must have mode 0700')
    return path


class SingleGzipReader:
    """Bounded decompression with CRC, end-of-member and trailing-data checks."""
    def __init__(self, source, maximum_bytes=None):
        self.source = source
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.pending = b''
        self.buffer = bytearray()
        self.finished = False
        self.bytes = 0
        self.hash = hashlib.sha256()
        self.tail = b''
        self.maximum_bytes = maximum_bytes

    def read(self, size):
        if size < 0:
            raise ValueError('Bounded gzip reads are required')
        while len(self.buffer) < size and not self.finished:
            if not self.pending:
                self.pending = self.source.read(65536)
                if not self.pending:
                    raise ValueError('Truncated gzip member')
            try:
                block = self.decoder.decompress(self.pending, 65536)
            except zlib.error as error:
                raise ValueError('Invalid gzip data or CRC') from error
            self.pending = self.decoder.unconsumed_tail
            if (self.maximum_bytes is not None
                    and self.bytes + len(self.buffer) + len(block) > self.maximum_bytes):
                raise ValueError('Decompressed TAR exceeds its frozen byte allowance')
            self.buffer.extend(block)
            if self.decoder.eof:
                if self.decoder.unused_data or self.pending or self.source.read(1):
                    raise ValueError('Trailing data or concatenated gzip members')
                self.finished = True
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        self.bytes += len(result)
        self.hash.update(result)
        self.tail = (self.tail + result)[-65536:]
        return result


def inspect_archive(path, *, campaign=None, host=None, maximum_uncompressed_bytes=None):
    """Inspect every file without extraction and consume the complete gzip CRC."""
    path = private_file(path)
    if (campaign is None) != (host is None) or host is not None and host not in HOSTS:
        raise ValueError('Exact campaign and host scope are required together')
    if (campaign is not None and (not re.fullmatch(r'[a-z][a-z0-9-]{2,20}', campaign)
                                 or not campaign.endswith('-smoke'))):
        raise ValueError('Private recovery is restricted to a separate smoke campaign')
    if (maximum_uncompressed_bytes is not None
            and (type(maximum_uncompressed_bytes) is not int or maximum_uncompressed_bytes <= 0)):
        raise ValueError('Invalid frozen decompressed-byte allowance')
    files, metadata, seen, marker, last_end = [], [], set(), None, 0
    allowed = {campaign, 'scope.txt', 'bootstrap-evidence', 'lost+found'}
    with path.open('rb') as source:
        stream = SingleGzipReader(source, maximum_uncompressed_bytes)
        try:
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                for member in archive:
                    name = PurePosixPath(member.name)
                    normalized = str(name)
                    if (name.is_absolute() or '..' in name.parts or '\\' in member.name
                            or '\x00' in member.name or normalized in seen
                            or not (member.isdir() or member.isfile())
                            or member.isdir() and member.size != 0
                            or campaign is not None and name.parts and name.parts[0] not in allowed):
                        raise ValueError('Unsafe, duplicate or out-of-scope TAR member')
                    seen.add(normalized)
                    last_end = max(last_end, member.offset_data + ((member.size + 511)//512)*512)
                    metadata.append({'path': member.name, 'mode': member.mode, 'uid': member.uid,
                                     'gid': member.gid, 'mtime': member.mtime,
                                     'kind': 'directory' if member.isdir() else 'file'})
                    if member.isfile():
                        body = archive.extractfile(member)
                        value = hashlib.sha256()
                        count, marker_parts = 0, []
                        for block in iter(lambda: body.read(1024 * 1024), b''):
                            count += len(block); value.update(block)
                            if normalized == 'scope.txt':
                                if count > 1024:
                                    raise ValueError('Oversized scope marker')
                                marker_parts.append(block)
                        if count != member.size:
                            raise ValueError('Truncated TAR file')
                        files.append({'path': member.name, 'bytes': count, 'sha256': value.hexdigest()})
                        if normalized == 'scope.txt':
                            marker = b''.join(marker_parts).decode().strip()
        except (tarfile.TarError, EOFError, UnicodeError) as error:
            raise ValueError('Invalid or truncated TAR stream') from error
        # TAR parsers may stop before the gzip trailer. Verify all remaining
        # bytes, including CRC/length, and reject hidden data after TAR finality.
        start = stream.bytes - len(stream.tail)
        if last_end < start or any(stream.tail[max(0, last_end-start):]):
            raise ValueError('Unparsed data after the final TAR member')
        for block in iter(lambda: stream.read(65536), b''):
            if any(block):
                raise ValueError('Nonzero data after TAR end markers')
        if stream.bytes % 512 or stream.bytes < last_end + 1024:
            raise ValueError('TAR lacks two complete end markers')
        if campaign is not None and marker != campaign + '/' + host:
            raise ValueError('Archived scope marker differs from the original host')
        return {'sha256': sha(path), 'archiveBytes': path.stat().st_size,
                'uncompressedTarSha256': stream.hash.hexdigest(),
                'uncompressedTarBytes': stream.bytes, 'fileBytes': sum(f['bytes'] for f in files),
                'files': files, 'metadata': metadata, 'crcVerified': True,
                'singleGzipMember': True}


class LimitedSink:
    def __init__(self, output, maximum):
        self.output, self.maximum, self.bytes = output, maximum, 0

    def write(self, data):
        if self.bytes + len(data) > self.maximum:
            raise ValueError('Compressed backup exceeds the explicit local byte allowance')
        result = self.output.write(data)
        self.bytes += result
        return result

    def flush(self):
        self.output.flush()


def compress_stream(source, destination, *, maximum_bytes, campaign=None, host=None):
    """Stream losslessly to a fresh private file without a full local raw TAR.

    A failed or interrupted output remains private and unverified. It never
    creates a recovery receipt and never replaces an existing file.
    """
    destination = Path(destination).absolute()
    private_directory(destination.parent)
    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise ValueError('A positive, explicit compressed-byte allowance is required')
    raw_sha, raw_bytes = hashlib.sha256(), 0
    with destination.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        sink = LimitedSink(output, maximum_bytes)
        with gzip.GzipFile(filename='', fileobj=sink, mode='wb', compresslevel=1, mtime=0) as compressed:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                raw_sha.update(block); raw_bytes += len(block); compressed.write(block)
        output.flush(); os.fsync(output.fileno())
    actual = inspect_archive(destination, campaign=campaign, host=host,
                             maximum_uncompressed_bytes=raw_bytes)
    if actual['uncompressedTarSha256'] != raw_sha.hexdigest() or actual['uncompressedTarBytes'] != raw_bytes:
        raise ValueError('Compressed archive does not exactly reproduce its source TAR')
    return actual


def _read(path):
    return json.loads(private_file(path).read_text())


def verify_contents(directory, expected_binding_sha256):
    """Validate four hosts, exact inventories, quiescence binding and evidence.

    The caller must obtain the binding/inventories from the original frozen
    stopped-state snapshot. Offline verification cannot observe the cloud.
    """
    directory = private_directory(directory)
    names = ({h+'-private-state.tar.gz' for h in HOSTS}
             | {'original-run-evidence.tar.gz', 'plan.local.json', 'quiescence.local.json',
                'original-binding.local.json', 'compressed-recovery.local.json'})
    if any(p.name not in names for p in directory.iterdir()):
        raise ValueError('Unknown file in compressed recovery directory')
    for path in directory.iterdir(): private_file(path)
    binding_file = directory/'original-binding.local.json'
    if sha(binding_file) != expected_binding_sha256:
        raise ValueError('Original recovery binding changed')
    binding = _read(binding_file)
    plan, quiet = _read(directory/'plan.local.json'), _read(directory/'quiescence.local.json')
    if (binding.get('schema') != 'vcfhe-compressed-recovery-binding-v1'
            or set(binding['hosts']) != HOSTS or set(quiet['hosts']) != HOSTS
            or len(plan['hosts']) != 4 or {h['id'] for h in plan['hosts']} != HOSTS
            or sha(directory/'plan.local.json') != binding['planSha256']
            or sha(directory/'quiescence.local.json') != binding['quiescenceSha256']):
        raise ValueError('Incomplete or changed four-host recovery scope')
    for field in ('campaign', 'run', 'configSha256', 'terraformStateSha256'):
        if plan.get(field) != binding.get(field) or quiet.get(field) != binding.get(field):
            raise ValueError('Snapshot, quiescence and frozen plan bindings differ')
    result = {}
    for host in sorted(HOSTS):
        proof = quiet['hosts'][host]
        expected = binding['hosts'][host]
        if (proof.get('scope') != binding['campaign']+'/'+host
                or proof.get('runningContainers') != [] or proof.get('samplerRunning') is not False
                or proof.get('snapshotAfterStopAndSync') is not True
                or proof.get('inventorySha256') != digest(expected['files'])):
            raise ValueError('Missing exact stopped-state snapshot evidence')
        actual = inspect_archive(directory/(host+'-private-state.tar.gz'),
                                 campaign=binding['campaign'], host=host,
                                 maximum_uncompressed_bytes=expected['uncompressedTarBytes'])
        for key in ('uncompressedTarSha256', 'uncompressedTarBytes', 'files'):
            if actual[key] != expected[key]:
                raise ValueError('Recovered archive differs from the frozen host inventory')
        result[host] = actual
    evidence = inspect_archive(directory/'original-run-evidence.tar.gz',
                               maximum_uncompressed_bytes=binding['evidence']['uncompressedTarBytes'])
    for key in ('uncompressedTarSha256', 'uncompressedTarBytes', 'files'):
        if evidence[key] != binding['evidence'][key]:
            raise ValueError('Original run evidence differs from its frozen snapshot')
    return {'schema': SCHEMA, 'status': 'verified-compressed-recovery',
            'sensitivity': 'unencrypted-secret-protocol-state',
            'bindingSha256': expected_binding_sha256, 'archives': result, 'evidence': evidence,
            'frozenCleanupSourceSha256': binding['frozenCleanupSourceSha256'],
            'originalSourceClosureSha256': binding['originalSourceClosureSha256'],
            'originalBackupStatusChanged': False, 'originalBackupVerifierPassed': False,
            'cleanupAuthorized': False,
            'scope': 'Lossless content and provided stopped-state evidence verified offline. '
                     'Live ownership, quiescence provenance and cleanup require separate review.'}


def write_receipt(directory, expected_binding_sha256):
    directory = private_directory(directory)
    value = verify_contents(directory, expected_binding_sha256)
    value['createdAt'] = datetime.now(timezone.utc).isoformat()
    target = directory/'compressed-recovery.local.json'
    with target.open('x') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, indent=2); output.write('\n')
        output.flush(); os.fsync(output.fileno())
    handle = os.open(directory, os.O_RDONLY)
    try: os.fsync(handle)
    finally: os.close(handle)
    return value
