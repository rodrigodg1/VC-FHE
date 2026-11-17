"""Private post-run archive worker. Standard library only, no KMS operations."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import subprocess
import sys
import tarfile
import time
import io
import traceback
import urllib.parse
import urllib.request


def hashes(path):
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            sha.update(block)
            md5.update(block)
    return sha.hexdigest(), base64.b64encode(md5.digest()).decode()


def archive_info(path, campaign, host):
    """Same allowed members and byte inventory as the local backup verifier."""
    members, total, seen, marker = [], 0, set(), None
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or '..' in name.parts or '\\' in member.name
                    or (name.parts and name.parts[0] not in {campaign, 'scope.txt', 'bootstrap-evidence', 'lost+found'})
                    or not (member.isdir() or member.isfile()) or member.name in seen or str(name) in seen):
                raise ValueError('Unsafe, duplicate or out-of-scope archive entry')
            seen.add(str(name))
            if member.isfile():
                digest, count = hashlib.sha256(), 0
                stream = archive.extractfile(member)
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
                    count += len(block)
                    if str(name) == 'scope.txt':
                        if member.size > 1024:
                            raise ValueError('Invalid scope marker size')
                        marker = (marker or b'') + block
                if count != member.size:
                    raise ValueError('Truncated archive')
                total += count
                members.append({'path': member.name, 'bytes': count, 'sha256': digest.hexdigest()})
    if marker is None or marker.decode().strip() != campaign + '/' + host:
        raise ValueError('Archive does not belong to this exact host')
    sha, md5 = hashes(path)
    return {'sha256': sha, 'md5Hash': md5, 'archiveBytes': Path(path).stat().st_size,
            'fileBytes': total, 'files': members}


def metadata(name):
    req = urllib.request.Request('http://metadata.google.internal/computeMetadata/v1/' + name,
                                 headers={'Metadata-Flavor': 'Google'})
    with urllib.request.urlopen(req, timeout=15) as response:
        if response.headers.get('Metadata-Flavor') != 'Google':
            raise ValueError('Untrusted instance metadata response')
        return response.read().decode()


def token():
    return json.loads(metadata('instance/service-accounts/default/token'))['access_token']


def connection():
    return http.client.HTTPSConnection('storage.googleapis.com', timeout=180, context=ssl.create_default_context())


def object_path(bucket, name, *, media=False, generation=None):
    path = '/storage/v1/b/' + urllib.parse.quote(bucket, safe='') + '/o/' + urllib.parse.quote(name, safe='')
    query = {}
    if media:
        query['alt'] = 'media'
    if generation is not None:
        query['generation'] = str(generation)
    return path + ('?' + urllib.parse.urlencode(query) if query else '')


def describe(bucket, name, generation=None):
    conn = connection()
    try:
        conn.request('GET', object_path(bucket, name, generation=generation), headers={'Authorization': 'Bearer ' + token()})
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError('Archive object metadata request failed, HTTP ' + str(response.status))
        return json.loads(response.read())
    finally:
        conn.close()


def upload(path, bucket, name, info):
    """Create only. Server verifies the MD5 header, then read back exact generation."""
    conn = connection()
    try:
        destination = '/' + urllib.parse.quote(bucket, safe='') + '/' + urllib.parse.quote(name, safe='/')
        conn.putrequest('PUT', destination)
        for key, value in {'Authorization': 'Bearer ' + token(), 'Content-Type': 'application/x-tar',
                           'Content-Length': str(info['archiveBytes']), 'Content-MD5': info['md5Hash'],
                           'x-goog-if-generation-match': '0', 'Cache-Control': 'no-store',
                           'x-goog-meta-vcfhe-sha256': info['sha256']}.items():
            conn.putheader(key, value)
        conn.endheaders()
        with Path(path).open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                conn.send(block)
        response = conn.getresponse()
        response.read()
        if response.status not in (200, 201):
            raise ValueError('Create-only archive upload failed, HTTP ' + str(response.status))
    finally:
        conn.close()
    result = describe(bucket, name)
    if (result.get('bucket') != bucket or result.get('name') != name
            or result.get('md5Hash') != info['md5Hash'] or int(result.get('size', -1)) != info['archiveBytes']
            or result.get('metadata', {}).get('vcfhe-sha256') != info['sha256']
            or not str(result.get('generation', '')).isdecimal()):
        raise ValueError('Uploaded archive metadata mismatch')
    return result


def readback(bucket, name, generation, destination):
    conn = connection()
    try:
        conn.request('GET', object_path(bucket, name, media=True, generation=generation),
                     headers={'Authorization': 'Bearer ' + token()})
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError('Exact-generation archive readback failed, HTTP ' + str(response.status))
        with Path(destination).open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
    finally:
        conn.close()


def perform(job, directory):
    campaign, host = job['campaign'], job['host']
    probe = job.get('mode') == 'preflight'
    if (not re.fullmatch(r'[a-z][a-z0-9-]{2,20}', campaign) or not re.fullmatch(r'host-[1-4]', host)
            or not re.fullmatch(r'vcfhe-evidence-[a-f0-9]{20}', job['bucket'])
            or not re.fullmatch(r'runs/[a-f0-9]{32}/host-[1-4]/' + ('preflight' if probe else 'private-state') + r'\.tar', job['object'])
            or job['object'].split('/')[2] != host):
        raise ValueError('Invalid private archive scope')
    if (metadata('instance/id').strip() != job['instanceId']
            or metadata('instance/service-accounts/default/email').strip() != job['serviceAccount']):
        raise ValueError('Instance or service-account identity changed')
    root = Path('/srv/vcfhe')
    if (root / 'scope.txt').read_text().strip() != campaign + '/' + host:
        raise ValueError('Foreign participant-state mount')
    subprocess.run(['mountpoint', '-q', str(root)], check=True)
    running = subprocess.check_output(['docker', 'ps', '-q', '--filter',
                                      'label=com.docker.compose.project=' + campaign + '-' + host], text=True)
    if running.strip() and not probe:
        raise ValueError('Participant containers are not quiescent')
    path = directory / 'private-state.tar'
    with path.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        if probe:
            with tarfile.open(fileobj=output, mode='w') as tar:
                for name, data in [('scope.txt', (campaign + '/' + host).encode()),
                                   (campaign + '/storage-preflight', b'synthetic archive, no protocol state')]:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
        else:
            subprocess.run(['tar', '--one-file-system', '-cf', '-', '-C', str(root), '.'], stdout=output, check=True)
        output.flush()
        os.fsync(output.fileno())
    info = archive_info(path, campaign, host)
    if info['archiveBytes'] > job['maximumArchiveBytes']:
        raise ValueError('Private archive exceeds the admitted cloud storage allowance')
    # Only IAM propagation reads are retried. No upload or protocol call repeats.
    deadline = time.monotonic() + 600
    while True:
        conn = connection()
        try:
            conn.request('GET', object_path(job['bucket'], job['object']), headers={'Authorization': 'Bearer ' + token()})
            response = conn.getresponse()
            status = response.status
            response.read()
        finally:
            conn.close()
        if status == 404:
            break
        if status != 403 or time.monotonic() >= deadline:
            raise ValueError('Archive prefix access unavailable or object already exists')
        time.sleep(10)
    stored = upload(path, job['bucket'], job['object'], info)
    returned = directory / 'readback.tar'
    readback(job['bucket'], job['object'], stored['generation'], returned)
    if archive_info(returned, campaign, host) != info:
        raise ValueError('Cloud readback bytes or archive inventory differ')
    return {'status': 'probe-verified-cloud-readback' if probe else 'verified-cloud-readback', 'host': host, 'instanceId': job['instanceId'],
            'serviceAccount': job['serviceAccount'], 'bucket': job['bucket'], 'object': job['object'],
            'generation': stored['generation'], **info}


def main():
    os.umask(0o077)
    directory = Path(sys.argv[1])
    if directory.is_symlink() or any(p.is_symlink() for p in directory.parents):
        raise ValueError('Archive worker path must not contain symlinks')
    job = json.loads((directory / 'job.local.json').read_text())
    try:
        result = perform(job, directory)
        state = {'status': 'passed', 'receipt': result}
    except BaseException as error:
        traceback.print_exc()
        state = {'status': 'failed', 'errorType': type(error).__name__, 'errorMessage': str(error)}
    temporary = directory / 'result.local.pending'
    with temporary.open('x') as output:
        json.dump(state, output)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(directory / 'result.local.json')
    return 0 if state['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
