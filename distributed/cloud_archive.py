"""Explicit private GCS backup backend. Never changes or repeats protocol work."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import topology

SCHEMA = 'vcfhe-private-smoke-backup-gcs-v1'
HERE = Path(__file__).resolve().parent


def settings(config):
    value = config.get('cloud_archive')
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {'backend', 'location', 'maximum_gib', 'planning_days'}
            or value['backend'] != 'gcs' or value['location'] != config['regions'][0]['name']
            or type(value['maximum_gib']) is not int or not 1 <= value['maximum_gib'] <= 100
            or type(value['planning_days']) is not int or not 1 <= value['planning_days'] <= 90
            or config.get('execution_mode') != 'smoke' or config.get('layout') != 'four-hosts'):
        raise ValueError('Cloud archive requires an explicit private four-host smoke storage plan')
    return value


def check_quote(config, quote):
    value = settings(config)
    if value is None:
        return
    proof = quote.get('cloud_archive')
    if (not isinstance(proof, dict) or proof.get('plan') != value
            or float(proof.get('storage_and_operations_usd', 0)) <= 0
            or float(quote['retained_resources']) < float(proof['storage_and_operations_usd'])
            or not proof.get('source_urls') or not proof.get('network_in_existing_envelope')):
        raise ValueError('Private GCS retention, operations and network require explicit budget evidence')


def bucket_name(config):
    settings(config)
    return 'vcfhe-evidence-' + topology.digest({'project': config['project_id'], 'campaign': config['campaign']})[:20]


def api(config, path, method='GET', body=None):
    result = subprocess.run(['gcloud', 'auth', 'print-access-token', '--project', config['project_id']],
                            capture_output=True, text=True, check=True)
    token = result.stdout.strip()
    if not token:
        raise ValueError('Missing cloud archive authentication')
    request = urllib.request.Request('https://storage.googleapis.com/storage/v1/' + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError('Private archive API failed, HTTP ' + str(error.code)) from None


def validate_bucket(config, bucket, project_number):
    if (bucket.get('name') != bucket_name(config) or str(bucket.get('projectNumber')) != str(project_number)
            or bucket.get('location', '').lower() != settings(config)['location']
            or bucket.get('storageClass') != 'STANDARD'
            or bucket.get('iamConfiguration', {}).get('uniformBucketLevelAccess', {}).get('enabled') is not True
            or bucket.get('iamConfiguration', {}).get('publicAccessPrevention') != 'enforced'
            or bucket.get('labels', {}).get('vcfhe-purpose') != 'private-evidence'
            or bucket.get('labels', {}).get('vcfhe-campaign') != config['campaign']):
        raise ValueError('Private archive bucket identity, ownership or access controls differ')
    if bucket.get('lifecycle', {}).get('rule'):
        raise ValueError('Automatic evidence deletion rules are not admitted')
    return {'name': bucket['name'], 'projectNumber': str(bucket['projectNumber']),
            'id': bucket['id'], 'timeCreated': bucket['timeCreated'], 'location': bucket['location']}


def ensure_bucket(config, cloud):
    name = bucket_name(config)
    project = cloud(['projects', 'describe', config['project_id']])
    if project.get('projectId') != config['project_id']:
        raise ValueError('Foreign archive project')
    result = subprocess.run(['gcloud', 'storage', 'buckets', 'describe', 'gs://' + name,
                             '--project', config['project_id'], '--raw', '--format=json'],
                            capture_output=True, text=True)
    if result.returncode:
        if not re.search(r'\bNOT_FOUND\b|\b404\b', result.stderr) or re.search(r'permission|denied|forbidden', result.stderr, re.I):
            raise ValueError('Cannot establish private bucket absence')
        subprocess.run(['gcloud', 'storage', 'buckets', 'create', 'gs://' + name,
                        '--project', config['project_id'], '--location', settings(config)['location'],
                        '--default-storage-class=STANDARD', '--uniform-bucket-level-access',
                        '--public-access-prevention', '--quiet'], check=True, stdout=subprocess.DEVNULL)
        # Labels are ownership guards for future reuse, not credentials.
        subprocess.run(['gcloud', 'storage', 'buckets', 'update', 'gs://' + name,
                        '--project', config['project_id'], '--update-labels=vcfhe-purpose=private-evidence,vcfhe-campaign=' + config['campaign'],
                        '--quiet'], check=True, stdout=subprocess.DEVNULL)
    return validate_bucket(config, api(config, 'b/' + name), project['projectNumber'])


def grants(config, plan, prefix):
    expiry = (datetime.now(timezone.utc) + timedelta(hours=6)).strftime('%Y-%m-%dT%H:%M:%SZ')
    result = []
    for host in plan['hosts']:
        key = host['id'].replace('-', '_')
        account = next(r['attributes']['email'] for r in plan['resources']
                       if r['type'] == 'google_service_account' and r['key'] == key)
        condition = {'title': 'vcfhe-' + prefix + '-' + host['id'],
            'expression': 'resource.name.startsWith("projects/_/buckets/' + bucket_name(config) + '/objects/runs/'
                          + prefix + '/' + host['id'] + '/") && request.time < timestamp("' + expiry + '")'}
        for role in ('roles/storage.objectCreator', 'roles/storage.objectViewer'):
            result.append({'role': role, 'members': ['serviceAccount:' + account], 'condition': condition})
    return result


def change_grants(config, bindings, add):
    path = 'b/' + bucket_name(config) + '/iam'
    policy = api(config, path + '?optionsRequestedPolicyVersion=3')
    if not policy.get('etag'):
        raise ValueError('Archive IAM policy requires a concurrency etag')
    current = policy.get('bindings', [])
    for binding in bindings:
        if add:
            if binding not in current:
                current.append(binding)
        else:
            current = [b for b in current if b != binding]
    api(config, path, 'PUT', dict(policy, version=3, bindings=current))
    checked = api(config, path + '?optionsRequestedPolicyVersion=3').get('bindings', [])
    if any((b not in checked) if add else (b in checked) for b in bindings):
        raise ValueError('Archive scoped IAM update could not be verified')


def prepare(config, plan, destination, cloud):
    prefix = topology.digest({'run': plan['run'], 'config': plan['configSha256']})[:32]
    bucket = ensure_bucket(config, cloud)
    existing = Path(plan['run']) / 'cloud-archive-preflight/cloud-store.local.json'
    if existing.is_file():
        record = json.loads(existing.read_text())
        if (record['prefix'] != prefix or record['bucket'] != bucket or record['plan'] != settings(config)
                or record['workerSha256'] != hashlib.sha256((HERE / 'archive_worker.py').read_bytes()).hexdigest()):
            raise ValueError('Cloud archive preflight source or ownership changed')
        from smoke_cleanup import _write
        _write(destination / 'cloud-store.local.json', record)
        change_grants(config, record['bindings'], True)
        return record
    bindings = grants(config, plan, prefix)
    record = {'bucket': bucket, 'prefix': prefix, 'bindings': bindings,
              'plan': settings(config), 'workerSha256': hashlib.sha256((HERE / 'archive_worker.py').read_bytes()).hexdigest()}
    from smoke_cleanup import _write
    _write(destination / 'cloud-store.local.json', record)
    change_grants(config, bindings, True)
    return record


def export_host(config, plan, host, remote, destination, store, maximum, *, probe=False):
    key = host['id'].replace('-', '_')
    vm = next(r for r in plan['resources'] if r['type'] == 'google_compute_instance' and r['key'] == key)
    account = next(r['attributes']['email'] for r in plan['resources'] if r['type'] == 'google_service_account' and r['key'] == key)
    job = {'campaign': config['campaign'], 'host': host['id'], 'instanceId': str(vm['identity']['id']),
           'serviceAccount': account, 'bucket': store['bucket']['name'],
           'object': 'runs/' + store['prefix'] + '/' + host['id'] + ('/preflight.tar' if probe else '/private-state.tar'),
           'maximumArchiveBytes': maximum}
    if probe:
        job['mode'] = 'preflight'
    root = '/var/tmp/vcfhe-private-archive-' + store['prefix'] + '/' + host['id'] + ('-probe' if probe else '')
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        os.chmod(folder, 0o700)
        (folder / 'archive_worker.py').write_bytes((HERE / 'archive_worker.py').read_bytes())
        (folder / 'job.local.json').write_text(json.dumps(job))
        for path in folder.iterdir():
            os.chmod(path, 0o600)
        remote.run(['test', '!', '-e', root])
        remote.upload(folder, root)
    # Detached maintenance only. Read retries cannot launch the worker twice.
    script = 'set -eu; umask 077; test ! -e "$1/started"; touch "$1/started"; nohup python3 "$1/archive_worker.py" "$1" > "$1/worker.log" 2>&1 < /dev/null &'
    remote.run(['sudo', 'sh', '-c', script, 'private-archive', root], timeout=45)
    deadline = time.monotonic() + 2400
    while time.monotonic() < deadline:
        try:
            result = remote.run(['sudo', 'cat', root + '/result.local.json'], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=45)
            value = json.loads(result.stdout)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            time.sleep(10)
            continue
        if value.get('status') != 'passed':
            raise ValueError('Cloud archive worker failed. Original state and private worker log retained')
        receipt = value['receipt']
        validate_receipt(config, store, host['id'], receipt, probe=probe)
        from smoke_cleanup import _write
        name = host['id'] + ('-cloud-probe.local.json' if probe else '-cloud-receipt.local.json')
        _write(destination / name, receipt)
        return dict(receipt, receiptFile=name)
    raise TimeoutError('Private cloud backup readback deadline exceeded, participant state retained')


def validate_receipt(config, store, host, receipt, *, probe=False):
    expected = 'runs/' + store['prefix'] + '/' + host + ('/preflight.tar' if probe else '/private-state.tar')
    if (receipt.get('status') != ('probe-verified-cloud-readback' if probe else 'verified-cloud-readback') or receipt.get('host') != host
            or receipt.get('bucket') != store['bucket']['name'] or receipt.get('object') != expected
            or not str(receipt.get('generation', '')).isdecimal()
            or not re.fullmatch(r'[a-f0-9]{64}', receipt.get('sha256', ''))
            or not isinstance(receipt.get('files'), list) or not receipt['files']):
        raise ValueError('Invalid cloud backup receipt')
    name = urllib.parse.quote(expected, safe='')
    value = api(config, 'b/' + store['bucket']['name'] + '/o/' + name + '?generation=' + receipt['generation'])
    if (value.get('bucket') != receipt['bucket'] or value.get('name') != expected
            or value.get('generation') != receipt['generation'] or value.get('md5Hash') != receipt['md5Hash']
            or int(value.get('size', -1)) != receipt['archiveBytes']
            or value.get('metadata', {}).get('vcfhe-sha256') != receipt['sha256']):
        raise ValueError('Cloud archive generation, bytes or checksum changed')


def verify(destination, manifest, plan):
    from smoke_cleanup import _read, _sha
    config = _read(Path(plan['run']) / 'distributed-config.json')
    store = _read(destination / 'cloud-store.local.json')
    expected_prefix = topology.digest({'run': plan['run'], 'config': plan['configSha256']})[:32]
    if store.get('prefix') != expected_prefix or store.get('plan') != settings(config):
        raise ValueError('Private cloud archive run prefix or storage plan changed')
    project = subprocess.check_output(['gcloud', 'projects', 'describe', config['project_id'],
                                       '--format=value(projectNumber)'], text=True).strip()
    actual = validate_bucket(config, api(config, 'b/' + store['bucket']['name']), project)
    if actual != store['bucket'] or _sha(destination / 'cloud-store.local.json') != manifest['cloudStoreSha256']:
        raise ValueError('Private archive bucket or store record changed')
    total = 0
    for host, receipt in manifest['archives'].items():
        if receipt.get('receiptFile') != host + '-cloud-receipt.local.json':
            raise ValueError('Foreign private cloud receipt path')
        if _read(destination / receipt['receiptFile']) != {k: v for k, v in receipt.items() if k != 'receiptFile'}:
            raise ValueError('Cloud readback receipt was modified')
        validate_receipt(config, store, host, receipt)
        vm = next(r for r in plan['resources'] if r['type'] == 'google_compute_instance' and r['key'] == host.replace('-', '_'))
        account = next(r['attributes']['email'] for r in plan['resources'] if r['type'] == 'google_service_account' and r['key'] == host.replace('-', '_'))
        if receipt['instanceId'] != str(vm['identity']['id']) or receipt['serviceAccount'] != account:
            raise ValueError('Cloud backup original host identity differs')
        total += receipt['archiveBytes']
    if total > settings(config)['maximum_gib'] * 2**30:
        raise ValueError('Private archives exceed quoted storage allowance')
    return manifest


def revoke(config, destination):
    from smoke_cleanup import _read
    store = _read(Path(destination) / 'cloud-store.local.json')
    change_grants(config, store['bindings'], False)


def preflight(campaign):
    """Exercise each real VM's exact prefix before any KMS or owner operation."""
    from smoke_cleanup import _state, _cloud, _args, _describe_args, _check_identity, _identity, _write
    from concurrent.futures import ThreadPoolExecutor
    config = campaign.config
    rows, state_sha = _state(config, campaign.run)
    resources = []
    for row in rows.values():
        if row['type'] not in ('google_compute_instance', 'google_service_account'):
            continue
        live = _cloud(_args(config, _describe_args(row)))
        _check_identity(config, row, live)
        resources.append(dict(row, identity=_identity(live)))
    plan = {'run': str(campaign.run), 'configSha256': topology.digest(config),
            'hosts': campaign.plan['hosts'], 'resources': resources, 'terraformStateSha256': state_sha}
    destination = campaign.run / 'cloud-archive-preflight'
    destination.mkdir(mode=0o700)
    store = prepare(config, plan, destination, _cloud)
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(lambda host: export_host(config, plan, host, campaign.remotes[host['id']],
                            destination, store, 1024**2, probe=True), plan['hosts']))
    _write(destination / 'result.local.json', {'status': 'passed', 'hosts': len(receipts),
        'protocolOperations': 0, 'syntheticArchivesOnly': True, 'bucketPreserved': True})
    return receipts
