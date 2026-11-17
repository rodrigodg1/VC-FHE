"""Private, state-preserving removal of one explicitly completed cloud smoke.

This module is deliberately separate from public evidence export. Its archives
contain KMS shares, identities, chain data, policy counters and recipient state.
They are UNENCRYPTED private backups, mode 0600 inside a Git-ignored mode 0700
directory. Only the explicit private Cloud Storage backend may upload them.
Never send them to public storage or the evaluation publisher.

inspect_plan() is read-only. backup() stops this smoke's containers and copies
the entire mounted participant-state filesystem. apply() removes only resources
whose Terraform and live identities match the verified backup. Shared image
repositories, build buckets, project settings and authentication are preserved.
No function starts a VM, an evaluation, a release or a replacement lineage.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import uuid

import gcp
from privacy import require_private
from remote import Remote
import topology

SCHEMA = 'vcfhe-private-smoke-backup-v1'
ALLOWED = {'google_compute_network', 'google_compute_subnetwork',
           'google_compute_router', 'google_compute_router_nat',
           'google_compute_firewall', 'google_compute_instance',
           'google_compute_disk', 'google_service_account',
           'google_artifact_registry_repository',
           'google_artifact_registry_repository_iam_member',
           'google_compute_instance_iam_member',
           'google_iap_tunnel_instance_iam_member',
           'google_service_account_iam_member'}
IDENTITY = {'google_compute_instance': ('instance_id', 'id'),
            'google_compute_disk': ('disk_id', 'id'),
            'google_service_account': ('unique_id', 'uniqueId')}


def _sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for part in iter(lambda: source.read(1024 * 1024), b''):
            value.update(part)
    return value.hexdigest()


def _write(path, value):
    path = Path(path)
    pending = path.with_name(path.name + '.' + uuid.uuid4().hex + '.pending')
    with pending.open('x') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    pending.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError('Private backup paths must not contain symlinks')
    return require_private(path)


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('A required original smoke record is unavailable')
    return json.loads(path.read_text())


def _cloud(args, missing=False):
    if missing and args[:3] == ['iam', 'service-accounts', 'describe']:
        # IAM may deliberately return PERMISSION_DENIED for a deleted account.
        # A successful, unfiltered project inventory proves absence without
        # interpreting that ambiguous error as permission to continue.
        if len(args) < 6 or args.count('--project') != 1:
            raise ValueError('Exact project scope is required for service-account inspection')
        project_index = args.index('--project')
        if project_index + 1 >= len(args):
            raise ValueError('Exact project scope is required for service-account inspection')
        project, email = args[project_index + 1], args[3]
        if (not re.fullmatch(r'[a-z][a-z0-9-]{5,29}', project)
                or not email.endswith('@' + project + '.iam.gserviceaccount.com')):
            raise ValueError('Service-account inspection is outside the exact project')
        accounts = _cloud(['iam', 'service-accounts', 'list', '--project', project])
        if not isinstance(accounts, list):
            raise ValueError('Cannot establish the complete project service-account inventory')
        matches = [item for item in accounts if item.get('email') == email]
        if len(matches) > 1:
            raise ValueError('Ambiguous service-account inventory')
        if matches and (not str(matches[0].get('uniqueId', '')).isdecimal()
                        or not matches[0].get('name')):
            raise ValueError('Live service-account identity is incomplete')
        # The caller compares uniqueId and the original resource name against
        # Terraform and the verified backup before any destructive operation.
        return matches[0] if matches else None
    result = subprocess.run(['gcloud', *map(str, args), '--format=json'],
                            capture_output=True, text=True)
    if result.returncode == 0:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    error = result.stderr or ''
    if (missing and (re.search(r'\bNOT_FOUND\b', error)
                     or re.search(r"The resource ['\"].+['\"] was not found", error, re.I)
                     or re.search(r'\bNAT\b.*\bnot found\b', error, re.I))
            and not re.search(r'permission|forbidden|unauthoriz|unauthenticat|denied|or.*(?:access|exist)', error, re.I)):
        return None
    raise ValueError('Cloud inspection or removal failed. Private resources remain preserved. Inspect the exact operation locally.')


def _args(config, args):
    return [*args, '--project', config['project_id']]


def _scope(config, run, allow_failed=False, *, allow_cleanup_retry=False):
    topology.validate(config)
    if (config.get('execution_mode') != 'smoke'
            or not config['campaign'].endswith('-smoke')
            or config['layout'] != 'four-hosts'):
        raise ValueError('Cleanup is restricted to the separate four-host -smoke campaign')
    run = _private(run)
    if _read(run / 'distributed-config.json') != config:
        raise ValueError('Cleanup configuration differs from this exact run')
    state = _read(run / 'launch-state.json')
    if state.get('config') != config:
        raise ValueError('Original launch configuration does not match')
    cleanup_retry = allow_cleanup_retry and state.get('status') == 'smoke-complete-cleanup-failed'
    if (state.get('status') != 'completed' and not cleanup_retry
            and not (allow_failed and state.get('status') == 'failed')):
        raise ValueError('Run must be completed or an explicitly inspected failed smoke')
    if state.get('status') == 'completed' or cleanup_retry:
        if _read(run / 'distributed/smoke-result.json').get('status') != 'passed':
            raise ValueError('A completed smoke lacks its passing smoke result')
    directory = run / 'terraform'
    if _read(directory / 'main.tf.json') != gcp.terraform(config):
        raise ValueError('Terraform declarations no longer match the exact smoke configuration')
    if _read(directory / 'terraform.tfvars.json') != {'project_id': config['project_id']}:
        raise ValueError('Terraform project scope differs')
    return run


def _state(config, run):
    state_path = run / 'terraform/terraform.tfstate'
    raw = _read(state_path)
    expected = gcp.terraform(config)['resource']
    rows = {}
    for resource in raw.get('resources', []):
        if resource.get('mode') == 'data':
            continue
        kind, name = resource['type'], resource['name']
        if (resource.get('module') or kind not in ALLOWED
                or name not in expected.get(kind, {})
                or len(resource.get('instances', [])) != 1):
            raise ValueError('Terraform contains unknown, foreign or ambiguous managed resources')
        instance = resource['instances'][0]
        if 'index_key' in instance or instance.get('deposed'):
            raise ValueError('Indexed or replaced resources require manual inspection')
        address = kind + '.' + name
        if address in rows:
            raise ValueError('Duplicate Terraform resource')
        value = instance['attributes']
        if value.get('project', config['project_id']) != config['project_id']:
            raise ValueError('Terraform resource belongs to a different project')
        for field in ('name', 'zone', 'region', 'role', 'member', 'account_id'):
            original = expected[kind][name].get(field)
            if original is not None and '${' not in str(original) and value.get(field) != original:
                raise ValueError('Terraform resource identity differs from the smoke declaration')
        rows[address] = {'address': address, 'type': kind, 'key': name, 'attributes': value}
    required = {kind + '.' + name for kind, values in expected.items() for name in values}
    if set(rows) != required:
        raise ValueError('Incomplete Terraform ownership. Refusing partial or unknown cleanup scope')
    return rows, _sha(state_path)


def _describe_args(row):
    kind, value = row['type'], row['attributes']
    if kind == 'google_compute_instance':
        return ['compute', 'instances', 'describe', value['name'], '--zone', value['zone']]
    if kind == 'google_compute_disk':
        return ['compute', 'disks', 'describe', value['name'], '--zone', value['zone']]
    if kind == 'google_compute_network':
        return ['compute', 'networks', 'describe', value['name']]
    if kind == 'google_compute_subnetwork':
        return ['compute', 'networks', 'subnets', 'describe', value['name'], '--region', value['region']]
    if kind == 'google_compute_router':
        return ['compute', 'routers', 'describe', value['name'], '--region', value['region']]
    if kind == 'google_compute_router_nat':
        return ['compute', 'routers', 'nats', 'describe', value['name'],
                '--router', value['router'], '--region', value['region']]
    if kind == 'google_compute_firewall':
        return ['compute', 'firewall-rules', 'describe', value['name']]
    if kind == 'google_service_account':
        return ['iam', 'service-accounts', 'describe', value['email']]
    return None


def _identity(value):
    if value is None:
        return None
    # Ignore mutable status, deletion protection and attached-policy fingerprints.
    return {key: value[key] for key in ('id', 'uniqueId', 'selfLink', 'name', 'creationTimestamp') if key in value}


def _check_identity(config, row, live):
    if live is None:
        return
    value = row['attributes']
    if live.get('name') != (value.get('email') if row['type'] == 'google_service_account' else value['name']):
        # IAM returns a full projects/.../serviceAccounts/... resource name.
        if row['type'] != 'google_service_account' or live.get('email') != value['email']:
            raise ValueError('Live resource has an unexpected name')
    if row['type'] in IDENTITY:
        stored, field = IDENTITY[row['type']]
        if value.get(stored) and str(value[stored]) != str(live.get(field)):
            raise ValueError('Live resource was replaced after Terraform ownership was recorded')
    if value.get('self_link') and live.get('selfLink') != value['self_link']:
        raise ValueError('Live resource belongs to another resource scope')
    if value.get('creation_timestamp') and live.get('creationTimestamp') != value['creation_timestamp']:
        raise ValueError('Live resource creation time differs from the owned resource')


def _disk_ref(config, source, zone):
    prefix = 'https://www.googleapis.com/compute/v1/projects/' + config['project_id'] + '/zones/' + zone + '/disks/'
    if not source.startswith(prefix) or not re.fullmatch(r'[a-z][a-z0-9-]+', source[len(prefix):]):
        raise ValueError('Attached disk is outside this exact project and zone')
    return source[len(prefix):]


def inspect_plan(config, run, *, allow_failed=False):
    """Read-only plan. Refuse foreign attachments and incomplete Terraform scope."""
    run = _scope(config, run, allow_failed)
    resources, state_sha = _state(config, run)
    physical = topology.hosts(config)
    hosts = {h['id'].replace('-', '_'): h for h in physical}
    result = {'schema': 'vcfhe-smoke-cleanup-plan-v1', 'run': str(run),
              'configSha256': topology.digest(config), 'campaign': config['campaign'],
              'terraformStateSha256': state_sha, 'resources': [], 'hosts': physical,
              'preserved': ['shared-image-repository', 'build-buckets', 'project', 'authentication'],
              'inspectedAt': datetime.now(timezone.utc).isoformat()}
    for row in resources.values():
        args = _describe_args(row)
        if args is None:
            continue
        live = _cloud(_args(config, args), missing=True)
        if live is None and row['type'] not in {'google_compute_router_nat'}:
            raise ValueError('An owned resource is unexpectedly absent before private backup')
        _check_identity(config, row, live)
        entry = dict(row, describe=args, identity=_identity(live), present=live is not None)
        if row['type'] == 'google_compute_instance':
            host = hosts[row['key']]
            labels = live.get('labels', {})
            metadata = {v['key']: v.get('value') for v in live.get('metadata', {}).get('items', [])}
            if (labels.get('experiment') != config['campaign']
                    or metadata.get('vcfhe-campaign') != config['campaign']
                    or metadata.get('vcfhe-host') != host['id']):
                raise ValueError('VM labels and bootstrap scope do not identify this smoke')
            disks = live.get('disks', [])
            if len(disks) != 2 or sum(bool(d.get('boot')) for d in disks) != 1:
                raise ValueError('Unexpected VM disks. No foreign attachment may be removed')
            names = [_disk_ref(config, d['source'], host['zone']) for d in disks]
            state_disk = host['name'] + '-state'
            if set(names) != {host['name'], state_disk}:
                raise ValueError('VM has a foreign boot or state disk')
            if not any(d.get('deviceName') == 'vcfhe-state' and not d.get('boot')
                       and d['source'].endswith('/' + state_disk) for d in disks):
                raise ValueError('Participant state disk is not the declared mount')
            entry['status'] = live.get('status')
            entry['host'] = host['id']
            entry['bootDisk'] = host['name']
            boot_row = {'type': 'google_compute_disk', 'attributes': {'name': host['name'], 'zone': host['zone']}}
            boot_args = _describe_args(boot_row)
            boot = _cloud(_args(config, boot_args))
            if boot.get('users') != [live['selfLink']]:
                raise ValueError('Boot disk is shared or is attached to another VM')
            result['resources'].append(dict(boot_row, address='boot.' + row['key'], describe=boot_args,
                                             identity=_identity(boot), present=True))
        if row['type'] == 'google_compute_disk':
            expected_user = 'https://www.googleapis.com/compute/v1/projects/' + config['project_id'] + '/zones/' + row['attributes']['zone'] + '/instances/' + hosts[row['key']]['name']
            if live.get('users') != [expected_user]:
                raise ValueError('State disk is detached, shared or attached to a foreign VM')
        result['resources'].append(entry)
    # IAM grants are removed with exact members from the original declarations.
    result['iam'] = [row for row in resources.values() if row['type'].endswith('_iam_member')]
    return result


def _archive_info(path, campaign):
    members, total = [], 0
    allowed = {campaign, 'scope.txt', 'bootstrap-evidence', 'lost+found'}
    with tarfile.open(path, 'r:') as archive:
        seen = set()
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or '..' in name.parts or '\\' in member.name
                    or (name.parts and name.parts[0] not in allowed)
                    or not (member.isdir() or member.isfile()) or member.name in seen):
                raise ValueError('Private state archive contains unsafe or out-of-scope entries')
            if str(name) in seen:
                raise ValueError('Duplicate normalized private archive entry')
            seen.add(str(name))
            if member.isfile():
                source = archive.extractfile(member)
                digest = hashlib.sha256()
                count = 0
                for part in iter(lambda: source.read(1024 * 1024), b''):
                    count += len(part)
                    digest.update(part)
                if count != member.size:
                    raise ValueError('Truncated private state archive')
                total += count
                members.append({'path': member.name, 'bytes': count, 'sha256': digest.hexdigest()})
    if not any(PurePosixPath(item['path']).name == 'scope.txt' and len(PurePosixPath(item['path']).parts) == 1 for item in members):
        raise ValueError('Private archive lacks its exact host scope marker')
    return {'sha256': _sha(path), 'archiveBytes': path.stat().st_size, 'fileBytes': total, 'files': members}


def backup(config, run, destination, *, allow_failed=False):
    """Quiesce and durably back up all four mounted state volumes, never decrypt.

    Call before Campaign.stop(). Stopped VMs are refused rather than silently
    started. For a failed smoke, allow_failed=True is an explicit inspection
    acknowledgement by the caller. Partial backups never authorize deletion.
    """
    plan = inspect_plan(config, run, allow_failed=allow_failed)
    destination = _private(destination)
    if destination.exists():
        raise ValueError('Use a fresh private backup directory. Existing backups are preserved')
    vms = [r for r in plan['resources'] if r['type'] == 'google_compute_instance']
    if len(vms) != 4 or any(r['status'] != 'RUNNING' for r in vms):
        raise ValueError('Private backup needs the four original running smoke VMs. It will not restart them')
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(destination, 0o700)
    _write(destination / 'plan.local.json', plan)
    remotes = {h['id']: Remote(config, h) for h in plan['hosts']}
    sizes = {}
    # Validate every host before stopping any participant.
    for host in plan['hosts']:
        remote = remotes[host['id']]
        remote.run(['mountpoint', '-q', '/srv/vcfhe'], stdout=subprocess.DEVNULL)
        marker = remote.text(['sudo', 'cat', '/srv/vcfhe/scope.txt'])
        if marker != config['campaign'] + '/' + host['id']:
            raise ValueError('Private state mount has a foreign host marker')
        sizes[host['id']] = int(remote.text(['sudo', 'du', '-sb', '/srv/vcfhe']).split()[0])
    from cloud_archive import settings as archive_settings
    cloud_plan = archive_settings(config)
    evidence_bytes = sum(p.stat().st_size for p in Path(run).rglob('*')
                         if p.is_file() and not p.is_relative_to(destination))
    required = evidence_bytes + 256 * 1024 * 1024
    if cloud_plan is None:
        required += sum(sizes.values())
    elif sum(sizes.values()) + 1024**3 > cloud_plan['maximum_gib'] * 1024**3:
        raise ValueError('Private state exceeds the quoted GCS archive allowance')
    if shutil.disk_usage(destination).free < required:
        raise ValueError('Insufficient local disk space. Cloud state has not been removed')
    store = None
    if cloud_plan is not None:
        from cloud_archive import prepare
        store = prepare(config, plan, destination, _cloud)
    for host in plan['hosts']:
        remote = remotes[host['id']]
        root = '/srv/vcfhe/' + config['campaign'] + '/' + host['id']
        remote.run(['sudo', 'touch', root + '/stop-sampler'], stdout=subprocess.DEVNULL)
        label = 'com.docker.compose.project=' + config['campaign'] + '-' + host['id']
        identifiers = remote.text(['sudo', 'docker', 'ps', '-q', '--filter', 'label=' + label]).split()
        if any(not re.fullmatch(r'[0-9a-f]{12,64}', item) for item in identifiers):
            raise ValueError('Unexpected smoke container identity')
        if identifiers:
            remote.run(['sudo', 'docker', 'stop', '--time', '45', *identifiers], stdout=subprocess.DEVNULL)
        if remote.text(['sudo', 'docker', 'ps', '-q', '--filter', 'label=' + label]):
            raise ValueError('Smoke containers remain active. Refusing an inconsistent backup')
        remote.run(['sudo', 'sync'], stdout=subprocess.DEVNULL)
    # The sampler observes its stop file every 15 seconds. Terminate only the
    # exact campaign-bound sampler before copying its observations.
    for host in plan['hosts']:
        remote = remotes[host['id']]
        pattern = '^python3 /srv/vcfhe/' + config['campaign'] + '/' + host['id'] + '/probe[.]py '
        remote.run(['sudo', 'sh', '-c', 'pids=$(pgrep -f "$1" || true); test -z "$pids" || kill $pids', 'smoke-sampler-stop', pattern],
                   stdout=subprocess.DEVNULL)
        remote.run(['sudo', 'sync'], stdout=subprocess.DEVNULL)
    archives = {}
    for host in plan['hosts']:
        if store is not None:
            from cloud_archive import export_host
            remaining = cloud_plan['maximum_gib'] * 1024**3 - sum(r['archiveBytes'] for r in archives.values())
            archives[host['id']] = export_host(config, plan, host, remotes[host['id']], destination, store, remaining)
            continue
        path = destination / (host['id'] + '-private-state.tar')
        with path.open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            remotes[host['id']].run(['sudo', 'tar', '--one-file-system', '-cf', '-', '-C', '/srv/vcfhe', '.'],
                                    stdout=output, stderr=subprocess.PIPE)
            output.flush()
            os.fsync(output.fileno())
        archives[host['id']] = dict(file=path.name, **_archive_info(path, config['campaign']))
        with tarfile.open(path) as archive:
            markers = [m for m in archive if str(PurePosixPath(m.name)) == 'scope.txt']
            if len(markers) != 1 or archive.extractfile(markers[0]).read().decode().strip() != config['campaign'] + '/' + host['id']:
                raise ValueError('Archived host scope marker differs from the live host')
    # Preserve the already collected evidence as its own closure. It is not
    # combined with any private participant state or used to create a new seal.
    evidence = destination / 'original-run-evidence.tar'
    with evidence.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        with tarfile.open(fileobj=output, mode='w') as archive:
            for path in sorted(Path(run).rglob('*')):
                if path.is_relative_to(destination):
                    continue
                if path.is_symlink():
                    raise ValueError('Original run evidence contains a symlink')
                if path.is_file():
                    archive.add(path, arcname=str(path.relative_to(run)), recursive=False)
        output.flush()
        os.fsync(output.fileno())
    manifest = {'schema': SCHEMA, 'status': 'complete', 'sensitivity': 'unencrypted-secret-protocol-state',
                'createdAt': datetime.now(timezone.utc).isoformat(), 'configSha256': topology.digest(config),
                'campaign': config['campaign'], 'run': str(Path(run).resolve()),
                'planSha256': _sha(destination / 'plan.local.json'), 'archives': archives,
                'evidence': {'file': evidence.name, 'sha256': _sha(evidence)},
                'participantStateScope': 'entire /srv/vcfhe filesystem on every original host',
                'excluded': ['ephemeral RAM', 'Docker image layers', 'boot-disk OS login and temporary registry tokens']}
    if store is not None:
        from cloud_archive import SCHEMA as CLOUD_SCHEMA
        manifest.update(schema=CLOUD_SCHEMA, cloudStoreSha256=_sha(destination / 'cloud-store.local.json'),
                        storage='private-gcs-generation-bound-readback-verified')
    _write(destination / 'backup.local.json', manifest)
    verify_backup(destination)
    return manifest


def verify_backup(destination):
    """Verify file modes, complete archive contents and all recorded hashes."""
    destination = _private(destination)
    if stat.S_IMODE(destination.stat().st_mode) != 0o700:
        raise ValueError('Private backup directory must have mode 0700')
    manifest = _read(destination / 'backup.local.json')
    plan = _read(destination / 'plan.local.json')
    from cloud_archive import SCHEMA as CLOUD_SCHEMA
    if (manifest.get('schema') not in (SCHEMA, CLOUD_SCHEMA) or manifest.get('status') != 'complete'
            or _sha(destination / 'plan.local.json') != manifest['planSha256']
            or plan.get('configSha256') != manifest['configSha256']
            or plan.get('campaign') != manifest['campaign'] or plan.get('run') != manifest['run']
            or set(manifest['archives']) != {h['id'] for h in plan['hosts']}):
        raise ValueError('Private backup is incomplete or its scope changed')
    for path in destination.iterdir():
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ValueError('Private backup files must be regular mode 0600 files')
    if manifest['schema'] == CLOUD_SCHEMA:
        from cloud_archive import verify
        verify(destination, manifest, plan)
    for host, row in (manifest['archives'].items() if manifest['schema'] == SCHEMA else []):
        if row['file'] != host + '-private-state.tar':
            raise ValueError('Unexpected private archive path')
        actual = _archive_info(destination / row['file'], manifest['campaign'])
        if actual != {key: row[key] for key in actual}:
            raise ValueError('Private archive changed after durable backup')
        with tarfile.open(destination / row['file']) as archive:
            scope = [m for m in archive if str(PurePosixPath(m.name)) == 'scope.txt']
            if len(scope) != 1 or archive.extractfile(scope[0]).read().decode().strip() != manifest['campaign'] + '/' + host:
                raise ValueError('Private archive host marker differs')
    if (manifest['evidence']['file'] != 'original-run-evidence.tar'
            or _sha(destination / manifest['evidence']['file']) != manifest['evidence']['sha256']):
        raise ValueError('Original evidence backup changed')
    return manifest


def _require_live(config, row):
    live = _cloud(_args(config, row['describe']), missing=True)
    if live is not None and _identity(live) != row['identity']:
        raise ValueError('Resource was replaced after backup. Refusing to remove it')
    return live


def _remove_iap(config, host, identity, member, role):
    """IAP Compute VM IAM has no supported gcloud TCP command. Use its API.

    The short-lived access token is held in memory only. Etag preserves other
    bindings in the instance-scoped policy during this exact-member removal.
    """
    project = _cloud(['projects', 'describe', config['project_id']])
    number, instance = str(project.get('projectNumber', '')), str(identity.get('id', ''))
    if (project.get('projectId') != config['project_id']
            or not number.isdecimal() or not instance.isdecimal()):
        raise ValueError('Cannot establish the exact IAP instance resource')
    result = subprocess.run(['gcloud', 'auth', 'print-access-token', '--project', config['project_id']],
                            capture_output=True, text=True)
    if result.returncode or not result.stdout.strip():
        raise ValueError('Cannot authenticate exact IAP policy removal')
    token = result.stdout.strip()
    base = 'https://iap.googleapis.com/v1/projects/' + number + '/iap_tunnel/zones/' + host['zone'] + '/instances/' + instance
    def request(method, value):
        data = json.dumps(value).encode()
        req = urllib.request.Request(base + ':' + method, data=data,
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return json.load(response)
        except (OSError, ValueError, urllib.error.HTTPError):
            raise ValueError('Exact IAP policy operation failed. No token was written to a file or log') from None
    policy = request('getIamPolicy', {'options': {'requestedPolicyVersion': 3}})
    changed = False
    bindings = []
    for binding in policy.get('bindings', []):
        if binding.get('role') == role and not binding.get('condition') and member in binding.get('members', []):
            binding = dict(binding, members=[m for m in binding['members'] if m != member])
            changed = True
        if binding.get('members'):
            bindings.append(binding)
    if changed:
        if not policy.get('etag'):
            raise ValueError('IAP policy lacks the concurrency etag')
        request('setIamPolicy', {'policy': dict(policy, bindings=bindings)})


def _remove_iam(config, row, resources):
    value, kind = row['attributes'], row['type']
    if value.get('condition'):
        raise ValueError('Conditional IAM bindings require separate review')
    member, role = value['member'], value['role']
    account = next(r['attributes']['email'] for r in resources if r.get('key') == row['key'] and r['type'] == 'google_service_account')
    host = next(r['attributes'] for r in resources if r.get('key') == row['key'] and r['type'] == 'google_compute_instance')
    if kind == 'google_artifact_registry_repository_iam_member':
        if (member != 'serviceAccount:' + account or role != 'roles/artifactregistry.reader'
                or value.get('location') != topology.registry_region(config)):
            raise ValueError('Foreign registry IAM binding')
        args = ['artifacts', 'repositories', 'remove-iam-policy-binding', gcp.image_repository(config),
                '--location', value['location']]
    else:
        if member != config.get('operator_principal'):
            raise ValueError('Foreign operator IAM binding')
        if kind == 'google_compute_instance_iam_member':
            if role != 'roles/compute.osAdminLogin':
                raise ValueError('Foreign instance IAM role')
            args = ['compute', 'instances', 'remove-iam-policy-binding', host['name'], '--zone', host['zone']]
        elif kind == 'google_iap_tunnel_instance_iam_member':
            if role != 'roles/iap.tunnelResourceAccessor':
                raise ValueError('Foreign IAP role')
            vm = next(r for r in resources if r.get('key') == row['key'] and r['type'] == 'google_compute_instance')
            if _require_live(config, vm) is not None:
                _remove_iap(config, host, vm['identity'], member, role)
            return
        else:
            if role != 'roles/iam.serviceAccountUser':
                raise ValueError('Foreign service-account IAM role')
            args = ['iam', 'service-accounts', 'remove-iam-policy-binding', account]
    policy_args = ['get-iam-policy' if item == 'remove-iam-policy-binding' else item for item in args]
    policy = _cloud(_args(config, policy_args), missing=True)
    if policy is not None and any(b.get('role') == role and not b.get('condition') and member in b.get('members', [])
                                  for b in policy.get('bindings', [])):
        _cloud(_args(config, [*args, '--member', member, '--role', role, '--condition=None', '--quiet']))


def apply(config, run, backup_directory, *, allow_failed=False):
    """Remove only the original smoke after its complete private backup verifies.

    Explicit per-resource deletion avoids Terraform destroy, which would remove
    a shared image repository or override retained-state protection. Original
    Terraform files/state remain forensic records and must never be reapplied.
    """
    run = _scope(config, run, allow_failed, allow_cleanup_retry=True)
    manifest = verify_backup(backup_directory)
    plan = _read(Path(backup_directory) / 'plan.local.json')
    _, state_sha = _state(config, run)
    if (manifest['run'] != str(run) or manifest['configSha256'] != topology.digest(config)
            or plan['terraformStateSha256'] != state_sha):
        raise ValueError('Backup does not belong to this unchanged smoke run')
    report_path = run / 'smoke-cleanup.local.json'
    report = _read(report_path) if report_path.exists() else {'schema': 'vcfhe-smoke-cleanup-v1',
        'status': 'running', 'configSha256': topology.digest(config), 'backupDirectory': str(Path(backup_directory).resolve()),
        'backupManifestSha256': _sha(Path(backup_directory) / 'backup.local.json'), 'removed': [], 'iamRemoved': []}
    if (report.get('configSha256') != topology.digest(config)
            or report.get('backupManifestSha256') != _sha(Path(backup_directory) / 'backup.local.json')):
        raise ValueError('Prior cleanup journal belongs to another backup')
    resources = plan['resources']
    # Validate ALL original live identities before the first destructive step.
    for row in resources:
        _require_live(config, row)
    from cloud_archive import SCHEMA as CLOUD_SCHEMA
    if manifest['schema'] == CLOUD_SCHEMA:
        from cloud_archive import revoke
        revoke(config, backup_directory)
        report['privateCloudArchivePreserved'] = True
        report['temporaryArchiveHostPermissionsRevoked'] = True
    _write(report_path, report)
    try:
        for row in plan['iam']:
            if row['address'] not in report['iamRemoved']:
                _remove_iam(config, row, resources)
                report['iamRemoved'].append(row['address'])
                _write(report_path, report)
        order = ['google_compute_instance', 'google_compute_disk', 'google_compute_router_nat',
                 'google_compute_firewall', 'google_compute_router', 'google_compute_subnetwork',
                 'google_compute_network', 'google_service_account']
        for kind in order:
            for row in (r for r in resources if r['type'] == kind):
                live = _require_live(config, row)
                if live is None:
                    if row['address'] not in report['removed']:
                        report['removed'].append(row['address'])
                    continue
                value = row['attributes']
                if kind == 'google_compute_instance':
                    _cloud(_args(config, ['compute', 'instances', 'update', value['name'], '--zone', value['zone'],
                                         '--no-deletion-protection', '--quiet']))
                    _require_live(config, row)
                    if live.get('status') != 'TERMINATED':
                        _cloud(_args(config, ['compute', 'instances', 'stop', value['name'], '--zone', value['zone'], '--quiet']))
                    args = ['compute', 'instances', 'delete', value['name'], '--zone', value['zone'], '--keep-disks=all']
                elif kind == 'google_service_account':
                    args = ['iam', 'service-accounts', 'delete', value['email']]
                else:
                    args = list(row['describe'])
                    args[args.index('describe')] = 'delete'
                _cloud(_args(config, [*args, '--quiet']))
                if kind == 'google_service_account':
                    from service_account_absence import confirm_absence
                    confirm_absence(config, row, _require_live)
                elif _cloud(_args(config, row['describe']), missing=True) is not None:
                    raise ValueError('Cloud resource still exists after removal')
                report['removed'].append(row['address'])
                _write(report_path, report)
        for row in resources:
            if _cloud(_args(config, row['describe']), missing=True) is not None:
                raise ValueError('Smoke cleanup left an owned resource')
        report.update(status='passed', completedAt=datetime.now(timezone.utc).isoformat(),
                      privateStatePreserved=True, originalEvidencePreserved=True,
                      sharedPreparationPreserved=True, terraformState='retained-forensics-do-not-reapply')
        _write(report_path, report)
        return report
    except BaseException:
        report['status'] = 'incomplete'
        _write(report_path, report)
        raise
