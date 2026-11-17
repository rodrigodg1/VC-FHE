#!/usr/bin/env python3
"""Private helper for an uninitialized, provisioning-only failed smoke.

prepare performs only local writes and cloud reads. apply alone removes the
exact approved subset. Original Terraform state and all logs remain untouched.
This controller-only maintenance tool is outside the evaluation image closure.
"""
from datetime import datetime, timezone
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import cloud_tools
import gcp
import smoke_cleanup as safe
import topology

REPOSITORY = 'google_artifact_registry_repository.images'
ALLOWED_STAGES = {'GCP provisioning', 'Preserve private smoke state before resource removal'}


def write(path, value):
    safe._write(path, value)


def sha(path):
    return safe._sha(path)


def read(path):
    return safe._read(path)


def scope(config, run):
    topology.validate(config)
    if config.get('execution_mode') != 'smoke' or not config['campaign'].endswith('-smoke'):
        raise ValueError('Only the explicitly separate smoke campaign may be removed')
    run = safe._private(run)
    if read(run / 'distributed-config.json') != config:
        raise ValueError('Original run configuration differs')
    launch = read(run / 'launch-state.json')
    if launch.get('status') != 'failed' or launch.get('config') != config:
        raise ValueError('Run is not the exact failed smoke')
    stages = launch.get('stages', [])
    if (not stages or stages[0].get('name') != 'GCP provisioning' or stages[0].get('status') != 'failed'
            or any(s.get('name') not in ALLOWED_STAGES or s.get('status') != 'failed' for s in stages)):
        raise ValueError('A protocol or private-state stage may have started. Full private backup is required')
    for name in ['enrollment', 'network', 'validator-config', 'compose', 'private-smoke-backup', 'state.json', 'seal.json']:
        if (run / name).exists():
            raise ValueError('Participant state or completed evaluation exists. Refusing provisioning-only cleanup')
    if read(run / 'terraform/main.tf.json') != gcp.terraform(config):
        raise ValueError('Original infrastructure declaration differs')
    if read(run / 'terraform/terraform.tfvars.json') != {'project_id': config['project_id']}:
        raise ValueError('Wrong original project scope')
    return run, launch


def state_rows(config, state):
    expected = gcp.terraform(config)['resource']
    rows = {}
    for resource in state.get('resources', []):
        if resource.get('mode') == 'data':
            if (resource.get('type'), resource.get('name')) != ('google_compute_image', 'debian'):
                raise ValueError('Unexpected data source in Terraform state')
            continue
        kind, key = resource['type'], resource['name']
        if (resource.get('module') or kind not in safe.ALLOWED or key not in expected.get(kind, {})
                or len(resource.get('instances', [])) != 1):
            raise ValueError('Unexpected managed resource in the original subset')
        instance = resource['instances'][0]
        if 'index_key' in instance or instance.get('deposed'):
            raise ValueError('Ambiguous Terraform ownership')
        value = instance['attributes']
        if value.get('project', config['project_id']) != config['project_id']:
            raise ValueError('Foreign project in original Terraform state')
        for field in ['name', 'zone', 'region', 'account_id', 'member', 'role']:
            declared = expected[kind][key].get(field)
            if declared is not None and '${' not in str(declared) and declared != value.get(field):
                raise ValueError('Resource differs from exact original declaration')
        address = kind + '.' + key
        if address in rows:
            raise ValueError('Duplicate resource address')
        rows[address] = {'address': address, 'type': kind, 'key': key, 'attributes': value}
    if REPOSITORY not in rows:
        raise ValueError('Original imported shared repository ownership record is absent')
    hosts = {h['id'].replace('-', '_'): h for h in topology.hosts(config)}
    repository = rows[REPOSITORY]['attributes']
    network = rows.get('google_compute_network.experiment', {}).get('attributes', {})
    for row in rows.values():
        kind, key, value = row['type'], row['key'], row['attributes']
        if kind.endswith('_iam_member'):
            account = rows.get('google_service_account.' + key, {}).get('attributes', {})
            if not account:
                raise ValueError('IAM binding has no owned service account')
            if kind == 'google_artifact_registry_repository_iam_member':
                if (value['member'] != 'serviceAccount:' + account['email']
                        or value['location'] != topology.registry_region(config)
                        or value['repository'] not in {gcp.image_repository(config), repository['name'], repository['id']}):
                    raise ValueError('IAM binding targets a foreign repository or identity')
            elif kind == 'google_service_account_iam_member':
                if value['service_account_id'] not in {account['name'], account['id']}:
                    raise ValueError('IAM binding targets a foreign service account')
            elif kind == 'google_compute_instance_iam_member':
                if value['instance_name'] not in {hosts[key]['name'], 'projects/' + config['project_id'] + '/zones/' + hosts[key]['zone'] + '/instances/' + hosts[key]['name']}:
                    raise ValueError('IAM binding targets a foreign VM')
            elif kind == 'google_iap_tunnel_instance_iam_member':
                vm = rows.get('google_compute_instance.' + key, {}).get('attributes', {})
                if not vm or str(value['instance']) not in {hosts[key]['name'], str(vm['instance_id']), 'projects/' + config['project_id'] + '/iap_tunnel/zones/' + hosts[key]['zone'] + '/instances/' + hosts[key]['name']}:
                    raise ValueError('IAP binding targets a foreign VM')
        if kind in {'google_compute_firewall', 'google_compute_router', 'google_compute_subnetwork'}:
            if value['network'] not in {network.get('self_link'), network.get('id')}:
                raise ValueError('Resource uses a foreign network')
    return rows


def cloud(config, args, missing=False):
    # IAM intentionally returns an ambiguous PERMISSION_DENIED after some
    # deletions. Only a successful project-wide list can prove that this exact
    # service-account email is absent. Never reinterpret a denied get request.
    if missing and args[:3] == ['iam', 'service-accounts', 'describe']:
        email = args[3]
        if not email.endswith('@' + config['project_id'] + '.iam.gserviceaccount.com'):
            raise ValueError('Service-account inspection is outside this project')
        accounts = safe._cloud(safe._args(config, ['iam', 'service-accounts', 'list']))
        if not isinstance(accounts, list):
            raise ValueError('Cannot establish complete project service-account inventory')
        matches = [item for item in accounts if item.get('email') == email]
        if len(matches) > 1:
            raise ValueError('Ambiguous service-account inventory')
        return matches[0] if matches else None
    return safe._cloud(safe._args(config, args), missing=missing)


def fresh(created, start):
    return datetime.fromisoformat(created.replace('Z', '+00:00')) >= datetime.fromisoformat(start.replace('Z', '+00:00'))


def inspect_live(config, rows, launch):
    snapshots = []
    hosts = {h['id'].replace('-', '_'): h for h in topology.hosts(config)}
    for address, row in rows.items():
        if address == REPOSITORY or row['type'].endswith('_iam_member'):
            continue
        args = safe._describe_args(row)
        if args is None:
            raise ValueError('Unknown cloud resource type')
        value = row['attributes']
        live = cloud(config, args, missing=True)
        if live is None and row['type'] != 'google_compute_router_nat':
            raise ValueError('Unexpectedly absent original resource before inspection')
        safe._check_identity(config, row, live)
        snapshot = dict(row, describe=args, identity=safe._identity(live))
        if row['type'] in {'google_compute_instance', 'google_compute_disk'}:
            if not fresh(value['creation_timestamp'], launch['createdAt']):
                raise ValueError('VM or state disk predates this failed launch')
        if row['type'] == 'google_compute_disk':
            if (live['labels'].get('experiment') != config['campaign']
                    or live['labels'].get('purpose') != 'retain-protocol-state'
                    or str(live['sizeGb']) != str(config['state_disk_gib'])
                    or any(value.get(k) for k in ['image', 'snapshot', 'source_disk', 'source_snapshot_id', 'source_image_id', 'source_storage_object'])):
                raise ValueError('State disk is not a fresh empty disk from this smoke')
            host = hosts[row['key']]
            expected_user = 'https://www.googleapis.com/compute/v1/projects/' + config['project_id'] + '/zones/' + host['zone'] + '/instances/' + host['name']
            if any(user != expected_user for user in live.get('users', [])):
                raise ValueError('State disk is attached to a foreign VM')
        if row['type'] == 'google_compute_instance':
            host = hosts[row['key']]
            metadata = {m['key']: m.get('value') for m in live.get('metadata', {}).get('items', [])}
            if (live.get('labels', {}).get('experiment') != config['campaign']
                    or metadata.get('vcfhe-campaign') != config['campaign'] or metadata.get('vcfhe-host') != host['id']
                    or live.get('status') != 'TERMINATED'):
                raise ValueError('Original stopped smoke VM identity does not match')
            disks = live.get('disks', [])
            if len(disks) != 2 or sum(bool(d.get('boot')) for d in disks) != 1:
                raise ValueError('Unexpected VM attachments')
            names = {safe._disk_ref(config, d['source'], host['zone']) for d in disks}
            if names != {host['name'], host['name'] + '-state'}:
                raise ValueError('Foreign disk is attached to the smoke VM')
            boot = next(d for d in disks if d.get('boot'))
            if not boot.get('autoDelete'):
                raise ValueError('Boot disk would survive VM deletion')
            boot_args = ['compute', 'disks', 'describe', host['name'], '--zone', host['zone']]
            boot_live = cloud(config, boot_args)
            if boot_live.get('users') != [live['selfLink']] or not fresh(boot_live['creationTimestamp'], launch['createdAt']):
                raise ValueError('Boot disk is not fresh and exclusively owned by this VM')
            snapshots.append({'address': 'boot.' + row['key'], 'type': 'boot-disk', 'describe': boot_args,
                              'identity': safe._identity(boot_live)})
        snapshots.append(snapshot)
    return snapshots


def terraform(work, args, logfile):
    with Path(logfile).open('ab') as log:
        os.fchmod(log.fileno(), 0o600)
        result = subprocess.run(['terraform', '-chdir=' + str(work), *args], stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise ValueError('Terraform operation failed. Inspect its private cleanup log')


def show_plan(work, planfile, destination):
    result = subprocess.run(['terraform', '-chdir=' + str(work), 'show', '-json', str(planfile)], capture_output=True)
    if result.returncode:
        raise ValueError('Cannot inspect exact destroy plan')
    value = json.loads(result.stdout)
    write(destination, value)
    return value


def validate_plan(plan, rows):
    deletes = []
    for change in plan.get('resource_changes', []):
        address = change['address']
        actions = change['change']['actions']
        if change.get('mode') == 'data':
            if address != 'data.google_compute_image.debian' or actions not in [['no-op'], ['read'], ['delete']]:
                raise ValueError('Unexpected data action')
            continue
        if actions == ['no-op']:
            continue
        if address == REPOSITORY or address not in rows or actions != ['delete']:
            raise ValueError('Destroy plan includes a protected, foreign, create or update action')
        before = change['change'].get('before', {})
        if before.get('id') != rows[address]['attributes'].get('id'):
            raise ValueError('Destroy plan resource identity differs from original ownership')
        for field in ['instance_id', 'disk_id', 'unique_id']:
            if rows[address]['attributes'].get(field) and before.get(field) != rows[address]['attributes'][field]:
                raise ValueError('Destroy plan resource was replaced')
        deletes.append(address)
    return deletes


def plan_destroy(work, rows, log):
    targets = ['-target=' + a for a in sorted(rows) if a != REPOSITORY]
    output = work / 'cleanup.tfplan'
    terraform(work, ['plan', '-destroy', '-input=false', '-out=' + str(output), *targets], log)
    value = show_plan(work, output, work.parent / 'destroy-plan.local.json')
    return validate_plan(value, rows)


def prepare(config, run):
    run, launch = scope(config, run)
    original = run / 'terraform/terraform.tfstate'
    state = read(original)
    rows = state_rows(config, state)
    snapshots = inspect_live(config, rows, launch)
    destination = safe._private(run / 'uninitialized-cleanup-private')
    if destination.exists():
        raise ValueError('Existing cleanup preparation is preserved. Inspect it instead of overwriting')
    destination.mkdir(mode=0o700)
    os.chmod(destination, 0o700)
    original_hashes = {}
    archive = destination / 'original-failed-run.tar'
    with archive.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        with tarfile.open(fileobj=output, mode='w') as tar:
            for path in sorted(run.rglob('*')):
                if path.is_relative_to(destination) or '.terraform' in path.relative_to(run).parts:
                    continue
                if path.is_symlink():
                    raise ValueError('Unexpected symlink in original evidence')
                if path.is_file():
                    name = str(path.relative_to(run))
                    original_hashes[name] = sha(path)
                    tar.add(path, arcname=name, recursive=False)
        output.flush()
        os.fsync(output.fileno())
    work = destination / 'terraform-work'
    work.mkdir(mode=0o700)
    declaration = copy.deepcopy(gcp.terraform(config))
    for disk in declaration['resource']['google_compute_disk'].values():
        disk.get('lifecycle', {}).pop('prevent_destroy', None)
    # Shared repository ownership is detached ONLY from this disposable copy.
    # The original imported repository record remains in the archived run.
    state['resources'] = [r for r in state['resources'] if r['type'] + '.' + r['name'] != REPOSITORY]
    state['outputs'] = {}
    write(work / 'main.tf.json', declaration)
    write(work / 'terraform.tfstate', state)
    write(work / 'terraform.tfvars.json', {'project_id': config['project_id']})
    for name in ['bootstrap.sh', '.terraform.lock.hcl']:
        source = run / 'terraform' / name
        if source.is_file():
            shutil.copy2(source, work / name)
            os.chmod(work / name, 0o600)
    repository = cloud(config, ['artifacts', 'repositories', 'describe', gcp.image_repository(config), '--location', topology.registry_region(config)])
    manifest = {'schema': 'vcfhe-uninitialized-smoke-cleanup-v1', 'status': 'prepared',
                'run': str(run), 'configSha256': topology.digest(config), 'originalStateSha256': sha(original),
                'originalArchiveSha256': sha(archive), 'originalFiles': original_hashes,
                'ownedAddresses': sorted(a for a in rows if a != REPOSITORY), 'snapshots': snapshots,
                'repositoryIdentity': {k: repository[k] for k in ['name', 'createTime'] if k in repository},
                'noProtocolStageStarted': True, 'createdAt': datetime.now(timezone.utc).isoformat()}
    write(destination / 'manifest.local.json', manifest)
    log = destination / 'terraform-cleanup.log'
    terraform(work, ['init', '-input=false', '-backend=false'], log)
    deletes = plan_destroy(work, rows, log)
    manifest.update(deleteAddresses=deletes, planSha256=sha(work / 'cleanup.tfplan'), planJsonSha256=sha(destination / 'destroy-plan.local.json'))
    write(destination / 'manifest.local.json', manifest)
    if sha(original) != manifest['originalStateSha256']:
        raise ValueError('Original Terraform state changed during preparation')
    return {'status': 'prepared', 'destroyActions': len(deletes), 'virtualMachines': sum(r['type'] == 'google_compute_instance' for r in rows.values()), 'originalStatePreserved': True, 'sharedRepositoryProtected': True}


def apply(config, run):
    run, _ = scope(config, run)
    destination = safe._private(run / 'uninitialized-cleanup-private')
    manifest = read(destination / 'manifest.local.json')
    work = destination / 'terraform-work'
    original = run / 'terraform/terraform.tfstate'
    rows = state_rows(config, read(original))
    if (manifest['run'] != str(run) or manifest['configSha256'] != topology.digest(config)
            or manifest['originalStateSha256'] != sha(original)
            or manifest['originalArchiveSha256'] != sha(destination / 'original-failed-run.tar')):
        raise ValueError('Original evidence or exact cleanup scope changed')
    for name, digest in manifest['originalFiles'].items():
        if sha(run / name) != digest:
            raise ValueError('Original failed-run evidence changed after archive')
    if (sha(work / 'cleanup.tfplan') != manifest['planSha256']
            or sha(destination / 'destroy-plan.local.json') != manifest['planJsonSha256']):
        raise ValueError('Prepared exact destroy plan changed')
    validate_plan(read(destination / 'destroy-plan.local.json'), rows)
    for row in manifest['snapshots']:
        live = cloud(config, row['describe'], missing=True)
        if live is not None and safe._identity(live) != row['identity']:
            raise ValueError('A resource was replaced after preparation')
    # Protection changes happen only after all identities and destroy actions
    # have been reviewed. Plan refresh then records the real disabled state.
    for row in manifest['snapshots']:
        if row['type'] == 'google_compute_instance' and cloud(config, row['describe'], missing=True) is not None:
            a = row['attributes']
            cloud(config, ['compute', 'instances', 'update', a['name'], '--zone', a['zone'], '--no-deletion-protection', '--quiet'])
    log = destination / 'terraform-cleanup.log'
    deletes = plan_destroy(work, rows, log)
    terraform(work, ['apply', '-input=false', str(work / 'cleanup.tfplan')], log)
    return verify(config, run)


def verify(config, run):
    """Read-only cloud verification after a completed disposable TF destroy.

    This can finish bookkeeping when destroy succeeded but a conservative
    absence check stopped the original command. It never repeats destroy.
    """
    run, _ = scope(config, run)
    destination = safe._private(run / 'uninitialized-cleanup-private')
    manifest = read(destination / 'manifest.local.json')
    work = destination / 'terraform-work'
    original = run / 'terraform/terraform.tfstate'
    rows = state_rows(config, read(original))
    if (manifest['run'] != str(run) or manifest['configSha256'] != topology.digest(config)
            or manifest['originalStateSha256'] != sha(original)
            or manifest['originalArchiveSha256'] != sha(destination / 'original-failed-run.tar')):
        raise ValueError('Original evidence or exact cleanup scope changed')
    for name, digest in manifest['originalFiles'].items():
        if sha(run / name) != digest:
            raise ValueError('Original failed-run evidence changed after archive')
    remaining = [r for r in read(work / 'terraform.tfstate').get('resources', []) if r.get('mode') != 'data']
    if remaining:
        raise ValueError('Disposable cleanup state still owns managed resources')
    deletes = validate_plan(read(destination / 'destroy-plan.local.json'), rows)
    for row in manifest['snapshots']:
        if cloud(config, row['describe'], missing=True) is not None:
            raise ValueError('An exact smoke resource remains after destroy')
    repository = cloud(config, ['artifacts', 'repositories', 'describe', gcp.image_repository(config), '--location', topology.registry_region(config)])
    if {k: repository[k] for k in ['name', 'createTime'] if k in repository} != manifest['repositoryIdentity']:
        raise ValueError('Shared repository identity differs after cleanup')
    for image in config['images'].values():
        cloud(config, ['artifacts', 'docker', 'images', 'describe', image])
    if sha(original) != manifest['originalStateSha256']:
        raise ValueError('Original Terraform state changed')
    result = {'status': 'passed', 'removedManagedResources': len(manifest['ownedAddresses']),
              'lastDestroyActions': len(deletes), 'originalEvidencePreserved': True,
              'sharedImagesPreserved': True, 'protocolStateNeverCreated': True,
              'completedAt': datetime.now(timezone.utc).isoformat()}
    write(destination / 'cleanup-result.local.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'apply', 'verify'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    cloud_tools.ensure()
    config = read(safe._private(args.config))
    result = globals()[args.action](config, args.run)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
