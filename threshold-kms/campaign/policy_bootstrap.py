"""Fail-closed first setup for an experimental release-policy installation.

This module never starts Docker, creates keys, deploys contracts or resets state.
The runner holds bootstrap_lock for its entire campaign. New installations create
their identities before Besu, then checkpoint those identities before any chain
resource is created. Existing installations keep policy-init's chain checks.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

SCHEMA = 'vcfhe-policy-bootstrap-v1'
PROJECT = 'vcfhe-besu'
NETWORK = 'vcfhe-besu_default'
MANIFEST = 'bootstrap.json'
IDENTITIES = ('owner/identities.json', 'recipient/signing.hex', 'setup/signing.hex')
_HELD_LOCKS = set()
_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _root(root):
    root = Path(root).absolute()
    if root.is_symlink():
        raise ValueError('policy-state directory must not be a symbolic link')
    return root


@contextmanager
def bootstrap_lock(policy_root):
    """Serialize all runs independently of the build-cache directory."""
    root = _root(policy_root)
    key = str(root)
    if key in _HELD_LOCKS:
        raise RuntimeError('policy bootstrap lock is already held in this process')
    lock_path = root.parent / (root.name + '.bootstrap.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('another campaign is using the cumulative policy state') from error
        _HELD_LOCKS.add(key)
        yield
    finally:
        _HELD_LOCKS.discard(key)
        os.close(fd)


def _require_lock(root):
    if str(_root(root)) not in _HELD_LOCKS:
        raise RuntimeError('policy bootstrap mutation requires bootstrap_lock')


def inspect_docker_state(project=PROJECT, network=NETWORK, runner=None):
    """Read daemon identity and existing project resources without starting it."""
    runner = runner or subprocess.run

    def output(arguments):
        try:
            result = runner(['docker', *arguments], capture_output=True, text=True,
                            check=True, timeout=20)
            return result.stdout.strip()
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError('Docker state could not be inspected without mutation') from error

    context = output(['context', 'show'])
    endpoint = json.loads(output(['context', 'inspect', context, '--format',
                                  '{{json .Endpoints.docker.Host}}']))
    # DOCKER_HOST overrides the context endpoint unless DOCKER_CONTEXT is set.
    if os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'):
        endpoint = os.environ['DOCKER_HOST']
    info = json.loads(output(['info', '--format', '{{json .}}']))

    def selected(arguments):
        rows = [json.loads(line) for line in output(arguments).splitlines() if line.strip()]
        names = []
        for row in rows:
            name = row.get('Name', row.get('Names', ''))
            labels = row.get('Labels', '')
            owned = (labels.get('com.docker.compose.project') == project if isinstance(labels, dict)
                     else f'com.docker.compose.project={project}' in labels.split(','))
            if owned or name == network or name.startswith((project + '_', project + '-')):
                names.append(name)
        return sorted(set(names))

    inventory = {
        'project': project, 'network': network,
        'binding': {'context': context, 'endpoint': endpoint, 'daemonId': info.get('ID')},
        'volumes': selected(['volume', 'ls', '--format', '{{json .}}']),
        'networks': selected(['network', 'ls', '--format', '{{json .}}']),
        'containers': selected(['ps', '-a', '--format', '{{json .}}']),
    }
    _validate_inventory(inventory)
    return inventory


def _validate_inventory(inventory):
    if not isinstance(inventory, dict):
        raise ValueError('Docker inventory is required')
    binding = inventory.get('binding')
    if (not isinstance(binding, dict) or set(binding) != {'context', 'endpoint', 'daemonId'}
            or any(not isinstance(value, str) or not value.strip() for value in binding.values())):
        raise ValueError('Docker daemon and context identity are unavailable')
    for field in ('volumes', 'networks', 'containers'):
        if (not isinstance(inventory.get(field), list)
                or any(not isinstance(name, str) or not name for name in inventory[field])):
            raise ValueError('Docker resource inventory is incomplete')
    if not inventory.get('project') or not inventory.get('network'):
        raise ValueError('Docker project and network are required')


def _resources(inventory):
    return any(inventory[name] for name in ('volumes', 'networks', 'containers'))


def _files(root):
    if not root.exists():
        return set()
    if not root.is_dir():
        raise ValueError('policy-state path is not a directory')
    files = set()
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('symbolic links are not permitted in policy bootstrap state')
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError('unsupported entry in policy bootstrap state')
    return files


def _read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f'policy state is unreadable: {path.name}') from error


def _key(value):
    if not isinstance(value, str):
        raise ValueError('invalid retained signing identity')
    value = value.removeprefix('0x')
    if not re.fullmatch('[0-9a-fA-F]{64}', value) or not 0 < int(value, 16) < _CURVE_ORDER:
        raise ValueError('invalid retained signing identity')
    return value.lower()


def _identity_hashes(root, complete):
    hashes = {}
    for name in IDENTITIES:
        path = root / name
        if not path.exists():
            if complete:
                raise ValueError('retained bootstrap identity is missing: ' + name)
            continue
        try:
            if name.startswith('owner/'):
                owners = _read_json(path)
                if not isinstance(owners, list) or len(owners) != 4 or len({_key(key) for key in owners}) != 4:
                    raise ValueError('invalid retained owner identity set')
            else:
                _key(path.read_text().strip())
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, UnicodeError) as error:
            raise ValueError('retained identity cannot be read: ' + name) from error
    return hashes


def _deployment(root):
    state = _read_json(root / 'onchain/deployment.json')
    if (not isinstance(state, dict) or state.get('schema') != 'vcfhe-release-policy-deployment-v3'
            or state.get('status') not in {'pending', 'deployed'}):
        raise ValueError('retained policy deployment is malformed')
    # Full bytecode, receipt, owner and rollback checks remain in policy-init.
    return state


def _decision(kind, manifest=None, allow=False, identities_first=False):
    return {'kind': kind, 'bootstrapId': manifest.get('bootstrapId') if manifest else None,
            'phase': manifest.get('phase') if manifest else None,
            'allowNewLineage': allow, 'identitiesMustRunFirst': identities_first}


def classify_bootstrap(policy_root, inventory):
    """Return the next safe action. This function never writes or creates files."""
    root = _root(policy_root)
    _validate_inventory(inventory)
    files = _files(root)
    has_deployment = 'onchain/deployment.json' in files
    if MANIFEST not in files:
        if has_deployment:
            _deployment(root)
            if 'owner/identities.json' not in files:
                raise ValueError('on-chain policy exists but owner identities are missing')
            _identity_hashes(root, complete=False)
            return _decision('existing')
        if 'gateway/ledger.json' in files and 'owner/identities.json' in files:
            _identity_hashes(root, complete=False)
            return _decision('legacy-migration')
        if files or _resources(inventory):
            raise ValueError('partial or orphaned policy state requires restoration, not a new policy')
        if inventory['project'] != PROJECT or inventory['network'] != NETWORK:
            raise ValueError('automatic first setup requires the default Besu project and network')
        return _decision('fresh', allow=True, identities_first=True)

    manifest = _read_json(root / MANIFEST)
    if (not isinstance(manifest, dict) or manifest.get('schema') != SCHEMA
            or not re.fullmatch('[0-9a-f]{32}', str(manifest.get('bootstrapId', '')))
            or manifest.get('phase') not in {'planned', 'identities-ready', 'policy-started', 'deployed'}):
        raise ValueError('bootstrap manifest is malformed')
    if (manifest.get('project') != inventory['project'] or manifest.get('network') != inventory['network']
            or manifest.get('binding') != inventory['binding']):
        raise ValueError('bootstrap Docker daemon, context or project changed')
    phase = manifest['phase']
    if phase == 'planned':
        if _resources(inventory) or has_deployment or files - {MANIFEST, *IDENTITIES}:
            raise ValueError('bootstrap identities must be fixed before creating chain resources')
        _identity_hashes(root, complete=False)
        return _decision('bootstrap-resume', manifest, allow=True, identities_first=True)
    hashes = _identity_hashes(root, complete=True)
    if hashes != manifest.get('identitySha256'):
        raise ValueError('retained bootstrap identities changed')
    if phase == 'identities-ready':
        if has_deployment or 'gateway/ledger.json' in files:
            raise ValueError('deployment appeared before the bootstrap policy-started checkpoint')
        return _decision('bootstrap-resume', manifest, allow=True)
    if not has_deployment:
        raise ValueError('bootstrap policy deployment state is missing after policy initialization started')
    deployment = _deployment(root)
    if phase == 'deployed' and (deployment.get('status') != 'deployed'
                              or _deployment_binding(deployment) != manifest.get('deployment')):
        raise ValueError('retained bootstrap deployment changed')
    return _decision('existing', manifest)


def _atomic(path, value):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.pending')
    with temporary.open('x', encoding='utf8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    _fsync(path.parent)


def _fsync(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare_bootstrap(policy_root, inventory):
    _require_lock(policy_root)
    root = _root(policy_root)
    decision = classify_bootstrap(root, inventory)
    if decision['kind'] != 'fresh':
        return decision
    root.mkdir(exist_ok=True, mode=0o700)
    _fsync(root.parent)
    manifest = {'schema': SCHEMA, 'bootstrapId': uuid.uuid4().hex, 'phase': 'planned',
                'project': inventory['project'], 'network': inventory['network'],
                'binding': inventory['binding']}
    _atomic(root / MANIFEST, manifest)
    return _decision('fresh', manifest, allow=True, identities_first=True)


def mark_identities_ready(policy_root, inventory):
    _require_lock(policy_root)
    root = _root(policy_root)
    decision = classify_bootstrap(root, inventory)
    if decision['phase'] == 'identities-ready':
        return decision
    if decision['phase'] != 'planned':
        raise ValueError('bootstrap identities checkpoint is out of order')
    manifest = _read_json(root / MANIFEST)
    manifest.update(phase='identities-ready', identitySha256=_identity_hashes(root, complete=True))
    # Make keys and their directory entries durable before the hash checkpoint.
    for name in IDENTITIES:
        _fsync(root / name)
        _fsync((root / name).parent)
    _fsync(root)
    _atomic(root / MANIFEST, manifest)
    return classify_bootstrap(root, inventory)


def mark_policy_starting(policy_root, inventory):
    _require_lock(policy_root)
    root = _root(policy_root)
    decision = classify_bootstrap(root, inventory)
    if decision['phase'] != 'identities-ready':
        raise ValueError('bootstrap policy checkpoint is out of order')
    manifest = _read_json(root / MANIFEST)
    manifest['phase'] = 'policy-started'
    _atomic(root / MANIFEST, manifest)
    return _decision('bootstrap-resume', manifest, allow=True)


def _deployment_binding(deployment):
    fields = ('address', 'chainId', 'policyVersion', 'genesisBlockHash', 'transactionHash',
              'deploymentBlock', 'deploymentBlockHash', 'sourceSha256', 'compilerVersion')
    binding = {name: deployment.get(name) for name in fields}
    if any(value is None for value in binding.values()):
        raise ValueError('completed bootstrap deployment is missing its chain anchors')
    return binding


def mark_deployed(policy_root, inventory):
    _require_lock(policy_root)
    root = _root(policy_root)
    decision = classify_bootstrap(root, inventory)
    if decision['phase'] == 'deployed':
        return decision
    if decision['phase'] != 'policy-started':
        raise ValueError('bootstrap deployment checkpoint is out of order')
    deployment = _deployment(root)
    if deployment['status'] != 'deployed':
        raise ValueError('pending deployment cannot complete bootstrap')
    manifest = _read_json(root / MANIFEST)
    manifest.update(phase='deployed', deployment=_deployment_binding(deployment))
    _atomic(root / MANIFEST, manifest)
    return classify_bootstrap(root, inventory)
