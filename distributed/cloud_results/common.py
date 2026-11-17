"""Shared guards for the separate cloud controller."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
DISTRIBUTED = HERE.parent
ROOT = DISTRIBUTED.parent
REPOSITORY = ROOT.parent
sys.path.insert(0, str(DISTRIBUTED))
VERSION = 'cloud-controller-results-v1'
MAX_PACKAGE_BYTES = 256 * 1024**2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            value.update(block)
    return value.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Missing or linked control file')
    return json.loads(path.read_text())


def write(path, value, *, new=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not path.is_symlink() and (not new or not path.exists()), 'Control file already exists or is linked')
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.pending')
    with temporary.open('x') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def safe_file(root, name):
    relative = Path(name)
    require(isinstance(name, str) and not relative.is_absolute() and '..' not in relative.parts
            and '\\' not in name and name not in ('', '.'), 'Unsafe result path')
    root = Path(root).resolve()
    target = root
    for part in relative.parts:
        target = target / part
        require(not target.is_symlink(), 'Symlink in results')
    require(target.is_file() and target.resolve().is_relative_to(root), 'Missing result file: ' + name)
    return target


def private(path):
    from privacy import require_private
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'Private storage must not contain symlinks')
    return require_private(path)


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def gcloud(*args):
    return json.loads(subprocess.check_output(['gcloud', *map(str, args), '--format=json'], text=True))


def sources():
    return {p.name: sha(p) for p in sorted(HERE.glob('*.py'))}


def check_full(config):
    from cloud_results.completion_budget import authorization
    authorization(config)
    import topology
    topology.validate(config)
    require(config.get('execution_mode', 'evaluation') == 'evaluation' and config['layout'] == 'four-hosts',
            'This route requires the complete four-host evaluation campaign')
    require(not config.get('diagnostic_profile') and not config.get('cloud_archive'),
            'Keep the regional smoke and its separate backup profile unchanged')
    require(all(config['images'].values()), 'Compile and pin images before cloud-controller execution')
    require(config['measurement_grid'] == {'paired_measurements': 480, 'full_workflows': 27,
        'warmups': 18, 'evaluation_source': 'validated-cloud', 'preserve_local_evaluation': True},
        'Full 480/18/27 design changed')
    return config


def now():
    return datetime.now(timezone.utc).isoformat()
