"""Select public reproduction sources from a standalone VC-FHE directory.

Runtime state, datasets and previous results are deliberately outside this list.
The campaign downloads pinned datasets and creates its own result directories.
No Git checkout or adjacent implementation is required.
"""
import os
from pathlib import Path

DIRECTORIES = (
    'distributed', 'threshold-kms/campaign', 'threshold-kms/src',
    'threshold-kms/scripts', 'threshold-kms/contracts', 'threshold-kms/patches',
    'threshold-kms/postprocess', 'threshold-kms/recovery',
    'fhe-pod/scripts', 'fhe-pod/contracts', 'fhe-pod/crates',
    'BN254-Signatures/scripts', 'BN254-Signatures/contract',
    'BN254-Signatures/test', 'BN254-Signatures/src',
    'datasets/prepare', 'datasets/download', 'datasets/test',
    'network', 'output-binding-lhs/src',
)
EXCLUDED = {'node_modules', '__pycache__', 'target', '.git', '.cache', '.deps',
            '.policy-state', 'runs', 'composites', 'generated', 'metrics',
            'preserved', 'reproduction', 'private', 'identity', 'transport',
            'recipient', 'keyset', 'data', 'keys', 'artifacts', 'cache', '_to_delete'}
EXTENSIONS = {'.py', '.sh', '.ps1', '.rs', '.mjs', '.cjs', '.js', '.sol',
              '.hcl', '.fixture', '.json', '.toml', '.lock', '.yaml', '.yml', '.md', '.txt', '.patch'}


def public_sources(root):
    root = Path(root).resolve()
    files = {}

    def add(path):
        relative = path.relative_to(root)
        if path.name.startswith('.') or path.name.endswith(('.local.json', '.key', '.pem')):
            return
        if path.name not in {'Dockerfile', 'LICENSE'} and path.suffix not in EXTENSIONS:
            return
        if path.is_symlink():
            raise ValueError('Linked reproduction source: ' + relative.as_posix())
        if path.is_file():
            files[relative.as_posix()] = path

    for name in ('', 'fhe-pod', 'BN254-Signatures', 'threshold-kms', 'output-binding-lhs', 'datasets'):
        for path in sorted((root / name).glob('*')):
            if not path.is_dir():
                add(path)
    for name in DIRECTORIES:
        directory = root / name
        if directory.is_symlink():
            raise ValueError('Linked reproduction directory: ' + name)
        for current, dirs, names in os.walk(directory, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not d.startswith('.'))
            for d in dirs:
                if (Path(current) / d).is_symlink():
                    raise ValueError('Linked reproduction directory')
            for filename in sorted(names):
                add(Path(current) / filename)
    required = {'run-poc.sh', 'run-distributed.sh', 'threshold-kms/campaign/run.py',
                'threshold-kms/postprocess/refresh.py', 'distributed/cloud_results/worker.py'}
    if not required <= files.keys():
        raise ValueError('Incomplete VC-FHE source directory: ' + ', '.join(sorted(required - files.keys())))
    return dict(sorted(files.items()))
