"""Real proposal inputs for synthetic image records. No verification bypass."""
import hashlib
from pathlib import Path
import shutil

PROPOSAL = Path(__file__).resolve().parents[1]/'maintenance/proposals/recipient-result-transport'


def native_recipient_proof(directory=PROPOSAL):
    directory = Path(directory)
    return {'version': 'distributed-accepted-submit-results-v1',
            'sourceFiles': {path.relative_to(directory).as_posix():
                            hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in sorted(directory.rglob('*'))
                            if path.is_file() and '__pycache__' not in path.parts
                            and path.suffix in {'.py', '.rs', '.md'}}}


def copy_native_recipient_sources(distributed_root):
    destination = Path(distributed_root)/'maintenance/proposals/recipient-result-transport'
    shutil.copytree(PROPOSAL, destination, ignore=shutil.ignore_patterns('__pycache__'))
    return destination
