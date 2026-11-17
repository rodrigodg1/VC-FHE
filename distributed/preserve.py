"""Copy publication evidence and current reproduction sources, never runtime secrets."""
import hashlib
import importlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]

def sha(file):
    value = hashlib.sha256()
    with Path(file).open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""): value.update(block)
    return value.hexdigest()


def preserve_sources(destination):
    """Snapshot the current public code without a prior run or implementation."""
    from source_bundle import public_sources
    destination=Path(destination).resolve()
    if destination.exists():raise ValueError('snapshot destination already exists')
    files=public_sources(ROOT)
    before={name:sha(path) for name,path in files.items()}
    destination.mkdir(parents=True,mode=0o700)
    for name,path in files.items():
        target=destination/'source'/name
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(path,target)
        if sha(path)!=before[name] or sha(target)!=before[name]:
            raise ValueError('source changed during preservation')
    manifest={'schema':'vcfhe-preserved-sources-v1',
              'files':{'source/'+name:value for name,value in before.items()},
              'raw_run_copied':False,'private_state_copied':False,
              'scope':'Public reproduction sources. No prior results, implementation or private runtime state.'}
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    verify(destination)
    return manifest

def verify(destination):
    destination = Path(destination).resolve()
    manifest = json.loads((destination/"manifest.json").read_text())
    if manifest["schema"] not in {"vcfhe-preserved-sources-v1"}: raise ValueError("unknown snapshot")
    for name, expected in manifest["files"].items():
        file = destination/name
        if not file.resolve().is_relative_to(destination) or file.is_symlink() or sha(file) != expected:
            raise ValueError("snapshot file mismatch: "+name)
    return {"verified_files": len(manifest["files"]), "raw_seal_reverified": False}
