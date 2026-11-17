"""Fixed one-use extraction guard executed before loading uploaded runner code."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile


def extract(root,archive_sha,manifest_sha):
    root=Path(root);archive=root/'controller-source.tar.gz';destination=root/'input'
    if destination.exists():raise ValueError('Refuse existing cloud controller input')
    h=hashlib.sha256()
    with archive.open('rb') as stream:
        for block in iter(lambda:stream.read(1024**2),b''):h.update(block)
    if h.hexdigest()!=archive_sha:raise ValueError('Uploaded source archive differs')
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers();names=[m.name for m in members]
        if len(members)>25000 or len(set(names))!=len(names) or sum(m.size for m in members)>4*1024**3:
            raise ValueError('Invalid source inventory')
        for member in members:
            p=Path(member.name)
            if not member.isfile() or p.is_absolute() or '..' in p.parts or '\\' in member.name:
                raise ValueError('Unsafe source member')
        raw=tar.extractfile('source-manifest.json').read()
        if hashlib.sha256(raw).hexdigest()!=manifest_sha:raise ValueError('Source manifest differs')
        manifest=json.loads(raw)
        if set(names)!=set(manifest['files'])|{'source-manifest.json'}:raise ValueError('Incomplete source archive')
        destination.mkdir(mode=0o700)
        for member in members:
            target=destination/member.name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with tar.extractfile(member) as source,target.open('xb') as out:shutil.copyfileobj(source,out)
        for name in ('actor-accounts.local.json','source-archive.local.json'):
            shutil.copy2(root/name,destination/'job'/name)
    return manifest

if __name__=='__main__':extract(*sys.argv[1:])
