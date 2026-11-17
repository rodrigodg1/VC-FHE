#!/usr/bin/env python3
"""Capture the installed dependency closure, including the adapted execution view."""
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

root=Path('/app')
evidence=root/'threshold-kms/campaign/build-evidence'
for command,name in [(['node','--version'],'node.txt'),(['npm','--version'],'npm.txt'),
                     (['dpkg-query','-W'],'system-packages.txt')]:
    (evidence/name).write_bytes(subprocess.check_output(command))
for component in ['BN254-Signatures','fhe-pod']:
    shutil.copy2(root/component/'package-lock.json',evidence/(component+'-package-lock.json'))
    shutil.copy2(root/component/'node_modules/.package-lock.json',evidence/(component+'-installed-lock.json'))
shutil.copy2(root/'threshold-kms/campaign/js-lock-adaptation.json',evidence/'js-lock-adaptation.json')
shutil.copytree(root/'threshold-kms/campaign/runtime',evidence/'execution-view',symlinks=True)
files={}
for path in sorted(root.rglob('*')):
    if not path.is_file() or path.is_relative_to(evidence):continue
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    files[str(path.relative_to(root))]={'sha256':h.hexdigest(),'bytes':path.stat().st_size}
with gzip.open(evidence/'installed-files.json.gz','wt') as f:json.dump(files,f,sort_keys=True)
