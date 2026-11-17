#!/usr/bin/env python3
"""Unapplied launch-only proposal for an explicit public keyset export."""
import difflib
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[1]/'launch.py'

SCRIPT=r'''import json,re,sys
from pathlib import Path
root=Path(sys.argv[1])
if root.is_symlink() or not root.is_dir():raise ValueError('keyset root must be a real directory')
top={'ready.json','prss.json','encryption-key.bin','evaluation-key.bin','keyset.json','keyset_descriptor.json'}
required={'ready.json','prss.json','encryption-key.bin','evaluation-key.bin'}
public_types={'VerfKey','VerfAddress','PublicKey','CompressedXofKeySet'}
files=[]
for entry in sorted(root.iterdir()):
 if entry.is_symlink():raise ValueError('symlink in keyset root')
 if entry.name=='CLIENT':
  if not entry.is_dir():raise ValueError('CLIENT must remain a local directory')
  continue
 if entry.name in top:
  if not entry.is_file():raise ValueError('public keyset file must be regular')
  files.append('keyset/'+entry.name)
 elif re.fullmatch(r'PUB-p[1-4]',entry.name):
  if not entry.is_dir():raise ValueError('public party prefix must be a directory')
  for kind in sorted(entry.iterdir()):
   if kind.is_symlink():raise ValueError('symlink in public party prefix')
   if kind.name=='tls.pem' and kind.is_file():
    files.append('keyset/'+str(kind.relative_to(root)));continue
   if kind.name not in public_types or not kind.is_dir():raise ValueError('unknown or private public-store category')
   for value in sorted(kind.iterdir()):
    if value.is_symlink() or not value.is_file():raise ValueError('public object must be a regular nonsymlink file')
    if not re.fullmatch(r'[0-9a-fA-F]{64}',value.name):raise ValueError('unknown public object name')
    files.append('keyset/'+str(value.relative_to(root)))
 else:raise ValueError('unknown or private keyset root entry')
if not required<={Path(p).name for p in files if p.count('/')==1}:raise ValueError('incomplete public keyset')
print(json.dumps(files))
'''

def render():
    original=SOURCE.read_text()
    anchor="HERE=Path(__file__).resolve().parent\n"
    if original.count(anchor)!=1:raise ValueError('launch header drift')
    candidate=original.replace(anchor,"PUBLIC_KEYSET_EXPORT_SCRIPT = r'''\n"+SCRIPT+"'''\n\n"+anchor)
    old="        self.remote('coordinator-1').download(self.root('coordinator-1'),['keyset'],self.run/'setup-public')"
    new="""        # Keep the SDK CLIENT identity local to the coordinator. Inspect names
        # only, then export the explicit public selection rather than the tree.
        public_paths=self.remote('coordinator-1').json(['sudo','python3','-c',PUBLIC_KEYSET_EXPORT_SCRIPT,
            self.root('coordinator-1')+'/keyset'])
        self.remote('coordinator-1').download(self.root('coordinator-1'),public_paths,self.run/'setup-public')"""
    if candidate.count(old)!=1:raise ValueError('setup download anchor drift')
    candidate=candidate.replace(old,new)
    patch=''.join(difflib.unified_diff(original.splitlines(True),candidate.splitlines(True),
        fromfile='a/VC-FHE/distributed/launch.py',tofile='b/VC-FHE/distributed/launch.py'))
    return original,candidate,patch

def main():
    original,candidate,patch=render()
    (HERE/'proposal.patch').write_text(patch)
    (HERE/'proposal.json').write_text(json.dumps({'schema':'vcfhe-public-keyset-export-proposal-v1',
        'status':'unapplied','sourceSha256':hashlib.sha256(original.encode()).hexdigest(),
        'candidateSha256':hashlib.sha256(candidate.encode()).hexdigest(),
        'coordinatorClientPreserved':True,'protocolChanged':False,'cloudActions':False},indent=2)+'\n')

if __name__=='__main__':main()
