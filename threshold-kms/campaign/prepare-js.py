"""Recorded Linux-only correction of an extraneous macOS lockfile entry.

The repository lock and every package version/integrity remain unchanged. This
does not use --force or disable integrity/platform checks globally.
"""
import hashlib
import json
from pathlib import Path

root=Path('/app');path=root/'fhe-pod/package-lock.json';original=path.read_bytes();lock=json.loads(original)
name='node_modules/ganache/node_modules/fsevents'
entry=lock['packages'][name]
if entry['version']!='2.3.2' or entry['os']!=['darwin'] or not entry['extraneous']:
    raise ValueError('unexpected platform-lock structure')
entry['optional']=True
adapted=(json.dumps(lock,indent=2)+'\n').encode();path.write_bytes(adapted)
(root/'threshold-kms/campaign/js-lock-adaptation.json').write_text(json.dumps({
 'reason':'extraneous bundled Darwin-only fsevents must be optional on Linux',
 'entry':name,'originalSha256':hashlib.sha256(original).hexdigest(),
 'adaptedSha256':hashlib.sha256(adapted).hexdigest(),'changedVersions':False},indent=2))
