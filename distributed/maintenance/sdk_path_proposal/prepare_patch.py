"""Render a future source-bound patch without editing cloud_tools.py."""
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('SDK proposal source drift: '+old[:70])
    return text.replace(old,new)


def render():
    original = {'cloud_tools.py':(SOURCE/'cloud_tools.py').read_text()}
    candidate = dict(original)
    candidate['sdk_invocation.py'] = (HERE/'sdk_invocation.py').read_text()
    candidate['cloud_tools.py'] = once(candidate['cloud_tools.py'],
        "    installed['gcloud']=sdk\n",
        "    from sdk_invocation import safe_sdk_invocation,validate_python_invocation\n"
        "    sdk=safe_sdk_invocation(sdk)\n"
        "    validate_python_invocation(os.environ.get('CLOUDSDK_PYTHON') or sys.executable)\n"
        "    installed['gcloud']=sdk\n")
    patch = ''
    for name, value in candidate.items():
        patch += ''.join(difflib.unified_diff(original.get(name,'').splitlines(True),value.splitlines(True),
            fromfile='a/VC-FHE/distributed/'+name if name in original else '/dev/null',
            tofile='b/VC-FHE/distributed/'+name))
    return original,candidate,patch


def hashes(values):
    return {name:hashlib.sha256(value.encode()).hexdigest() for name,value in values.items()}


if __name__=='__main__':
    original,candidate,patch=render()
    (HERE/'proposal.patch').write_text(patch)
    (HERE/'proposal.json').write_text(json.dumps({'schema':'vcfhe-sdk-path-proposal-v1',
        'status':'unapplied','source':hashes(original),'candidate':hashes(candidate),
        'sdkCopied':False,'credentialsChanged':False,'cloudCalls':[],
        'defaultAliasDirectory':'/tmp/vcfhe-cloud-tools-<uid>',
        'actualCause':'Pinned SDK rejects non-ASCII and control characters in IAP ProxyCommand arguments. ASCII spaces and apostrophes are escaped.'},indent=2)+'\n')
