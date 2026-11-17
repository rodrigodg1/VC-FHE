"""Install missing local cloud CLIs from verified official archives."""
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

CACHE=Path(__file__).resolve().parents[1]/'.cache/gcp-preparation-tools'
SDK_VERSION='590.0.1'
SDK_CHECKSUMS={
 ('Darwin','arm64'):('darwin-arm','02f20618f43b9147e049a73fec37ab71b586b0dc6a242fa6ca835229cb5e542f'),
 ('Darwin','x86_64'):('darwin-x86_64','32e41cdb54d3946bcd5d29bd2bd9f3d8923bf1578e8ecc94d0999f2f18f2f0f1'),
 ('Linux','x86_64'):('linux-x86_64','d1ae7be7e12c4e7d8286fab4774f5441020aca89dc7793ddacbace8d11d20f06'),
 ('Linux','aarch64'):('linux-arm','fd760d8b1c2c4c484d7b659964994b07aaefddc6ac4350e681940477dbdbb22c')}

def download(url,target,digest):
    target=Path(target)
    if not target.exists():
        pending=target.with_suffix(target.suffix+'.pending')
        with urllib.request.urlopen(url,timeout=60) as response,pending.open('wb') as stream:
            shutil.copyfileobj(response,stream)
        pending.replace(target)
    if hashlib.sha256(target.read_bytes()).hexdigest()!=digest:
        raise ValueError('Official download checksum changed. Review the tool manifest before execution: '+str(target))

def ensure():
    CACHE.mkdir(parents=True,exist_ok=True)
    installed={}
    sdk=shutil.which('gcloud') or str(CACHE/'google-cloud-sdk/bin/gcloud')
    if not Path(sdk).is_file():
        package,digest=SDK_CHECKSUMS[(platform.system(),platform.machine())]
        name='google-cloud-cli-'+SDK_VERSION+'-'+package+'.tar.gz'
        download('https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/'+name,CACHE/name,digest)
        with tarfile.open(CACHE/name) as archive:archive.extractall(CACHE,filter='data')
    from sdk_invocation import safe_sdk_invocation,validate_python_invocation
    sdk=safe_sdk_invocation(sdk)
    validate_python_invocation(os.environ.get('CLOUDSDK_PYTHON') or sys.executable)
    installed['gcloud']=sdk
    terraform=shutil.which('terraform') or str(CACHE/'terraform')
    if not Path(terraform).is_file():
        system={'Darwin':'darwin','Linux':'linux'}[platform.system()]
        arch={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
        name=f'terraform_1.9.8_{system}_{arch}.zip'
        base='https://releases.hashicorp.com/terraform/1.9.8/'
        sums=urllib.request.urlopen(base+'terraform_1.9.8_SHA256SUMS',timeout=30).read().decode().splitlines()
        digest=next(line.split()[0] for line in sums if line.split()[-1]==name)
        download(base+name,CACHE/name,digest)
        with zipfile.ZipFile(CACHE/name) as archive:
            with archive.open('terraform') as source,Path(terraform).open('wb') as dest:shutil.copyfileobj(source,dest)
        Path(terraform).chmod(0o755)
    installed['terraform']=terraform
    os.environ['PATH']=os.pathsep.join([str(Path(p).parent) for p in installed.values()])+os.pathsep+os.environ['PATH']
    if not os.environ.get('CLOUDSDK_PYTHON'):os.environ['CLOUDSDK_PYTHON']=sys.executable
    for name,path in installed.items():
        subprocess.run([path,'--version'] if name=='gcloud' else [path,'version'],check=True,stdout=subprocess.DEVNULL)
    return installed
