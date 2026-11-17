"""Argument-safe IAP transport. Never copies private participant identities."""
import io
import json
import math
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import time
import uuid

READ_ATTEMPTS=3
READ_TIMEOUT_SECONDS=900
HOST_PROFILE_SCRIPT='import json,platform;from pathlib import Path;cpu=next(s.split(":",1)[1].strip() for s in Path("/proc/cpuinfo").read_text().splitlines() if s.startswith("model name"));print(json.dumps(dict(cpuModel=cpu,kernelRelease=platform.release(),architecture=platform.machine())))'

def read_timeout(remote,maximum=READ_TIMEOUT_SECONDS):
    deadline=getattr(remote,'read_deadline',None)
    if deadline is None:return maximum
    if type(deadline) not in (int,float) or not math.isfinite(deadline):
        raise ValueError('invalid original evidence-read deadline')
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('original evidence-read deadline exhausted')
    return min(maximum,remaining)

def retryable_read(error):
    if isinstance(error,subprocess.TimeoutExpired):return True
    if not isinstance(error,subprocess.CalledProcessError):return False
    message=error.stderr or ''
    if isinstance(message,bytes):message=message.decode('utf8',errors='replace')
    return error.returncode==255 or ('4033' in message and 'not authorized' in message.lower())

def read_pause(remote,attempt):
    time.sleep(min(2**attempt,read_timeout(remote)))

def read_host_profile(remote):
    """Retry only this fixed, public metadata read. No generic command retry."""
    for attempt in range(READ_ATTEMPTS):
        try:
            result=remote.run(['python3','-c',HOST_PROFILE_SCRIPT],stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,text=True,timeout=read_timeout(remote,45))
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
            if not retryable_read(error) or attempt+1==READ_ATTEMPTS:raise
            read_pause(remote,attempt)
            continue
        # A successful but malformed response is a validation failure, not an
        # invitation to hide it by reading repeatedly.
        value=json.loads(result.stdout)
        if (not isinstance(value,dict) or set(value)!={'cpuModel','kernelRelease','architecture'}
                or any(not isinstance(v,str) or not v for v in value.values())):
            raise ValueError('invalid public host profile')
        return value

def command(args, **kwargs):
    return subprocess.run([str(x) for x in args],check=True,**kwargs)

class Remote:
    def __init__(self,config,host):self.config,self.host=config,host
    def argv(self,script):
        return ['gcloud','compute','ssh',self.host['name'],'--zone',self.host['zone'],
                '--project',self.config['project_id'],'--tunnel-through-iap','--quiet','--command',script]
    def shell(self,script,**kwargs):return command(self.argv(script),**kwargs)
    def run(self,args,**kwargs):return self.shell(shlex.join(map(str,args)),**kwargs)
    def text(self,args):return self.run(args,stdout=subprocess.PIPE,text=True).stdout.strip()
    def json(self,args):return json.loads(self.text(args))
    def upload(self,source,destination):
        source=Path(source).resolve()
        with tempfile.TemporaryDirectory() as temporary:
            archive=Path(temporary)/'files.tar'
            with tarfile.open(archive,'w') as tar:
                paths=sorted(source.rglob('*')) if source.is_dir() else [source]
                for path in paths:
                    if path.is_symlink():raise ValueError('symlink in deployment input')
                    if path.is_file():tar.add(path,arcname=str(path.relative_to(source)) if source.is_dir() else path.name,recursive=False)
            remote='/tmp/vcfhe-upload-'+uuid.uuid4().hex+'.tar'
            command(['gcloud','compute','scp',str(archive),self.host['name']+':'+remote,
                     '--zone',self.host['zone'],'--project',self.config['project_id'],'--tunnel-through-iap','--quiet'],stdout=subprocess.DEVNULL)
            # Destination is generated from the validated topology, never a remote response.
            self.run(['sudo','install','-d','-o','10001','-g','10001','-m','700',destination])
            self.run(['sudo','tar','--no-same-owner','-xf',remote,'-C',destination])
            self.run(['sudo','chown','-R','10001:10001',destination])
            self.run(['rm','--',remote])
    def download(self,root,names,destination):
        forbidden={'identity','private','chain','policy-state','transport','recipient-identity','owner-identity'}
        for name in names:
            p=Path(name)
            if p.is_absolute() or '..' in p.parts or set(p.parts)&forbidden:
                raise ValueError('private state or noncanonical evidence export')
        destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
        for attempt in range(READ_ATTEMPTS):
            # Every transport attempt starts with a new empty local archive.
            # Nothing is extracted until a complete SSH read exits successfully.
            with tempfile.TemporaryFile() as archive:
                try:
                    self.run(['sudo','tar','-cf','-','-C',root,*names],stdout=archive,
                             stderr=subprocess.PIPE,timeout=read_timeout(self))
                except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
                    if not retryable_read(error) or attempt+1==READ_ATTEMPTS:raise
                    print(f'EVIDENCE DOWNLOAD read-only transport retry {attempt+2}/{READ_ATTEMPTS}',flush=True)
                    read_pause(self,attempt)
                    continue
                archive.seek(0)
                with tarfile.open(fileobj=archive) as tar:
                    members=tar.getmembers()
                    for member in members:
                        p=Path(member.name)
                        if p.is_absolute() or '..' in p.parts or not(member.isfile() or member.isdir()):
                            raise ValueError('unsafe evidence archive entry')
                    for member in members:
                        target=destination/member.name
                        if member.isdir():target.mkdir(parents=True,exist_ok=True);continue
                        target.parent.mkdir(parents=True,exist_ok=True)
                        with target.open('xb') as output,tar.extractfile(member) as source:
                            import shutil
                            shutil.copyfileobj(source,output)
                return

