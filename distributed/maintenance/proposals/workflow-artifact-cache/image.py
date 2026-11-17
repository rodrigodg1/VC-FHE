"""Create an isolated Docker build context. Never build, push, or deploy here."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import deployment

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent

def adapter_sources():
    return [source for source in sorted(HERE.glob('*'))
            if source.is_file() and source.suffix in ('.py','.mjs','.sh')]

def verify_adapter_sources(record):
    """Reject added, removed or changed adapters after context preparation."""
    current={source.name:hashlib.sha256(source.read_bytes()).hexdigest()
             for source in adapter_sources()}
    if current!=record.get('distributedSource'):
        raise ValueError('Prepared image context has stale adapters. Use a new build directory.')

def inputs(directory):
    """Bind every copied build input, including additions and symlink targets."""
    directory=Path(directory)
    result={}
    for top in ('app','upstream'):
        for path in sorted((directory/top).rglob('*')):
            name=str(path.relative_to(directory))
            if path.is_symlink():
                result[name]={'symlink':str(path.readlink())}
            elif path.is_file():
                result[name]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    return result

def verify_inputs(directory,record):
    if hashlib.sha256((directory/'Dockerfile').read_bytes()).hexdigest()!=record['dockerfileSha256']:
        raise ValueError('Dockerfile changed after preparation')
    if not record.get('buildInputs') or inputs(directory)!=record['buildInputs']:
        raise ValueError('copied build inputs changed after preparation')

def prepare(cache,output):
    cache,output=Path(cache).resolve(),Path(output).resolve()
    if output.exists():raise ValueError('image build output already exists')
    module=deployment.campaign_module()
    manifest=module.source_manifest()
    # Existing guarded upstream adapter and exact Cargo lock are reused.
    original,_=module.build_context(cache,manifest)
    output.mkdir(parents=True)
    shutil.copytree(original/'app',output/'app')
    shutil.copytree(original/'upstream',output/'upstream')
    distributed={}
    for source in adapter_sources():
        target=output/'app/distributed'/source.name
        target.parent.mkdir(exist_ok=True)
        shutil.copy2(source,target)
        distributed[source.name]=hashlib.sha256(source.read_bytes()).hexdigest()
    docker=(original/'Dockerfile').read_text()
    anchor='    python3 /app/threshold-kms/campaign/inventory.py && '
    if docker.count(anchor)!=1:raise ValueError('image inventory build anchor changed')
    docker=docker.replace(anchor,'    python3 /app/distributed/runtime.py --app /app && \\\n'
        '    node --input-type=module -e \'import {buildWorkflowArtifactCache} from "/app/distributed/workflow-artifact-cache.mjs"; await buildWorkflowArtifactCache("/app");\' && \\\n'+anchor)
    (output/'Dockerfile').write_text(docker)
    record={'schema':'vcfhe-distributed-build-v1','localSource':manifest,'distributedSource':distributed,
        'upstreamCommit':module.PIN,'dockerfileSha256':hashlib.sha256(docker.encode()).hexdigest(),
        'baseContext':str(original),'targetPlatform':'linux/amd64','cloudResourcesCreated':False,
        'buildInputs':inputs(output),
        'buildCommand':['docker','buildx','build','--platform','linux/amd64','--load','--tag','vcfhe-distributed:prepared',str(output)]}
    (output/'distributed-source.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

def build(directory):
    directory=Path(directory).resolve()
    record=json.loads((directory/'distributed-source.json').read_text())
    verify_inputs(directory,record)
    subprocess.run(['docker','buildx','build','--platform','linux/amd64','--load','--tag',
                    'vcfhe-distributed:prepared',str(directory)],check=True)
    verify_inputs(directory,record)
    image_id=subprocess.check_output(['docker','image','inspect','vcfhe-distributed:prepared','--format','{{.Id}}'],text=True).strip()
    (directory/'built-image.json').write_text(json.dumps({'imageId':image_id,'sourceSha256':deployment.topology.digest(record)},indent=2)+'\n')
    return {'imageId':image_id,'pushed':False,'cloudResourcesCreated':False}

def push(config,quote,directory):
    import budget,topology
    topology.validate(config)
    if config['project_id']=='replace-with-your-project-id':raise ValueError('actual project required')
    cost=budget.assess(config,quote)
    if cost['status']!='admit':raise ValueError('complete campaign does not fit budget')
    directory=Path(directory).resolve();record=json.loads((directory/'distributed-source.json').read_text())
    built=json.loads((directory/'built-image.json').read_text())
    if built['sourceSha256']!=topology.digest(record):raise ValueError('built image source binding changed')
    import gcp
    region=topology.registry_region(config);registry=region+'-docker.pkg.dev'
    repo=gcp.image_repository(config);project=config['project_id']
    describe=['gcloud','artifacts','repositories','describe',repo,'--location',region,'--project',project,'--format=json']
    result=subprocess.run(describe,capture_output=True,text=True)
    if result.returncode:
        # Describe permission/authentication errors are not treated as absence.
        if 'NOT_FOUND' not in result.stderr:raise ValueError('cannot inspect Artifact Registry: '+result.stderr)
        subprocess.run(['gcloud','artifacts','repositories','create',repo,'--location',region,'--project',project,
                        '--repository-format=docker','--quiet'],check=True)
    token=subprocess.check_output(['gcloud','auth','print-access-token'])
    subprocess.run(['docker','login','-u','oauth2accesstoken','--password-stdin',registry],input=token,stdout=subprocess.DEVNULL,check=True)
    tag=f'{registry}/{project}/{repo}/campaign:{topology.digest(record)[:16]}'
    subprocess.run(['docker','tag',built['imageId'],tag],check=True)
    subprocess.run(['docker','push',tag],check=True)
    digest=subprocess.check_output(['gcloud','artifacts','docker','images','describe',tag,'--project',project,
        '--format=value(image_summary.digest)'],text=True).strip()
    if not __import__('re').fullmatch('sha256:[a-f0-9]{64}',digest):raise ValueError('registry did not return an immutable image digest')
    published=tag.rsplit(':',1)[0]+'@'+digest
    receipt={'digest':published,'sourceSha256':topology.digest(record),'budget':cost}
    (directory/'published-image.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
