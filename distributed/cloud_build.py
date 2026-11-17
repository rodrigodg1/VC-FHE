"""Build missing images remotely. No evaluation VM is created by this module."""
from decimal import Decimal
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request
import budget
import cloud_setup
import image
import image_recovery
import gcp
import topology

MAX_BUILD_SECONDS=7200
BUILD_USD_PER_MINUTE=Decimal('0.0624')
BUILD_PRICE_SOURCE='https://cloud.google.com/build/pricing?hl=en'

def docker_manifest(repository,tag):
    """Resolve the original PoC Besu tag to its Linux/amd64 content digest."""
    token=json.load(urllib.request.urlopen('https://auth.docker.io/token?service=registry.docker.io&scope=repository:'+repository+':pull',timeout=30))['token']
    def request(ref):
        req=urllib.request.Request('https://registry-1.docker.io/v2/'+repository+'/manifests/'+ref,
            headers={'Authorization':'Bearer '+token,'Accept':','.join([
                'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json',
                'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'])})
        with urllib.request.urlopen(req,timeout=30) as response:
            body=response.read();digest='sha256:'+hashlib.sha256(body).hexdigest()
            if response.headers.get('Docker-Content-Digest')!=digest:raise ValueError('registry manifest hash mismatch')
            return json.loads(body),digest
    manifest,digest=request(tag)
    if 'manifests' in manifest:
        selected=[v['digest'] for v in manifest['manifests'] if v.get('platform',{}).get('os')=='linux'
                  and v.get('platform',{}).get('architecture')=='amd64']
        if len(selected)!=1:raise ValueError('one Linux/amd64 Besu image required')
        _,digest=request(selected[0])
    return repository+'@'+digest

def specification(config,record,resources,besu,timeout_seconds=MAX_BUILD_SECONDS):
    if resources['region']!=topology.registry_region(config):raise ValueError('build registry region mismatch')
    repository=gcp.image_repository(config)
    if resources.get('project',config['project_id'])!=config['project_id'] or resources.get('repository',repository)!=repository:
        raise ValueError('build registry project or repository mismatch')
    prefix=resources['region']+'-docker.pkg.dev/'+config['project_id']+'/'+repository
    tag=prefix+'/campaign:'+topology.digest(record)[:16]
    besu_tag=prefix+'/besu:'+besu.split('@sha256:')[1][:16]
    # BuildKit is required by the original Dockerfile's Cargo cache mounts.
    # Cloud Build's Docker builder downloads the pinned Node/Rust base images.
    upstream={k:v for k,v in record.get('buildInputs',{}).items() if k.startswith('upstream/')}
    native=prefix+'/native-cache:'+topology.digest(upstream)[:16]
    cache_script=(f'if ! docker pull {native} >/tmp/native-cache.log 2>&1; then '
        'if grep -qiE "not found|manifest unknown|NAME_UNKNOWN" /tmp/native-cache.log; then '
        'echo "No previous native layer cache"; else cat /tmp/native-cache.log; exit 1; fi; fi\n'
        f'docker build --pull --platform=linux/amd64 --target=build --build-arg=BUILDKIT_INLINE_CACHE=1 --cache-from={native} -t {native} .\n'
        f'docker push {native}')
    steps=[{'id':'compile-or-reuse-pinned-native-fhe-kms','name':'gcr.io/cloud-builders/docker',
            'entrypoint':'bash','env':['DOCKER_BUILDKIT=1'],'args':['-ceu',cache_script]},
           {'id':'build-role-adapters','name':'gcr.io/cloud-builders/docker',
            'env':['DOCKER_BUILDKIT=1'],'args':['build','--pull','--platform=linux/amd64',
                '--build-arg=BUILDKIT_INLINE_CACHE=1','--cache-from='+native,'-t',tag,'.']},
           {'id':'download-pinned-besu','name':'gcr.io/cloud-builders/docker','args':['pull',besu]},
           {'id':'retain-besu-in-project-registry','name':'gcr.io/cloud-builders/docker','args':['tag',besu,besu_tag]}]
    return {'steps':steps,'images':[tag,besu_tag],'timeout':str(timeout_seconds)+'s','tags':['vcfhe-'+config['campaign']],
        'serviceAccount':resources['builderServiceAccount'],'logsBucket':resources['bucket'],
        'options':{'machineType':'E2_HIGHCPU_32','diskSizeGb':'100','logging':'GCS_ONLY'}},tag,besu_tag

def build(config,quote,directory,_recovering=False):
    cost=budget.assess(config,quote)
    if cost['status']!='admit':raise ValueError('complete campaign is not admitted within USD 50')
    minimum=BUILD_USD_PER_MINUTE*MAX_BUILD_SECONDS/60
    if budget.amount(quote['build_registry'])<minimum:
        raise ValueError('build_registry must include up to USD '+str(minimum)+' for the bounded native build, plus registry/storage charges')
    setup=cloud_setup.inspect(config,enable=True)
    directory=Path(directory).resolve()
    if not directory.exists():image.prepare(image.ROOT/'threshold-kms/.cache',directory)
    image_recovery.require_no_pending(directory)
    record=json.loads((directory/'distributed-source.json').read_text())
    image.verify_inputs(directory,record)
    if record['localSource']!=image.deployment.campaign_module().source_manifest():
        raise ValueError('Prepared image context has stale protocol sources. Use a new build directory.')
    image.verify_adapter_sources(record)
    resources=cloud_setup.ensure_build_resources(config,setup)
    receipt=directory/'published-image.json'
    # Reuse only this exact source-bound receipt and registry identity.
    if receipt.exists():
        published=json.loads(receipt.read_text())
        if published.get('sourceSha256')!=topology.digest(record):raise ValueError('existing image receipt belongs to different sources')
        missing=image_recovery.missing_images(config,published)
        if not missing:return published
        if _recovering:raise ValueError('Newly rebuilt image is unavailable. Inspect the build without repeating compilation.')
        image_recovery.require_success(published,topology.digest(record))
        history=cloud_setup.gcloud('builds','list','--region',resources['region'],'--project',config['project_id'],
                                  '--filter=tags:vcfhe-'+config['campaign'])
        image_recovery.no_active(history)
        work=directory/'gce-builder'
        if published.get('builder')=='temporary GCE VM' and not work.is_dir():
            raise ValueError('Prior GCE state is missing. Cannot establish safe backend replacement.')
        if work.exists():image_recovery.prove_gce_cleanup(config,work)
        image_recovery.archive(directory,['published-image.json','cloud-build-submission.json',
            'cloud-build-result.json','cloudbuild.json','cloud-build-upload','gce-builder'],missing)
        return build(config,quote,directory,_recovering=True)
    submission=directory/'cloud-build-submission.json'
    existing_submission=submission.exists()
    if (directory/'ambiguous-cloud-build-submission.json').exists():
        raise ValueError('A prior build submission has an unknown outcome. Inspect Cloud Build before any new paid submission.')
    if submission.exists():
        submitted=json.loads(submission.read_text())
        # An interrupted client must inspect the same remote build, never pay
        # for an automatic second compilation.
        build_id=submitted['id']
        completed=cloud_setup.gcloud('builds','describe',build_id,'--region',resources['region'],'--project',config['project_id'])
        if completed['status']!='SUCCESS':
            raise ValueError('Existing cloud build '+build_id+' has status '+completed['status']+'. Inspect it without resubmitting.')
        besu=submitted['besuSource']
        spec,tag,besu_tag=specification(config,record,resources,besu)
    else:
        history=cloud_setup.gcloud('builds','list','--region',resources['region'],'--project',config['project_id'],
                                  '--filter=tags:vcfhe-'+config['campaign'])
        image_recovery.no_active(history)
        spent_seconds=0
        for previous in history:
            if previous['status'] in ['QUEUED','WORKING','PENDING']:
                raise ValueError('A campaign build is already active. Inspect it instead of submitting another.')
            if previous.get('startTime') and previous.get('finishTime'):
                spent_seconds+=(datetime.fromisoformat(previous['finishTime'].replace('Z','+00:00'))-
                                datetime.fromisoformat(previous['startTime'].replace('Z','+00:00'))).total_seconds()
        # Bound all attempts together within the planned build allowance.
        # Registry storage retains its own USD 0.50 allowance.
        prior_gce=image_recovery.gce_reservations(config,image.HERE/'generated/build-cost-ledger.local.json')
        remaining=(budget.amount(quote['build_registry'])-Decimal('0.50')-prior_gce)/BUILD_USD_PER_MINUTE*60-Decimal(str(spent_seconds))
        timeout=max(0,min(MAX_BUILD_SECONDS,int(remaining)))
        if timeout<600:raise ValueError('Remaining cumulative build allowance is below ten minutes. No new paid build.')
        besu=docker_manifest('hyperledger/besu','25.3.0')
        spec,tag,besu_tag=specification(config,record,resources,besu,timeout)
        (directory/'cloudbuild.json').write_text(json.dumps(spec,indent=2)+'\n')
        # Recovery history and prior GCE state remain on the controller. Only
        # the exact public, source-bound closure is staged for submission.
        upload=image_recovery.prepare_upload(directory,record)
        try:
            submitted=cloud_setup.gcloud('builds','submit',upload,'--config',directory/'cloudbuild.json',
                '--region',resources['region'],'--project',config['project_id'],
                '--gcs-source-staging-dir',resources['bucket']+'/source','--ignore-file',upload/'.gcloudignore','--async','--quiet')
        except BaseException:
            (directory/'ambiguous-cloud-build-submission.json').write_text(json.dumps({'sourceSha256':topology.digest(record),
                'instruction':'Inspect Cloud Build before a manual retry. The API may have accepted the submission.'},indent=2)+'\n')
            raise
        submitted['besuSource']=besu
        submission.write_text(json.dumps(submitted,indent=2)+'\n')
        build_id=submitted['id']
        print('CLOUD BUILD '+build_id+' (bounded to '+str(timeout)+' seconds, no evaluation VMs)',flush=True)
        subprocess.run(['gcloud','builds','log',build_id,'--stream','--region',resources['region'],
                        '--project',config['project_id']],check=True)
        completed=cloud_setup.gcloud('builds','describe',build_id,'--region',resources['region'],'--project',config['project_id'])
    if completed['status']!='SUCCESS':raise ValueError('Native image build did not succeed. No evaluation launch.')
    image.verify_inputs(directory,record)
    images={entry['name']:entry['digest'] for entry in completed['results']['images']}
    for name in [tag,besu_tag]:
        if not re.fullmatch(r'sha256:[a-f0-9]{64}',images.get(name,'')):raise ValueError('completed build lacks immutable image identity')
    published={'digest':tag.rsplit(':',1)[0]+'@'+images[tag],
        'besuDigest':besu_tag.rsplit(':',1)[0]+'@'+images[besu_tag],
        'besuSource':besu,'sourceSha256':topology.digest(record),'budget':cost,
        'buildId':build_id,'buildRegion':resources['region'],'builder':'Google Cloud Build',
        'buildStatus':completed['status'],'buildPricingSource':BUILD_PRICE_SOURCE}
    missing=image_recovery.missing_images(config,published)
    if missing:
        # A SUCCESS response from an old submission may outlive deleted
        # registry objects. A newly completed submission is never retried here.
        if _recovering or not submission.exists():
            image_recovery.retain_result(directory,completed)
            raise ValueError('Completed build images are unavailable. Inspect retained results without retrying compilation.')
        # Only a submission that existed before this invocation can authorize
        # recovery, preventing an immediately missing new image from creating
        # a second paid attempt.
        if not existing_submission:
            image_recovery.retain_result(directory,completed)
            raise ValueError('Newly completed build images are unavailable. No automatic compilation retry.')
        history=cloud_setup.gcloud('builds','list','--region',resources['region'],'--project',config['project_id'],
                                  '--filter=tags:vcfhe-'+config['campaign'])
        image_recovery.no_active(history)
        image_recovery.archive(directory,['cloud-build-submission.json','cloud-build-result.json','cloudbuild.json','cloud-build-upload'],missing,
                               remoteSuccessfulBuild=completed)
        return build(config,quote,directory,_recovering=True)
    image_recovery.retain_result(directory,completed)
    receipt.write_text(json.dumps(published,indent=2)+'\n')
    return published
