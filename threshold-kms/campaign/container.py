#!/usr/bin/env python3
"""Container entry points. Private volumes are never copied to evidence."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def call(args): subprocess.run(args,check=True)
def atomic(path,value):
    path=Path(path); temp=path.with_suffix('.pending')
    with temp.open('x') as f:
        json.dump(value,f); f.flush(); os.fsync(f.fileno())
    temp.replace(path)

def core():
    party=os.environ['VCFHE_PARTY']; private=Path('/private'); public=Path('/public')/('PUB-p'+party)
    private.mkdir(exist_ok=True);public.mkdir(exist_ok=True)
    marker=private/'initialized'
    if not marker.exists():
        call(['kms-gen-keys','--mock-enclave','--public-storage','file','--public-file-path','/public',
              '--public-file-prefix','PUB-p'+party,'--private-storage','file','--private-file-path','/private',
              '--private-file-prefix','PRIV-p'+party,'--cmd','signing-keys','threshold',
              '--signing-key-party-id',party,'--tls-subject','kms'+party])
        call(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
              '-keyout','/private/tls-key.pem','-out',str(public/'tls.pem'),'-days','30',
              '-subj','/CN=kms'+party,'-addext','subjectAltName=DNS:kms'+party,
              '-addext','basicConstraints=critical,CA:FALSE',
              '-addext','keyUsage=critical,digitalSignature',
              '-addext','extendedKeyUsage=serverAuth,clientAuth'])
        os.chmod('/private/tls-key.pem',0o600)
        marker.write_text('random signing identity; no pregenerated FHE key\n')
    deadline=time.monotonic()+300
    while not all((Path('/public')/f'PUB-p{i}'/'tls.pem').exists() for i in range(1,5)):
        if time.monotonic()>deadline:raise RuntimeError('peer certificates unavailable')
        time.sleep(1)
    os.execvp('kms-server',['kms-server','--config-file','/config/core-'+party+'.toml'])

mode=sys.argv[1]
if mode=='core':core()
elif mode=='public-store':
    os.chdir('/public')
    http.server.ThreadingHTTPServer(('0.0.0.0',8080),http.server.SimpleHTTPRequestHandler).serve_forever()
elif mode=='init':
    started=time.monotonic()
    call(['kms-init','-a',*[f'http://kms{i}:50100' for i in range(1,5)]])
    atomic('/keyset/prss.json',{'seconds':time.monotonic()-started,'livePRSS':True})
elif mode=='setup':os.execvp('kms-campaign',['kms-campaign','tops_campaign_setup','--exact','--nocapture','--test-threads=1'])
elif mode=='recipient':os.execvp('kms-campaign',['kms-campaign','tops_campaign_recipient','--exact','--nocapture','--test-threads=1'])
elif mode=='owner':os.execvp('node',['node','/app/threshold-kms/campaign/owner.mjs'])
elif mode=='worker':os.execvp('node',['node','/app/threshold-kms/campaign/worker.mjs'])
elif mode=='evaluate':os.execvp('node',['node','/app/threshold-kms/campaign/evaluate.mjs'])
elif mode=='identities':os.execvp('node',['node','/app/threshold-kms/campaign/identities.mjs'])
elif mode=='policy-init':os.execvp('node',['node','/app/threshold-kms/campaign/policy-init.mjs'])
else:raise SystemExit('unknown container role')
