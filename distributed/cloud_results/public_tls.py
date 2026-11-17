"""Transfer public KMS certificates readably before original core initialization.

The original uploader extracts as root before changing ownership. A private
controller umask can otherwise give its public certificates mode 0600, allowing
cores to observe a present but unreadable certificate during that interval.
Only the four public certificates are changed. Private key modes remain intact.
"""
from contextlib import contextmanager
from pathlib import Path
import ssl
import threading

from cloud_results.common import require, sha, write


def prepare_certificates(source):
    source=Path(source)
    require(source.is_dir() and not source.is_symlink(), 'Missing public TLS exchange')
    expected={Path('PUB-p'+str(i))/'tls.pem' for i in range(1,5)}
    files={p.relative_to(source) for p in source.rglob('*') if p.is_file()}
    require(files==expected and not any(p.is_symlink() for p in source.rglob('*')),
            'Public TLS exchange contains unexpected or linked material')
    result=[]
    # Validate the complete selection before modifying any permission.
    for name in sorted(expected):
        path=source/name
        data=path.read_text()
        require(data.count('-----BEGIN CERTIFICATE-----')==1
                and data.count('-----END CERTIFICATE-----')==1 and 'PRIVATE KEY' not in data,
                'Only one public certificate per KMS party is allowed')
        ssl.PEM_cert_to_DER_cert(data)
        result.append({'name':name.as_posix(), 'sha256':sha(path)})
    for row in result:
        path=source/row['name']
        path.chmod(0o644)
        require(sha(path)==row['sha256'], 'Public certificate bytes changed')
    return result


@contextmanager
def readable_public_exchange(campaign):
    """Keep the original KMS sequence and wrap only its public TLS uploads."""
    source=(campaign.run/'public-tls').resolve()
    originals=[]
    seen={}
    lock=threading.Lock()
    for host,remote in campaign.remotes.items():
        original=remote.upload
        originals.append((remote,original))
        def upload(path,destination,*,_remote=remote,_original=original,_host=host):
            if Path(path).resolve()!=source:
                return _original(path,destination)
            targets=[name for name,node in campaign.nodes.items()
                     if node['host']==_host and node['role']=='kms'
                     and destination==campaign.root(name)+'/public']
            require(len(targets)==1, 'Public TLS upload targets another role')
            # Original kms() calls four uploads concurrently. Serialize the
            # local chmod and inventory only, without serializing transport.
            with lock:
                certificates=prepare_certificates(source)
            result=_original(path,destination)
            with lock:
                require(_host not in seen, 'Public TLS exchange was repeated')
                seen[_host]={'certificates':certificates,'publicMode':'0644'}
                write(campaign.run/'distributed/public-tls-transfer.json',{
                    'schema':'readable-public-kms-certificates-v1',
                    'status':'passed' if len(seen)==4 else 'in-progress',
                    'hosts':dict(seen),'privateKeyModesChanged':False,
                    'originalKmsSequenceUsed':True,'protocolRequestsRepeated':0})
            return result
        remote.upload=upload
    try:
        yield
    finally:
        for remote,original in originals:
            remote.upload=original
