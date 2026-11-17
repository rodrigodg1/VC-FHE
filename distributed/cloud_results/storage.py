"""Generation-bound private object storage. No evaluator or KMS calls."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import urllib.parse
import urllib.request
from cloud_results.common import require, sha


class Store:
    def __init__(self, bucket, project):
        require(bucket.startswith('vcfhe-evidence-') and bucket[15:].isalnum(), 'Invalid private evidence bucket')
        self.bucket, self.project = bucket, project
    def token(self):
        return subprocess.check_output(['gcloud','auth','print-access-token','--project',self.project],text=True).strip()
    def connection(self):
        return http.client.HTTPSConnection('storage.googleapis.com',timeout=180,context=ssl.create_default_context())
    def api(self, path, method='GET', body=None):
        req=urllib.request.Request('https://storage.googleapis.com/storage/v1/b/'+self.bucket+path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization':'Bearer '+self.token(),'Content-Type':'application/json'},method=method)
        with urllib.request.urlopen(req,timeout=60) as response:return json.load(response)
    def metadata(self, name, generation=None):
        path='/o/'+urllib.parse.quote(name,safe='')
        if generation is not None:path+='?generation='+str(generation)
        value=self.api(path)
        require(value.get('bucket')==self.bucket and value.get('name')==name
                and str(value.get('generation','')).isdecimal(), 'Object identity differs')
        if generation is not None:require(value['generation']==str(generation),'Object generation differs')
        return value
    def upload(self, path, name):
        path=Path(path);checksum=hashlib.md5()
        with path.open('rb') as stream:
            for data in iter(lambda:stream.read(1024**2),b''):checksum.update(data)
        md5=base64.b64encode(checksum.digest()).decode();expected=sha(path)
        c=self.connection()
        try:
            c.putrequest('PUT','/'+self.bucket+'/'+urllib.parse.quote(name,safe='/'))
            for key,value in {'Authorization':'Bearer '+self.token(),'Content-Length':str(path.stat().st_size),
                'Content-Type':'application/octet-stream','Content-MD5':md5,'Cache-Control':'no-store',
                'x-goog-if-generation-match':'0','x-goog-meta-vcfhe-sha256':expected}.items():c.putheader(key,value)
            c.endheaders()
            with path.open('rb') as stream:
                for data in iter(lambda:stream.read(1024**2),b''):c.send(data)
            response=c.getresponse();response.read()
            require(response.status in (200,201),'Create-only object upload failed, HTTP '+str(response.status))
        finally:c.close()
        meta=self.metadata(name)
        result={'bucket':self.bucket,'object':name,'generation':meta['generation'],
            'bytes':path.stat().st_size,'sha256':expected,'md5Hash':md5}
        self.verify(result)
        return result
    def verify(self, receipt):
        require(receipt['bucket']==self.bucket,'Foreign object receipt')
        meta=self.metadata(receipt['object'],receipt['generation'])
        require(int(meta['size'])==receipt['bytes'] and meta['md5Hash']==receipt['md5Hash']
                and meta.get('metadata',{}).get('vcfhe-sha256')==receipt['sha256'], 'Cloud object checksum or size differs')
        return meta
    def download(self, receipt, destination, *, maximum=None):
        meta=self.verify(receipt)
        require(maximum is None or int(meta['size'])<=maximum,'Refuse oversized local result download')
        path=Path(destination);require(not path.exists() and not path.is_symlink(),'Download destination exists')
        c=self.connection();checksum=hashlib.sha256();count=0
        try:
            target='/storage/v1/b/'+self.bucket+'/o/'+urllib.parse.quote(receipt['object'],safe='')
            target+='?alt=media&generation='+receipt['generation']
            c.request('GET',target,headers={'Authorization':'Bearer '+self.token()})
            response=c.getresponse();require(response.status==200,'Exact-generation object read failed')
            with path.open('xb') as out:
                import os
                os.fchmod(out.fileno(),0o600)
                while True:
                    data=response.read(1024**2)
                    if not data:break
                    count+=len(data);require(count<=receipt['bytes'],'Object body exceeds its verified length')
                    out.write(data);checksum.update(data)
                out.flush();os.fsync(out.fileno())
        finally:c.close()
        require(count==receipt['bytes'] and checksum.hexdigest()==receipt['sha256'],'Object readback mismatch')
        return path
