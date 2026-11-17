"""Public certificate permissions never weaken private key permissions."""
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results.public_tls import prepare_certificates,readable_public_exchange


class PublicCertificateTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.cert=Path(cls.tmp.name)/'public.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
            '-keyout',str(Path(cls.tmp.name)/'private.pem'),'-out',str(cls.cert),
            '-days','1','-subj','/CN=synthetic-public-certificate.test'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.work=tempfile.TemporaryDirectory();self.addCleanup(self.work.cleanup)
        self.run=Path(self.work.name);self.source=self.run/'public-tls'
        for i in range(1,5):
            path=self.source/('PUB-p'+str(i))/'tls.pem';path.parent.mkdir(parents=True)
            shutil.copyfile(self.cert,path);path.chmod(0o600)
        self.private=self.run/'private-key.pem';self.private.write_text('synthetic private marker');self.private.chmod(0o600)
    def test_all_public_bytes_unchanged_and_private_key_stays_private(self):
        before={p:p.read_bytes() for p in self.source.rglob('tls.pem')}
        proof=prepare_certificates(self.source)
        self.assertEqual(len(proof),4)
        for p,data in before.items():
            self.assertEqual(p.read_bytes(),data);self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o644)
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode),0o600)
    def test_extra_private_material_refused_before_any_chmod(self):
        (self.source/'secret.key').write_text('not transferable')
        with self.assertRaises(ValueError):prepare_certificates(self.source)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in self.source.rglob('tls.pem')))
    def test_symlink_refused(self):
        p=self.source/'PUB-p1/tls.pem';p.unlink();p.symlink_to(self.cert)
        with self.assertRaises(ValueError):prepare_certificates(self.source)
    def test_private_key_in_expected_filename_refused(self):
        (self.source/'PUB-p1/tls.pem').write_text('-----BEGIN '+'PRIVATE KEY'+'-----\nsynthetic\n-----END '+'PRIVATE KEY'+'-----\n')
        with self.assertRaises(ValueError):prepare_certificates(self.source)
    def test_only_original_four_public_uploads_are_wrapped_and_restored(self):
        calls=[]
        remotes={};nodes={}
        for i in range(1,5):
            host='host-'+str(i)
            def upload(source,dest,_host=host):
                calls.append((_host,str(source),dest))
                if Path(source)==self.source:
                    # Check the actual TAR header mode used by Remote.upload.
                    import tarfile
                    for p in self.source.rglob('tls.pem'):
                        with tarfile.open(self.run/('test-'+_host+'.tar'),'w') as tar:
                            tar.add(p,arcname=p.name)
                        with tarfile.open(self.run/('test-'+_host+'.tar')) as tar:
                            self.assertTrue(tar.getmembers()[0].mode&0o004)
            remotes[host]=SimpleNamespace(upload=upload)
            nodes['kms-'+str(i)]={'host':host,'role':'kms'}
        roots=lambda name:'/synthetic/'+name
        campaign=SimpleNamespace(run=self.run,remotes=remotes,nodes=nodes,root=roots)
        original={k:v.upload for k,v in remotes.items()}
        with readable_public_exchange(campaign):
            remotes['host-1'].upload(self.private,'/unrelated')
            for i in range(1,5):remotes['host-'+str(i)].upload(self.source,roots('kms-'+str(i))+'/public')
        self.assertEqual(len(calls),5)
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode),0o600)
        self.assertTrue(all(v.upload is original[k] for k,v in remotes.items()))
        import json
        proof=json.loads((self.run/'distributed/public-tls-transfer.json').read_text())
        self.assertEqual(proof['status'],'passed');self.assertEqual(proof['protocolRequestsRepeated'],0)
    def test_other_role_destination_refused_and_original_methods_restored(self):
        calls=[];remote=SimpleNamespace(upload=lambda *args:calls.append(args));original=remote.upload
        campaign=SimpleNamespace(run=self.run,remotes={'host-1':remote},nodes={'kms-1':{'host':'host-1','role':'kms'}},root=lambda name:'/synthetic/'+name)
        with self.assertRaises(ValueError):
            with readable_public_exchange(campaign):remote.upload(self.source,'/synthetic/owner-1/public')
        self.assertIs(remote.upload,original);self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
