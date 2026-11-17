import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import prepare_patch

HERE=Path(__file__).resolve().parent

class PublicKeysetProposalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.keyset=self.root/'keyset';self.keyset.mkdir()
        for name in ['ready.json','prss.json','encryption-key.bin','evaluation-key.bin']:(self.keyset/name).write_text('public fixture '+name)
        private=self.keyset/'CLIENT/SigningKey';private.mkdir(parents=True);(private/'do-not-export').write_text('private fixture, never inspected')
        for i in range(1,5):
            directory=self.keyset/f'PUB-p{i}'/'VerfKey';directory.mkdir(parents=True);(directory/('a'*64)).write_text('public verification fixture')

    def select(self):
        # Execute the exact remote script extracted from the candidate launch.
        source=prepare_patch.render()[1]
        tree=ast.parse(source)
        script=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PUBLIC_KEYSET_EXPORT_SCRIPT' for t in n.targets))
        return subprocess.run([sys.executable,'-c',script,str(self.keyset)],capture_output=True,text=True,timeout=5)

    def test_actual_filter_exports_public_files_and_never_reads_or_copies_client(self):
        client=self.keyset/'CLIENT';before={p.relative_to(client).as_posix():p.read_bytes() for p in client.rglob('*') if p.is_file()}
        selected=self.select();self.assertEqual(selected.returncode,0,selected.stderr);names=json.loads(selected.stdout)
        destination=self.root/'export'
        for name in names:
            target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(self.root/name,target)
        self.assertEqual(len(names),8);self.assertFalse((destination/'keyset/CLIENT').exists())
        self.assertEqual({p.relative_to(client).as_posix():p.read_bytes() for p in client.rglob('*') if p.is_file()},before)
        for name in names:self.assertEqual((destination/name).read_bytes(),(self.root/name).read_bytes())

    def test_optional_public_descriptors_and_certificates_are_retained(self):
        for name in ['keyset.json','keyset_descriptor.json']:(self.keyset/name).write_text('{}')
        (self.keyset/'PUB-p1/tls.pem').write_text('public certificate fixture')
        result=self.select();self.assertEqual(result.returncode,0,result.stderr)
        names=json.loads(result.stdout)
        self.assertIn('keyset/keyset_descriptor.json',names);self.assertIn('keyset/PUB-p1/tls.pem',names)

    def test_unknown_or_private_roots_are_rejected(self):
        for name in ['unknown.json','private','PRIV-p1','identity']:
            p=self.keyset/name;p.write_text('must reject')
            self.assertNotEqual(self.select().returncode,0,name);p.unlink()

    def test_unknown_or_private_public_store_categories_are_rejected(self):
        for name in ['SigningKey','SecretKey','CLIENT','unknown']:
            p=self.keyset/'PUB-p1'/name;p.mkdir();(p/('b'*64)).write_text('must reject')
            self.assertNotEqual(self.select().returncode,0,name);shutil.rmtree(p)

    def test_symlinks_at_all_export_levels_are_rejected(self):
        target=self.root/'outside';target.write_text('outside fixture')
        for name in ['unknown','ready.json','PUB-p1','PUB-p1/VerfKey',f'PUB-p1/VerfKey/{"a"*64}']:
            p=self.keyset/name
            backup=p.with_name(p.name+'.saved')
            if p.exists():p.rename(backup)
            p.symlink_to(target)
            self.assertNotEqual(self.select().returncode,0,name)
            p.unlink()
            if backup.exists():backup.rename(p)

    def test_missing_required_or_malformed_public_objects_are_rejected(self):
        p=self.keyset/'ready.json';p.unlink();self.assertNotEqual(self.select().returncode,0);p.write_text('{}')
        p=self.keyset/'PUB-p1/VerfKey/secret.key';p.write_text('must reject');self.assertNotEqual(self.select().returncode,0)

    def test_patch_only_changes_controller_selection_and_remains_unapplied(self):
        original,candidate,patch=prepare_patch.render();record=json.loads((HERE/'proposal.json').read_text())
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),record['sourceSha256'])
        self.assertEqual(hashlib.sha256(candidate.encode()).hexdigest(),record['candidateSha256'])
        self.assertEqual((HERE/'proposal.patch').read_text(),patch)
        (self.root/'VC-FHE/distributed').mkdir(parents=True)
        target=self.root/'VC-FHE/distributed/launch.py';target.write_text(original)
        subprocess.run(['patch','--batch','-p1','-d',str(self.root),'-i',str(HERE/'proposal.patch')],check=True,capture_output=True,timeout=5)
        self.assertEqual(target.read_text(),candidate);ast.parse(candidate)
        self.assertEqual(prepare_patch.SOURCE.read_text(),original)
        self.assertNotIn("['keyset'],self.run/'setup-public'",candidate)

if __name__=='__main__':unittest.main(verbosity=2)
