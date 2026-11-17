"""Public witness acquisition is complete without copying owner secrets."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloud_results.owner_materials import public_paths, collect


class PublicOwnerMaterialTests(unittest.TestCase):
    def app(self, **change):
        case = dict(name='regional_qoe_compliance-0', half='nonlinear', n=50)
        case.update(change)
        return dict(status='passed', cases=[case])
    def test_nonlinear_selects_only_approved_context(self):
        self.assertEqual(public_paths(self.app()), ['owner/regional_qoe_compliance-0/approved-context.json'])
    def test_linear_selects_coordinates_and_every_ciphertext(self):
        paths=public_paths(self.app(name='linear-10-0',half='linear',n=10))
        self.assertEqual(len(paths),11)
        self.assertEqual(paths[0],'owner/linear-10-0/coordinates.json')
        self.assertEqual(paths[-1],'owner/linear-10-0/input-9.bin')
        self.assertNotIn('owner',paths)
    def test_unsafe_names_and_invalid_sizes_refused(self):
        for change in ({'name':'../escape'},{'name':'a/b'},{'name':'a\\b'},{'half':'kms'},{'n':1000000},{'n':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):public_paths(self.app(**change))
    def test_failed_or_duplicate_reports_refused(self):
        app=self.app();app['status']='failed'
        with self.assertRaises(ValueError):public_paths(app)
        app=self.app();app['cases']*=2
        with self.assertRaises(ValueError):public_paths(app)
    def test_reads_existing_files_once_and_preserves_private_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp);calls=[]
            def download(root,names,dest):
                calls.append((root,list(names)))
                for name in names:
                    p=dest/name;p.parent.mkdir(parents=True,exist_ok=True)
                    with p.open('x') as stream:json.dump(self.app() if name=='reports/application.json' else {'context':'synthetic'},stream)
            remote=SimpleNamespace(download=download)
            campaign=SimpleNamespace(run=run,remote=lambda _:remote,root=lambda n:'/synthetic/'+n)
            proof=collect(campaign)
            self.assertEqual(len(calls),2)
            self.assertEqual(calls[1][1],['owner/regional_qoe_compliance-0/approved-context.json'])
            self.assertFalse(proof['privateOwnerDirectoryCopied']);self.assertEqual(proof['protocolRequestsRepeated'],0)
            with self.assertRaises(ValueError):collect(campaign)

    def test_full_controller_keeps_original_validation_and_preservation(self):
        from cloud_results.worker import CloudCampaign
        import launch
        calls=[]
        instance=object.__new__(CloudCampaign)
        with patch('cloud_results.owner_materials.collect',side_effect=lambda c:calls.append('public-witnesses')), \
             patch.object(launch.Campaign,'collect',side_effect=lambda:calls.append('original-collector')), \
             patch('cloud_results.worker.preserve_hosts',side_effect=lambda c:calls.append('private-preservation')):
            instance.collect()
        self.assertEqual(calls,['public-witnesses','original-collector','private-preservation'])

if __name__=='__main__':unittest.main()
