from pathlib import Path
import importlib.util
import copy
import unittest

spec=importlib.util.spec_from_file_location('keyset_mount_repair',Path(__file__).with_name('public_keyset_mounts.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class KeysetMounts(unittest.TestCase):
    def test_public_material_has_own_writable_copy(self):
        original={'services':{'operator-1':{'read_only':True,'volumes':[
            {'source':'/original/public','target':'/keyset','read_only':True},
            {'source':'/original/identity','target':'/identity','read_only':True}]},
            'kms-1-core':{'volumes':[{'source':'/original/vault','target':'/private','read_only':False},
                {'source':'/original/pinned','target':'/release-keyset','read_only':True}]}}}
        before=copy.deepcopy(original);result=m.restore(original,'/new')
        self.assertEqual(original,before)
        self.assertEqual(result['services']['operator-1']['volumes'][0],
            {'source':'/new/operator-1/keyset','target':'/keyset','read_only':False})
        self.assertTrue(result['services']['operator-1']['read_only'])
        self.assertEqual(result['services']['operator-1']['volumes'][1],before['services']['operator-1']['volumes'][1])
        self.assertEqual(result['services']['kms-1-core'],before['services']['kms-1-core'])

if __name__=='__main__':unittest.main()
