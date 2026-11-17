from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from cloud_results import reliability, source_cache


class SourceCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base/'source'
        self.source.mkdir()
        (self.source/'complete.json').write_text('{"synthetic": true}')
        (self.source/'code').mkdir()
        (self.source/'code/input').write_bytes(b'original public source')
        self.target = self.base/'restored'

    def test_copy_once_then_verify_without_writing(self):
        self.assertEqual(source_cache.restore(self.source, self.target)['status'], 'verified-copy')
        before = {p: p.stat().st_mtime_ns for p in self.target.rglob('*')}
        with patch.object(source_cache.shutil, 'copytree', side_effect=AssertionError('must reuse')):
            self.assertEqual(source_cache.restore(self.source, self.target)['status'], 'verified-reuse')
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in self.target.rglob('*')})

    def test_changed_cache_is_preserved_and_refused(self):
        source_cache.restore(self.source, self.target)
        (self.target/'code/input').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'differs'):
            source_cache.restore(self.source, self.target)
        self.assertEqual((self.target/'code/input').read_bytes(), b'changed')

    def test_missing_and_extra_content_cannot_count_as_complete(self):
        source_cache.restore(self.source, self.target)
        (self.target/'code/input').unlink()
        with self.assertRaisesRegex(ValueError, 'differs'):
            source_cache.restore(self.source, self.target)
        (self.target/'code/input').write_bytes(b'original public source')
        (self.target/'unexpected').write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'differs'):
            source_cache.restore(self.source, self.target)
        self.assertTrue((self.target/'unexpected').exists())

    def test_links_and_missing_completion_marker_are_refused(self):
        self.target.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'real directory'):
            source_cache.restore(self.source, self.target)
        (self.source/'linked').symlink_to(self.source/'code/input')
        with self.assertRaisesRegex(ValueError, 'Linked'):
            source_cache.inventory(self.source)
        (self.source/'linked').unlink()
        (self.source/'complete.json').unlink()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            source_cache.inventory(self.source)


class OfflineGateTests(unittest.TestCase):
    def fixture(self, root):
        for folder in reliability.SUITES:
            path = root/folder
            path.mkdir(parents=True)
            (path/'test_synthetic.py').write_text('# synthetic')
        (root/'tests/synthetic.test.mjs').write_text('// synthetic')

    def test_gate_includes_both_recovery_suites_in_separate_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.fixture(root)
            with patch.object(reliability.subprocess,'run') as execute:
                result=reliability.run(root)
            self.assertEqual(execute.call_count,4)
            self.assertIn('maintenance/completed-prefix-recovery',result['suites'])
            self.assertIn('maintenance/workflow-recovery',result['suites'])
            self.assertFalse(result['cloudExecutionValidated'])
            self.assertEqual(result['protocolOperations'],0)
            self.assertEqual(len(result['testSources']),4)
            for call in execute.call_args_list:
                self.assertTrue(call.kwargs['check'])
                self.assertEqual(call.kwargs['timeout'],600)

    def test_failure_does_not_produce_passing_receipt_or_continue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.fixture(root)
            with patch.object(reliability.subprocess,'run',side_effect=[None,subprocess.CalledProcessError(1,['synthetic'])]) as execute:
                with self.assertRaises(subprocess.CalledProcessError):reliability.run(root)
                self.assertEqual(execute.call_count,2)

    def test_missing_suite_cannot_be_silently_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'suite missing'):
                reliability.commands(Path(tmp))

    def test_concurrent_source_edit_prevents_passing_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.fixture(root)
            def mutate(*args,**kwargs):
                (root/'tests/test_synthetic.py').write_text('# changed during checks')
            with patch.object(reliability.subprocess,'run',side_effect=mutate):
                with self.assertRaisesRegex(ValueError,'Sources changed'):
                    reliability.run(root)


if __name__ == '__main__':unittest.main()
