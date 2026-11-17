"""Synthetic offline tests only. No actual private run contents are opened."""
import gzip
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
import compressed_backup as proposal


def tar_bytes(host=None, extra=(), evidence=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        directory = tarfile.TarInfo('.'); directory.type = tarfile.DIRTYPE
        directory.mode = 0o700; directory.uid = 10001; directory.gid = 10001
        directory.mtime = 123456789; tar.addfile(directory)
        entries = ([('launch-state.json', b'{"status":"failed"}'),
                    ('reports/public.json', b'{"measured":true}')]
                   if evidence else [('scope.txt', ('synthetic-smoke/'+host+'\n').encode()),
                                     ('synthetic-smoke/private/synthetic-key', b'NOT A REAL KEY\x00\x01'),
                                     ('synthetic-smoke/fixtures/ciphertext.bin', bytes(range(256))*128)])
        for name, data in [*entries, *extra]:
            item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o600
            item.uid = 10001; item.gid = 10001; item.mtime = 123456789
            tar.addfile(item, io.BytesIO(data))
    return buffer.getvalue()


class CompressedBackupProposalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vcfhe-compressed-proposal-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); os.chmod(self.root, 0o700)

    def write(self, name, data):
        path = self.root/name; path.write_bytes(data); os.chmod(path, 0o600)
        return path

    def archive(self, name, raw, **kwargs):
        path = self.root/name
        info = proposal.compress_stream(io.BytesIO(raw), path, maximum_bytes=1024*1024, **kwargs)
        return path, info

    def test_lossless_roundtrip_sha_inventory_crc_and_modes(self):
        raw = tar_bytes('host-1')
        path, info = self.archive('host-1-private-state.tar.gz', raw,
                                  campaign='synthetic-smoke', host='host-1')
        self.assertEqual(gzip.decompress(path.read_bytes()), raw)
        self.assertEqual(info['uncompressedTarSha256'], proposal.hashlib.sha256(raw).hexdigest())
        self.assertEqual(info['uncompressedTarBytes'], len(raw))
        self.assertTrue(info['crcVerified']); self.assertTrue(info['singleGzipMember'])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertTrue(all(row['mode'] == (0o600 if row['kind'] == 'file' else 0o700)
                            for row in info['metadata']))
        self.assertTrue(all(row['uid'] == row['gid'] == 10001 for row in info['metadata']))
        self.assertFalse((self.root/'backup.local.json').exists())

    def test_unsafe_absolute_parent_foreign_and_normalized_duplicate_refused(self):
        for i, name in enumerate(('/absolute', '../escape', 'foreign/file', './scope.txt')):
            with self.subTest(name=name):
                raw = tar_bytes('host-1', [(name, b'bad')])
                path = self.write('unsafe'+str(i)+'.gz', gzip.compress(raw, mtime=0))
                with self.assertRaises(ValueError):
                    proposal.inspect_archive(path, campaign='synthetic-smoke', host='host-1')

    def test_links_and_special_members_refused(self):
        for i, kind in enumerate((tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                                  tarfile.FIFOTYPE)):
            with self.subTest(kind=kind):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w') as tar:
                    item = tarfile.TarInfo('scope.txt'); item.type = kind; item.linkname = 'elsewhere'
                    tar.addfile(item)
                path = self.write('special'+str(i)+'.gz', gzip.compress(buffer.getvalue(), mtime=0))
                with self.assertRaises(ValueError):
                    proposal.inspect_archive(path, campaign='synthetic-smoke', host='host-1')

    def test_wrong_host_or_missing_marker_refused(self):
        path = self.write('host.gz', gzip.compress(tar_bytes('host-2'), mtime=0))
        with self.assertRaisesRegex(ValueError, 'scope marker'):
            proposal.inspect_archive(path, campaign='synthetic-smoke', host='host-1')
        path = self.write('no-marker.gz', gzip.compress(tar_bytes(evidence=True), mtime=0))
        with self.assertRaises(ValueError):
            proposal.inspect_archive(path, campaign='synthetic-smoke', host='host-1')

    def test_truncated_gzip_crc_corruption_and_trailing_members_refused(self):
        encoded = gzip.compress(tar_bytes('host-1'), mtime=0)
        damaged = bytearray(encoded); damaged[-8] ^= 1
        for i, content in enumerate((encoded[:-1], encoded[:-8], bytes(damaged),
                                     encoded+b'garbage', encoded+gzip.compress(b'\0'*1024))):
            with self.subTest(i=i):
                path = self.write('damaged'+str(i)+'.gz', content)
                with self.assertRaises(ValueError):
                    proposal.inspect_archive(path, campaign='synthetic-smoke', host='host-1')

    def test_tar_truncation_and_hidden_data_after_end_refused(self):
        raw = tar_bytes('host-1')
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            last = tar.getmembers()[-1]
            end = last.offset_data+((last.size+511)//512)*512
        for i, content in enumerate((raw[:end+512], raw+b'HIDDEN'+b'\0'*2048)):
            with self.subTest(i=i):
                path = self.write('bad-tar'+str(i)+'.gz', gzip.compress(content, mtime=0))
                with self.assertRaises(ValueError):
                    proposal.inspect_archive(path, campaign='synthetic-smoke', host='host-1')

    def test_byte_allowance_failure_never_creates_receipt_or_replaces_data(self):
        path = self.root/'limited.gz'
        with self.assertRaisesRegex(ValueError, 'byte allowance'):
            proposal.compress_stream(io.BytesIO(tar_bytes('host-1')), path, maximum_bytes=20,
                                      campaign='synthetic-smoke', host='host-1')
        self.assertLessEqual(path.stat().st_size, 20)
        self.assertFalse((self.root/'compressed-recovery.local.json').exists())
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            proposal.compress_stream(io.BytesIO(tar_bytes('host-1')), path, maximum_bytes=10000)
        self.assertEqual(path.read_bytes(), original)

    def bundle(self):
        plan = {'campaign':'synthetic-smoke', 'run':'ORIGINAL IMMUTABLE RUN IDENTITY',
                'configSha256':'a'*64, 'terraformStateSha256':'b'*64,
                'hosts':[{'id':h} for h in sorted(proposal.HOSTS)]}
        quiet = {**{k:v for k,v in plan.items() if k != 'hosts'}, 'hosts':{}}
        binding = {**plan, 'schema':'vcfhe-compressed-recovery-binding-v1', 'hosts':{},
                   'frozenCleanupSourceSha256':'c'*64, 'originalSourceClosureSha256':'d'*64}
        for host in sorted(proposal.HOSTS):
            _, info = self.archive(host+'-private-state.tar.gz', tar_bytes(host),
                                    campaign='synthetic-smoke', host=host)
            expected = {k:info[k] for k in ('uncompressedTarSha256','uncompressedTarBytes','files')}
            binding['hosts'][host] = expected
            quiet['hosts'][host] = {'scope':'synthetic-smoke/'+host, 'runningContainers':[],
                'samplerRunning':False, 'snapshotAfterStopAndSync':True,
                'inventorySha256':proposal.digest(expected['files'])}
        _, evidence = self.archive('original-run-evidence.tar.gz', tar_bytes(evidence=True))
        binding['evidence'] = {k:evidence[k] for k in ('uncompressedTarSha256','uncompressedTarBytes','files')}
        plan_path = self.write('plan.local.json', json.dumps(plan).encode())
        quiet_path = self.write('quiescence.local.json', json.dumps(quiet).encode())
        binding.update(planSha256=proposal.sha(plan_path), quiescenceSha256=proposal.sha(quiet_path))
        path = self.write('original-binding.local.json', json.dumps(binding).encode())
        return binding, proposal.sha(path)

    def test_four_host_receipt_is_separate_truthful_and_not_cleanup_authorization(self):
        _, binding_sha = self.bundle()
        value = proposal.write_receipt(self.root, binding_sha)
        self.assertEqual(value['status'], 'verified-compressed-recovery')
        self.assertEqual(set(value['archives']), proposal.HOSTS)
        self.assertFalse(value['cleanupAuthorized'])
        self.assertFalse(value['originalBackupVerifierPassed'])
        self.assertFalse(value['originalBackupStatusChanged'])
        self.assertFalse((self.root/'backup.local.json').exists())
        self.assertEqual(proposal.verify_contents(self.root,binding_sha)['archives'], value['archives'])
        with self.assertRaises(FileExistsError):
            proposal.write_receipt(self.root,binding_sha)

    def test_changed_missing_host_inventory_or_quiescence_refused(self):
        binding, original_sha = self.bundle()
        path = self.root/'original-binding.local.json'
        binding['hosts']['host-1']['files'][0]['bytes'] += 1
        path.write_text(json.dumps(binding))
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            proposal.verify_contents(self.root, original_sha)
        with self.assertRaisesRegex(ValueError, 'stopped-state'):
            proposal.verify_contents(self.root, proposal.sha(path))
        self.assertFalse((self.root/'compressed-recovery.local.json').exists())

    def test_missing_host_archive_refused_without_receipt(self):
        _, binding_sha = self.bundle()
        (self.root/'host-4-private-state.tar.gz').unlink()
        with self.assertRaises(ValueError):
            proposal.verify_contents(self.root,binding_sha)
        self.assertFalse((self.root/'compressed-recovery.local.json').exists())

    def test_quiescence_semantics_refused_even_with_updated_hashes(self):
        binding, _ = self.bundle()
        quiet_path = self.root/'quiescence.local.json'
        quiet = json.loads(quiet_path.read_text())
        quiet['hosts']['host-1']['runningContainers'] = ['synthetic-still-running']
        quiet_path.write_text(json.dumps(quiet))
        binding['quiescenceSha256'] = proposal.sha(quiet_path)
        path = self.root/'original-binding.local.json'; path.write_text(json.dumps(binding))
        with self.assertRaisesRegex(ValueError,'stopped-state'):
            proposal.verify_contents(self.root,proposal.sha(path))

    def test_unknown_bundle_file_refused(self):
        _, binding_sha = self.bundle()
        self.write('unexpected-file',b'synthetic')
        with self.assertRaisesRegex(ValueError,'Unknown file'):
            proposal.verify_contents(self.root,binding_sha)

    def test_decompression_cannot_exceed_frozen_raw_size(self):
        raw = tar_bytes('host-1')
        path = self.write('too-large.gz',gzip.compress(raw,mtime=0))
        with self.assertRaisesRegex(ValueError,'byte allowance'):
            proposal.inspect_archive(path,campaign='synthetic-smoke',host='host-1',
                                      maximum_uncompressed_bytes=len(raw)-1)

    def test_private_modes_symlinks_and_unknown_files_refused(self):
        path, _ = self.archive('one.gz', tar_bytes('host-1'), campaign='synthetic-smoke', host='host-1')
        os.chmod(path,0o644)
        with self.assertRaisesRegex(ValueError, '0600'):
            proposal.inspect_archive(path,campaign='synthetic-smoke',host='host-1')
        os.chmod(path,0o600)
        link=self.root/'link.gz';link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            proposal.inspect_archive(link,campaign='synthetic-smoke',host='host-1')
        os.chmod(self.root,0o755)
        with self.assertRaisesRegex(ValueError, '0700'):
            proposal.compress_stream(io.BytesIO(tar_bytes('host-1')),self.root/'another.gz',maximum_bytes=10000)


if __name__ == '__main__':
    unittest.main(verbosity=2)
