import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import remote


def archive_bytes(name='reports/result.json',payload=b'{"passed":true}',kind=None):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as archive:
        entry=tarfile.TarInfo(name)
        if kind is not None:
            entry.type=kind
            entry.linkname='/outside'
            archive.addfile(entry)
        else:
            entry.size=len(payload)
            archive.addfile(entry,io.BytesIO(payload))
    return output.getvalue()


class EvidenceReadRetryTests(unittest.TestCase):
    def setUp(self):
        self.transport=remote.Remote({'project_id':'fixture'},{'name':'fixture','zone':'fixture'})
        self.sleep=patch.object(remote.time,'sleep').start()
        self.addCleanup(patch.stopall)

    def download(self,destination):
        return self.transport.download('/srv/fixture',['reports'],destination)

    def test_partial_transport_archive_is_discarded_before_retry_and_extraction(self):
        streams=[]
        commands=[]
        def read(args,**kwargs):
            stream=kwargs['stdout']
            self.assertEqual(stream.tell(),0)
            streams.append(stream)
            commands.append(args)
            if len(streams)==1:
                stream.write(archive_bytes('reports/unconfirmed.json',b'partial'))
                raise subprocess.CalledProcessError(255,args,stderr=b'connection closed')
            stream.write(archive_bytes())
        self.transport.run=Mock(side_effect=read)
        with tempfile.TemporaryDirectory() as directory:
            self.download(directory)
            self.assertFalse((Path(directory)/'reports/unconfirmed.json').exists())
            self.assertEqual((Path(directory)/'reports/result.json').read_bytes(),b'{"passed":true}')
        self.assertIsNot(streams[0],streams[1])
        self.assertTrue(all(stream.closed for stream in streams))
        self.assertEqual(commands,[['sudo','tar','-cf','-','-C','/srv/fixture','reports']]*2)
        self.assertEqual(self.sleep.call_args_list[0].args,(1,))

    def test_three_failed_readonly_transports_never_extract_partial_bytes(self):
        def fail(args,**kwargs):
            kwargs['stdout'].write(archive_bytes())
            raise subprocess.CalledProcessError(255,args,stderr=b'connection closed')
        self.transport.run=Mock(side_effect=fail)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError):self.download(directory)
            self.assertEqual(list(Path(directory).iterdir()),[])
        self.assertEqual(self.transport.run.call_count,3)
        self.assertEqual([call.args for call in self.sleep.call_args_list],[(1,),(2,)])

    def test_iap_authorization_transport_failure_is_retried_for_tar_only(self):
        def read(args,**kwargs):
            if self.transport.run.call_count==1:
                raise subprocess.CalledProcessError(1,args,stderr='ERROR 4033: not authorized')
            kwargs['stdout'].write(archive_bytes())
        self.transport.run=Mock(side_effect=read)
        with tempfile.TemporaryDirectory() as directory:self.download(directory)
        self.assertEqual(self.transport.run.call_count,2)

    def test_remote_tar_failure_is_not_retried(self):
        self.transport.run=Mock(side_effect=subprocess.CalledProcessError(2,['tar'],stderr=b'Cannot stat'))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError):self.download(directory)
        self.assertEqual(self.transport.run.call_count,1)
        self.sleep.assert_not_called()

    def test_successful_transport_with_invalid_archive_is_not_retried(self):
        self.transport.run=Mock(side_effect=lambda args,**kw:kw['stdout'].write(b'not a tar archive'))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(tarfile.ReadError):self.download(directory)
            self.assertEqual(list(Path(directory).iterdir()),[])
        self.assertEqual(self.transport.run.call_count,1)
        self.sleep.assert_not_called()

    def test_unsafe_archive_is_rejected_without_retry_or_extraction(self):
        for name,kind in [('../outside',None),('/outside',None),('reports/link',tarfile.SYMTYPE)]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as directory:
                self.transport.run=Mock(side_effect=lambda args,**kw:kw['stdout'].write(archive_bytes(name,kind=kind)))
                with self.assertRaisesRegex(ValueError,'unsafe evidence archive entry'):self.download(directory)
                self.assertEqual(list(Path(directory).iterdir()),[])
                self.assertEqual(self.transport.run.call_count,1)
        self.sleep.assert_not_called()

    def test_existing_evidence_is_not_overwritten_or_retried(self):
        self.transport.run=Mock(side_effect=lambda args,**kw:kw['stdout'].write(archive_bytes()))
        with tempfile.TemporaryDirectory() as directory:
            original=Path(directory)/'reports/result.json'
            original.parent.mkdir()
            original.write_bytes(b'preserved')
            with self.assertRaises(FileExistsError):self.download(directory)
            self.assertEqual(original.read_bytes(),b'preserved')
        self.assertEqual(self.transport.run.call_count,1)
        self.sleep.assert_not_called()

    def test_local_extraction_error_is_not_retried(self):
        self.transport.run=Mock(side_effect=lambda args,**kw:kw['stdout'].write(archive_bytes()))
        with tempfile.TemporaryDirectory() as directory,patch('shutil.copyfileobj',side_effect=OSError('local disk full')):
            with self.assertRaisesRegex(OSError,'local disk full'):self.download(directory)
        self.assertEqual(self.transport.run.call_count,1)
        self.sleep.assert_not_called()

    def test_retry_timeout_uses_the_original_remaining_budget(self):
        clock={'now':90}
        self.transport.read_deadline=100
        def read(args,**kwargs):
            if self.transport.run.call_count==1:
                self.assertEqual(kwargs['timeout'],10)
                clock['now']=94
                raise subprocess.TimeoutExpired(args,10)
            self.assertEqual(kwargs['timeout'],5)
            kwargs['stdout'].write(archive_bytes())
        self.transport.run=Mock(side_effect=read)
        self.sleep.side_effect=lambda duration:clock.__setitem__('now',clock['now']+duration)
        with patch.object(remote.time,'monotonic',side_effect=lambda:clock['now']),tempfile.TemporaryDirectory() as directory:
            self.download(directory)
        self.assertEqual(self.transport.read_deadline,100)
        self.assertEqual(self.transport.run.call_count,2)

    def test_retry_backoff_cannot_extend_an_expired_original_budget(self):
        clock={'now':99.75}
        self.transport.read_deadline=100
        self.transport.run=Mock(side_effect=subprocess.TimeoutExpired(['tar'],.25))
        self.sleep.side_effect=lambda duration:clock.__setitem__('now',clock['now']+duration)
        with patch.object(remote.time,'monotonic',side_effect=lambda:clock['now']),tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(TimeoutError,'original evidence-read deadline exhausted'):self.download(directory)
        self.assertEqual(self.transport.run.call_count,1)
        self.sleep.assert_called_once_with(.25)

    def test_expired_or_invalid_deadline_starts_no_read(self):
        self.transport.run=Mock()
        for deadline,error in [(99,TimeoutError),(float('nan'),ValueError),(True,ValueError)]:
            with self.subTest(deadline=deadline),patch.object(remote.time,'monotonic',return_value=100),tempfile.TemporaryDirectory() as directory:
                self.transport.read_deadline=deadline
                with self.assertRaises(error):self.download(directory)
        self.transport.run.assert_not_called()

    def test_generic_run_and_json_do_not_retry_commands(self):
        with patch.object(remote,'command',side_effect=subprocess.CalledProcessError(255,['ssh'])) as call:
            for action in [lambda:self.transport.run(['state-changing-command']),lambda:self.transport.json(['ambiguous-command'])]:
                call.reset_mock()
                with self.assertRaises(subprocess.CalledProcessError):action()
                call.assert_called_once()
        self.sleep.assert_not_called()


class PublicHostProfileRetryTests(unittest.TestCase):
    def setUp(self):
        self.profile={'cpuModel':'AMD EPYC fixture','kernelRelease':'fixture','architecture':'x86_64'}
        self.transport=SimpleNamespace(run=Mock())
        self.sleep=patch.object(remote.time,'sleep').start()
        self.addCleanup(patch.stopall)

    def test_only_fixed_public_metadata_command_retries_iap_read_failure(self):
        self.transport.run.side_effect=[subprocess.CalledProcessError(1,['ssh'],stderr='ERROR 4033: not authorized'),
                                       SimpleNamespace(stdout=json.dumps(self.profile))]
        self.assertEqual(remote.read_host_profile(self.transport),self.profile)
        self.assertEqual(self.transport.run.call_count,2)
        for call in self.transport.run.call_args_list:
            self.assertEqual(call.args,(['python3','-c',remote.HOST_PROFILE_SCRIPT],))
            self.assertEqual(call.kwargs['timeout'],45)

    def test_successful_but_malformed_profile_never_retries(self):
        for value in ['not json','{}',json.dumps(dict(self.profile,private='unexpected')),json.dumps(dict(self.profile,cpuModel=''))]:
            with self.subTest(value=value):
                self.transport.run.reset_mock()
                self.transport.run.return_value=SimpleNamespace(stdout=value)
                with self.assertRaises((ValueError,json.JSONDecodeError)):remote.read_host_profile(self.transport)
                self.transport.run.assert_called_once()
        self.sleep.assert_not_called()

    def test_host_profile_read_obeys_original_remaining_budget(self):
        self.transport.read_deadline=100
        self.transport.run.return_value=SimpleNamespace(stdout=json.dumps(self.profile))
        with patch.object(remote.time,'monotonic',return_value=97):remote.read_host_profile(self.transport)
        self.assertEqual(self.transport.run.call_args.kwargs['timeout'],3)


if __name__=='__main__':unittest.main()
