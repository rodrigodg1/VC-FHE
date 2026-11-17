"""Guarded candidate checks. Native/Tonic tests are prepared, never executed here."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PROPOSAL=ROOT/'maintenance/proposals/recipient-result-transport'
SOURCE=ROOT.parent/'threshold-kms/campaign/transport.rs'
VALIDATOR=ROOT.parent/'threshold-kms/src/recipient_validation.rs'
BASELINE=PROPOSAL/'fixtures/original-transport.rs'
spec=importlib.util.spec_from_file_location('recipient_result_candidate',PROPOSAL/'prepare.py')
candidate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class RecipientTransportCandidateTests(unittest.TestCase):
    def setUp(self):
        self.original=BASELINE.read_text()
        self.proposed=candidate.render(self.original)

    def test_reviewed_baseline_and_crypto_validator_are_preserved(self):
        self.assertEqual(hashlib.sha256(BASELINE.read_bytes()).hexdigest(),candidate.EXPECTED_SOURCE_SHA256)
        self.assertEqual(hashlib.sha256(VALIDATOR.read_bytes()).hexdigest(),
                         '8b5cf6bb7b28e97edc63bcd032dbb029315ef1673b88451d922a51858f45cce1')

    def test_production_calls_the_same_function_as_real_loopback_tests(self):
        self.assertIn('let (responses,poll_count)=acquire_accepted_user_results(&endpoints,',self.proposed)
        helper=(PROPOSAL/'acquire-accepted-results.rs').read_text()
        self.assertIn('for core in accepted_submit_cores {',helper)
        self.assertNotIn('.user_decrypt(',helper)
        self.assertIn('validate_submit_core_partition(accepted_submit_cores, failed_submit_cores)?;',helper)
        self.assertIn('responses.len() >= 3',helper)
        tests=(PROPOSAL/'transport-regressions.rs').read_text()
        self.assertIn('serve_with_incoming(incoming)',tests)
        self.assertIn('CoreServiceEndpointClient::connect',tests)
        self.assertGreaterEqual(tests.count('acquire_accepted_user_results(&harness.clients'),6)
        self.assertIn('vec![1,1,0,1]',tests)
        self.assertIn('vec![1,1,1,0]',tests)

    def test_no_submissions_replayed_and_all_ingress_negative_checks_preserved(self):
        prefix=self.original[:self.original.index('        let started=std::time::Instant::now();\n        let mut accepted_submit_cores=')]
        self.assertTrue(self.proposed.startswith(prefix))
        # Production endpoint invocations are unchanged. The helper and fixture
        # server introduce no UserDecrypt or administrative call.
        self.assertEqual(self.original.count('.user_decrypt('),self.proposed.count('.user_decrypt('))
        self.assertIn('std::time::Duration::from_secs(180)',self.proposed)

    def test_exact_existing_crypto_validation_and_four_negative_response_checks_remain(self):
        before=candidate.security_tail(self.original)
        after=candidate.security_tail(self.proposed)
        self.assertEqual(before,after)
        for literal in ['responses[..1]', 'external_signature.clear()',
                        'vec![responses[0].clone();3]', 'substituted.extra_data.push(0)',
                        'substituted release context', 'signature fallback']:
            self.assertIn(literal,after)
        start='fn validate_submit_core_partition('
        self.assertEqual(self.original[self.original.index(start):],
                         self.proposed[self.proposed.index(start):].split('// Candidate client transport helper.')[0].rstrip()+'\n')

    def test_private_submission_diagnostics_precede_gate_and_result_poll(self):
        self.assertLess(self.proposed.index('format!("submit-{index}.json")'),
                        self.proposed.index('validate_submit_core_partition(&accepted_submit_cores'))
        self.assertLess(self.proposed.index('format!("submit-{index}.json")'),
                        self.proposed.index('let (responses,poll_count)=acquire_accepted_user_results'))
        self.assertIn('"userDecryptResubmissions":0',self.proposed)
        self.assertIn('"grpcCode":format!("{:?}",error.code())',self.proposed)
        self.assertNotIn('error.message()',self.proposed)

    def test_missing_accepted_core_is_not_relabeled_as_pending(self):
        helper=(PROPOSAL/'acquire-accepted-results.rs').read_text()
        self.assertIn('error.code() == tonic::Code::Unavailable',helper)
        self.assertIn('Err(error) => return Err(error.into())',helper)
        self.assertNotIn('error.code() == tonic::Code::NotFound',helper)
        tests=(PROPOSAL/'transport-regressions.rs').read_text()
        self.assertIn('tops_transport_accepted_core_notfound_fails_closed',tests)
        self.assertIn('tops_transport_two_acks_rejected_before_fetch',tests)
        self.assertIn('tops_transport_unavailable_is_polled_without_resubmission',tests)

    def test_prepare_uses_fresh_private_output_and_rejects_source_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'candidate'
            report=candidate.prepare(BASELINE,output)
            self.assertEqual(report['status'],'candidate-not-applied')
            self.assertFalse(report['nativeCompiled'])
            self.assertFalse(report['nativeExecuted'])
            self.assertEqual(output.stat().st_mode&0o777,0o700)
            self.assertEqual((output/'transport.proposed.rs').stat().st_mode&0o777,0o600)
            self.assertEqual((output/'transport.proposed.rs').read_text(),self.proposed)
            with self.assertRaises(ValueError):candidate.prepare(BASELINE,output)
        with self.assertRaises(ValueError):candidate.render(self.original+'\n')


if __name__=='__main__':unittest.main()
