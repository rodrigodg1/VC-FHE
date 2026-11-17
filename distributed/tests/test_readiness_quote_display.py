"""Readiness must show the supplied quote even when another prerequisite fails."""
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import cli


class ReadinessQuoteDisplayTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((HERE/'config.example.json').read_text())
        self.quote = {
            'currency': 'USD', 'campaign': self.config['campaign'], 'layout': 'four-hosts',
            'hourly': {'compute': '0.8', 'nat': '0.2', 'disks': '0.1', 'ipv4': '0'},
            'planned_hours': '12', 'build_registry': '2', 'retained_resources': '1',
            'transfer_storage_upper_bound': '8', 'prior_experiment_upper_bound_usd': '4',
            'quoted_at': datetime.now(timezone.utc).isoformat(),
            'source_urls': ['https://example.org/synthetic-test-only'],
        }

    def invoke(self, *, quote=True, failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root/'config.local.json'
            config.write_text(json.dumps(self.config))
            argv = ['distributed', 'readiness', '--config', str(config), '--build', str(root)]
            if quote:
                q = root/'quote.local.json'
                q.write_text(json.dumps(self.quote))
                argv += ['--quote', str(q)]
            output = io.StringIO()
            with patch.object(sys, 'argv', argv), patch('launch.check_launch', side_effect=failure) as check:
                with redirect_stdout(output):
                    code = cli.main()
            return code, json.loads(output.getvalue()), check.call_count

    def test_priced_quote_overrides_unpriced_legacy_config(self):
        self.assertTrue(any(v is None for v in self.config['cost_estimate'].values()))
        code, result, calls = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(calls, 1)
        self.assertEqual(result['budget']['status'], 'admit')
        self.assertEqual(result['budget']['prior_experiment_upper_bound_usd'], '4')
        self.assertEqual(result['cloud_actions_executed'], [])

    def test_storage_failure_does_not_erase_a_valid_price_quote(self):
        code, result, _ = self.invoke(failure=ValueError('Insufficient controller storage'))
        self.assertEqual(code, 2)
        self.assertFalse(result['ready_to_launch'])
        self.assertEqual(result['budget']['status'], 'admit')
        self.assertIn('Insufficient controller storage', result['failures'])

    def test_expired_quote_is_invalid_without_invoking_launch(self):
        self.quote['quoted_at'] = (datetime.now(timezone.utc)-timedelta(days=8)).isoformat()
        code, result, calls = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(calls, 0)
        self.assertEqual(result['budget']['status'], 'invalid-quote')
        self.assertFalse(result['ready_to_launch'])

    def test_missing_quote_stays_unpriced_and_not_ready(self):
        code, result, calls = self.invoke(quote=False)
        self.assertEqual((code, calls), (2, 0))
        self.assertEqual(result['budget']['status'], 'unpriced')
        self.assertFalse(result['ready_to_launch'])

    def test_prior_expense_can_refuse_even_if_other_checks_are_mocked(self):
        self.quote['prior_experiment_upper_bound_usd'] = '40'
        code, result, _ = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(result['budget']['status'], 'refuse')
        self.assertFalse(result['ready_to_launch'])


if __name__ == '__main__':
    unittest.main()
