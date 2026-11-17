#!/usr/bin/env python3
"""Test proposed code in temporary copies without changing the live sources."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import prepare_patch

HERE = Path(__file__).resolve().parent

class ProposalTests(unittest.TestCase):
    def test_source_bound_candidate(self):
        original, candidate, patch = prepare_patch.render()
        record = json.loads((HERE/'proposal.json').read_text())
        self.assertEqual(prepare_patch.hashes(original), record['source'])
        self.assertEqual(prepare_patch.hashes(candidate), record['candidate'])
        self.assertEqual((HERE/'proposal.patch').read_text(), patch)
        # Configuration, TLS options, IDs, RPC logging and phase scopes are intact.
        unchanged_rpc = original['client.mjs'].split("const cache='/transport/public-chunks';")[0]
        self.assertTrue(candidate['client.mjs'].startswith(unchanged_rpc))
        with tempfile.TemporaryDirectory(prefix='vcfhe-unapplied-transport-') as directory:
            root = Path(directory)
            staged = root/'VC-FHE/distributed'
            staged.mkdir(parents=True)
            for name, value in original.items(): (staged/name).write_text(value)
            subprocess.run(['patch','--batch','-p1','-d',str(root),'-i',str(HERE/'proposal.patch')],
                           capture_output=True,text=True,check=True,timeout=10)
            for name, value in candidate.items():
                self.assertEqual((staged/name).read_text(), value)
                (root/name).write_text((staged/name).read_text())
            (root/'legacy-public-files.mjs').write_text(original['public-files.mjs'])
            result = subprocess.run(['node','--test',str(HERE/'proposal.test.mjs')],
                env={**os.environ,'VCFHE_TRANSPORT_PROPOSAL_COPY':str(root)},capture_output=True,text=True,timeout=90)
            print(result.stdout, end='')
            if result.stderr: print(result.stderr, end='')
            self.assertEqual(result.returncode, 0)
        self.assertEqual(prepare_patch.hashes(prepare_patch.render()[0]), record['source'])

if __name__ == '__main__': unittest.main()
