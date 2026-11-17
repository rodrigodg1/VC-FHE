import copy
import hashlib
import json
import tempfile
from pathlib import Path
import unittest
from verify_composite import member, sha, verify_files, verify_ledger, ledger_wire_sha


class CompositeChecks(unittest.TestCase):
    def test_ledger_wire_hash_survives_snapshot_indentation(self):
        raw = '{"version":2,"domain":"d","records":{"a":{"spent":3}}}'
        snapshot = json.loads(json.dumps(json.loads(raw), indent=2))
        self.assertEqual(ledger_wire_sha(snapshot), hashlib.sha256(raw.encode()).hexdigest())
        snapshot['records']['a']['spent'] = 0
        self.assertNotEqual(ledger_wire_sha(snapshot), hashlib.sha256(raw.encode()).hexdigest())

    def setUp(self):
        self.before = {'domain': 'd', 'version': 2, 'records': {'r': {'owner': 'o', 'limit': 18, 'spent': 3}},
                       'slots': {}, 'requests': {}, 'consents': {}}
        self.case = {'name': 'case', 'n': 1, 'recordIds': ['r'], 'owners': ['o']}
        context = {k: k for k in ['domain', 'chainId', 'game', 'keyId', 'keyEpoch', 'keysetDigest',
                                  'mpcContext', 'programDigest', 'profileDigest', 'contextDigest', 'outputType']}
        self.request = {**context, 'slot': 's', 'requestId': 'q', 'kmsRequestDigest': 'h',
                        'consentId': 'c', 'recipient': 'recipient'}
        self.after = copy.deepcopy(self.before)
        self.after['records']['r']['spent'] = 4
        self.after['slots']['s'] = {'state': 'released', 'requestId': 'q', 'kmsRequestDigest': 'h'}
        self.after['requests']['q'] = 's'
        self.after['consents']['s'] = {'id': 'c', 'consent': {**context, 'slot': 's',
                                            'recordIds': ['r'], 'recipients': ['recipient']}}

    def check(self):
        return verify_ledger(self.before, self.after, [self.case], [self.request], 18)

    def test_exact_delta(self):
        self.assertEqual(self.check()['newReleases'], 1)

    def test_reset_rejected(self):
        self.after['records']['r']['spent'] = 1
        with self.assertRaises(ValueError): self.check()

    def test_limit_increase_rejected(self):
        self.after['records']['r']['limit'] = 19
        with self.assertRaises(ValueError): self.check()

    def test_reserved_slot_rejected(self):
        self.after['slots']['s']['state'] = 'reserved'
        with self.assertRaises(ValueError): self.check()

    def test_extra_release_rejected(self):
        self.after['slots']['extra'] = self.after['slots']['s']
        with self.assertRaises(ValueError): self.check()

    def test_old_consent_mutation_rejected(self):
        self.before['consents']['prior'] = {'id': 'old'}
        self.after['consents']['prior'] = {'id': 'new'}
        with self.assertRaises(ValueError): self.check()

    def test_recipient_change_rejected(self):
        self.request['recipient'] = 'other'
        with self.assertRaises(ValueError): self.check()

    def test_counter_removal_rejected(self):
        self.after['records'].clear()
        with self.assertRaises(ValueError): self.check()

    def test_missing_request_rejected(self):
        self.after['requests'].clear()
        with self.assertRaises(ValueError): self.check()

    def test_traversal_rejected(self):
        for p in ['../outside', '/outside']:
            with self.assertRaises(ValueError): member(Path('/tmp'), p)

    def test_inventory_bytes_and_link_targets(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'file').write_bytes(b'one')
            (root / 'link').symlink_to('file')
            manifest = {'file': sha(root / 'file'), 'link': {'symlink': 'file'}}
            verify_files(root, manifest)
            (root / 'file').write_bytes(b'two')
            with self.assertRaises(ValueError): verify_files(root, manifest)

    def test_symlink_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'dir').symlink_to('/tmp')
            with self.assertRaises(ValueError): member(root, 'dir/file')


if __name__ == '__main__':
    unittest.main()
