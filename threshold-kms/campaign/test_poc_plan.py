import collections
import unittest
from poc_plan import (FULL_REPEATS, TEST_POC_DISCLOSURE_BATCH_SIZE,
                      TEST_POC_WINDOW_SECONDS, plan, validate_timing_window)


class PocPlanTests(unittest.TestCase):
    def test_test_only_timing_gate_rejects_sixty_seconds_without_changing_the_profile(self):
        admitted=validate_timing_window(TEST_POC_WINDOW_SECONDS,TEST_POC_DISCLOSURE_BATCH_SIZE)
        self.assertEqual(admitted['windowSeconds'],120)
        self.assertEqual(admitted['exclusiveFloorSeconds'],80)
        self.assertEqual(admitted['maximumDisclosureBatches'],8)
        with self.assertRaisesRegex(ValueError,'must exceed 80 seconds'):
            validate_timing_window(60,TEST_POC_DISCLOSURE_BATCH_SIZE)
        with self.assertRaisesRegex(ValueError,'invalid Test PoC timing parameter'):
            validate_timing_window(TEST_POC_WINDOW_SECONDS,65)
        with self.assertRaisesRegex(ValueError,'protocol window remains 120 seconds'):
            validate_timing_window(90,64)

    def test_complete_grid_no_warmup_or_release_inflation(self):
        p = plan()
        self.assertEqual(p, plan())
        self.assertEqual(p['measuredPairs'], 480)
        self.assertEqual(p['fullCases'], 45)
        self.assertEqual(len(p['jobs']), 498)
        self.assertEqual(len({j['name'] for j in p['jobs']}), 498)
        self.assertEqual([j['ordinal'] for j in p['jobs']], list(range(498)))
        groups = collections.defaultdict(list)
        for job in p['jobs']:
            groups[job['group']].append(job)
        self.assertEqual(len(groups), 9)
        for jobs in groups.values():
            kind = jobs[0]['half']
            measured = [j for j in jobs if not j['warmup']]
            self.assertEqual(len(measured), 100 if kind == 'linear' else 30)
            self.assertEqual(sum(j['warmup'] for j in jobs), 2)
            self.assertFalse(any(j['fullCase'] for j in jobs if j['warmup']))
            full = [j for j in jobs if j['fullCase']]
            self.assertEqual([j['repeat'] for j in full], list(FULL_REPEATS[kind]))
            if kind == 'nonlinear':
                self.assertEqual([j['faultPosition'] for j in full], ['early', 'middle', 'terminal', 'early', 'middle'])
            for i in range(0, len(measured), 2):
                self.assertEqual(measured[i]['order'], measured[i+1]['order'][::-1])
            self.assertEqual(sum(j['order'][0] == 'proposed' for j in measured), len(measured)//2)

    def test_independent_halves_preserve_pair_order_and_full_selection(self):
        for half, pairs, releases in [('linear', 300, 15), ('nonlinear', 180, 30)]:
            p = plan(half)
            self.assertEqual(p['measuredPairs'], pairs)
            self.assertEqual(p['fullCases'], releases)
            wanted = [j for j in plan()['jobs'] if j['half'] == half]
            for a, b in zip(p['jobs'], wanted, strict=True):
                self.assertEqual({k:v for k,v in a.items() if k != 'ordinal'},
                                 {k:v for k,v in b.items() if k != 'ordinal'})
        with self.assertRaises(ValueError):
            plan('partial')


if __name__ == '__main__':
    unittest.main()
