"""Sealed setup evidence checks, with synthetic data and no infrastructure."""
import json
from pathlib import Path
import tempfile
import unittest
import setup_evidence as setup
import refresh
from verify_composite import sha


class SetupEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.run, self.base = root/'run', root/'derived'
        (self.run/'config').mkdir(parents=True)
        self.base.mkdir()

    def fixture(self, half='both', host=True):
        cfg = dict(half=half, windowSeconds=120, disclosureBatchSize=64,
                   kmsRayonThreads=1, kmsTokioThreads=1, nonlinearProtocol='bounty-v2')
        state = dict(config=cfg, resources=dict(NCPU=16, MemTotal=32*2**30,
                                              Architecture='x86_64', OperatingSystem='Fixture Docker'))
        if host:
            state['hostEnvironment'] = dict(schema='launcher-host-environment-v1',
                scope='launcher-host-not-docker-daemon', cpuModel='Fixture CPU',
                logicalCpuCount=24, osVisibleMemoryBytes=64*2**30,
                operatingSystem='Linux', operatingSystemRelease='fixture', architecture='x86_64')
        (self.run/'reports').mkdir(exist_ok=True)
        app = self.disclosure_fixture()
        names = ['state.json', 'config/campaign.json', 'reports/application.json']
        for name, data in zip(names, [state, cfg, app]):
            (self.run/name).write_text(json.dumps(data))
        (self.run/'seal.json').write_text(json.dumps(dict(files={
            name:sha(self.run/name) for name in names})))
        pairs, warmups, cases = {'both':(480,18,45), 'linear':(300,6,15), 'nonlinear':(180,12,30)}[half]
        provenance = dict(kind='single-complete-run', run=str(self.run), stateSha256=sha(self.run/'state.json'),
                          measuredPairs=pairs, warmups=warmups, fullCases=cases)
        (self.base/'provenance.json').write_text(json.dumps(provenance))
        return cfg, state

    def disclosure_fixture(self):
        topic = '0x4f06e2771c770611ac4e425d815922b2bf8b3693fdbd5e5262fcb7190d360ff6'
        bounty = dict(availability='0x1234', taskId='0xabcd')
        receipts = []
        for i, indices in enumerate([range(48), range(48,64)]):
            receipts.append(dict(label='publishAuthenticatedTraceBatch', txHash=str(i), status=1,
                to=bounty['availability'], logs=[dict(address=bounty['availability'],
                    topics=[topic, bounty['taskId'], hex(n)]) for n in indices]))
        return dict(cases=[dict(half='nonlinear',metrics=dict(nonlinearProtocol='bounty-v2',leaves=64,
            disputes=[dict(settlement=dict(bounty=bounty))]))], receipts=receipts)

    def test_measured_batch_is_distinct_from_configured_request(self):
        self.fixture()
        report = setup.ensure(self.base)
        self.assertEqual(report['configuredDisclosureBatchSize'], 64)
        self.assertEqual(report['disclosureBatchSize'], 48)
        evidence = report['disclosureBatchEvidence']
        self.assertEqual(evidence['batchCount'], 2)
        self.assertEqual(evidence['publishedLeaves'], 64)
        self.assertEqual(evidence['batchSizeCounts'], {'16':1,'48':1})
        self.assertIn('| Maximum leaves per measured disclosure batch | 48 |', setup.render(report))

    def test_incomplete_duplicate_failed_and_foreign_receipts_are_rejected(self):
        for corruption in ['missing', 'duplicate', 'failed', 'foreign', 'unsealed']:
            with self.subTest(corruption=corruption):
                self.fixture()
                app = self.disclosure_fixture()
                if corruption == 'missing': app['receipts'].pop()
                elif corruption == 'duplicate': app['receipts'].append(app['receipts'][0])
                elif corruption == 'failed': app['receipts'][0]['status'] = 0
                elif corruption == 'foreign': app['receipts'][0]['logs'][0]['address'] = '0x9999'
                else:
                    (self.run/'reports/application.json').write_text('{}')
                    with self.assertRaises(ValueError): setup.build(self.base)
                    continue
                with self.assertRaises(ValueError): setup.measured_disclosure({'disclosureBatchSize':64}, app)

    def test_legacy_profile_retains_its_configured_batch(self):
        self.fixture()
        cfg = json.loads((self.run/'config/campaign.json').read_text())
        cfg['nonlinearProtocol'] = 'canonical'
        state = json.loads((self.run/'state.json').read_text()); state['config'] = cfg
        for name, obj in [('state.json',state),('config/campaign.json',cfg)]:
            (self.run/name).write_text(json.dumps(obj))
        seal = json.loads((self.run/'seal.json').read_text())
        for name in seal['files']: seal['files'][name] = sha(self.run/name)
        (self.run/'seal.json').write_text(json.dumps(seal))
        provenance = json.loads((self.base/'provenance.json').read_text())
        provenance['stateSha256'] = sha(self.run/'state.json')
        (self.base/'provenance.json').write_text(json.dumps(provenance))
        report = setup.build(self.base)
        self.assertEqual(report['disclosureBatchSize'],64)
        self.assertIsNone(report['disclosureBatchEvidence'])

    def test_report_uses_sealed_host_and_docker_values_separately(self):
        self.fixture()
        report = setup.ensure(self.base)
        self.assertEqual(setup.validate(self.base), report)
        self.assertEqual(report['hostEnvironment']['logicalCpuCount'], 24)
        self.assertEqual(report['dockerResources']['NCPU'], 16)
        self.assertEqual(report['measuredPairs'], 480)
        self.assertIn('remote Docker daemon', (self.base/setup.TEXT_NAME).read_text())
        self.assertEqual(setup.ensure(self.base), report)

    def test_historical_run_does_not_infer_physical_host_from_docker(self):
        self.fixture(host=False)
        report = setup.ensure(self.base)
        self.assertIsNone(report['hostEnvironment'])
        self.assertEqual(report['hostMetadataStatus'], 'unavailable in this historical run')
        self.assertIn('| Launcher CPU model | not recorded |', (self.base/setup.TEXT_NAME).read_text())

    def test_nonlinear_counts_and_results_index(self):
        self.fixture(half='nonlinear')
        report = setup.ensure(self.base)
        self.assertEqual((report['measuredPairs'], report['warmups'], report['fullCases']), (180,12,30))

    def test_changed_state_config_or_derived_report_is_rejected(self):
        for changed in ['state.json', 'config/campaign.json', 'derived']:
            with self.subTest(changed=changed):
                self.fixture()
                # Distinct subtest files avoid replacing a retained derived report.
                expected = setup.build(self.base)
                (self.base/setup.JSON_NAME).write_text(json.dumps(expected, indent=2)+'\n')
                (self.base/setup.TEXT_NAME).write_text(setup.render(expected))
                path = self.base/setup.JSON_NAME if changed=='derived' else self.run/changed
                path.write_text('{}')
                with self.assertRaises(ValueError):
                    setup.validate(self.base)




if __name__ == '__main__':
    unittest.main()
