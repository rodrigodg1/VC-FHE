import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import legacy_v1_seal as legacy


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


class Fixture:
    def __init__(self, base):
        self.base = Path(base)
        self.repo = self.base / "repo"
        self.cache_root = self.base / "cache"
        self.run = self.base / "run-v1-synthetic"
        self.repo.mkdir()
        self.cache_root.mkdir()
        self.run.mkdir()
        self.dataset_bytes = b"synthetic pinned V1 dataset\n"
        self.dataset_name = "datasets/test/input.csv"
        dataset = self.repo / self.dataset_name
        dataset.parent.mkdir(parents=True)
        dataset.write_bytes(self.dataset_bytes)
        self.datasets = {
            self.dataset_name: {
                "half": "linear",
                "sha256": hashlib.sha256(self.dataset_bytes).hexdigest(),
                "source": "https://example.invalid/pinned/input.csv",
                "conversion": "none",
            }
        }
        self._source_cache()
        self._run()

    def _source_cache(self):
        payloads = {
            "threshold-kms/campaign/run.py": (
                f"VERSION={legacy.VERSION!r}\nPIN={legacy.UPSTREAM_PIN!r}\n"
            ).encode(),
            "threshold-kms/campaign/Dockerfile": (
                b"COPY app/ /app/\n"
                b"RUN python3 /app/threshold-kms/campaign/inventory.py\n"
            ),
            "threshold-kms/campaign/inventory.py": b"# inventory\n",
            "threshold-kms/campaign/export.py": b"# export\n",
            "threshold-kms/campaign/datasets.py": b"# datasets\n",
        }
        self.source = {name: hashlib.sha256(payload).hexdigest()
                       for name, payload in payloads.items()}
        digest = hashlib.sha256(json.dumps(self.source, sort_keys=True).encode()).hexdigest()
        self.cache = self.cache_root / digest
        for name, payload in payloads.items():
            target = self.cache / "app" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        (self.cache / "upstream").mkdir(parents=True)
        (self.cache / "upstream/vcfhe-adapter.json").write_text("{}\n", encoding="utf-8")
        (self.cache / "Dockerfile").write_bytes(payloads["threshold-kms/campaign/Dockerfile"])
        build_files = {
            f"app/{name}": digest for name, digest in self.source.items()
        }
        build_files["Dockerfile"] = self.source["threshold-kms/campaign/Dockerfile"]
        build_files["upstream/vcfhe-adapter.json"] = sha256(
            self.cache / "upstream/vcfhe-adapter.json")
        write_json(self.cache / "complete.json", {
            "source": self.source,
            "upstream": legacy.UPSTREAM_PIN,
            "buildFiles": build_files,
        })

    def _run(self):
        cfg = {
            "version": legacy.VERSION,
            "half": "linear",
            "parameters": "Test",
            "smoke": True,
            "runId": self.run.name,
            "chainId": "46853",
            "policyDomain": legacy.VERSION,
            "infrastructureOrder": "kms-setup-before-besu-v1",
            "ownerReleaseLimit": 18,
        }
        dataset_record = {
            key: self.datasets[self.dataset_name][key]
            for key in ("sha256", "source", "conversion")
        }
        state = {
            "version": legacy.VERSION,
            "status": "passed",
            "config": cfg,
            "source": self.source,
            "upstream": legacy.UPSTREAM_PIN,
            "datasets": {self.dataset_name: dataset_record},
            "stages": [
                {"name": name, "status": "passed", "seconds": index + 0.5}
                for index, name in enumerate(legacy.EXPECTED_STAGES)
            ],
        }
        keyset = {
            "status": "passed",
            "parameters": "Test",
            "parties": 4,
            "corruptionThreshold": 1,
            "fullPreprocessing": True,
            "preloadedFheKey": False,
            "upstreamCommit": legacy.UPSTREAM_PIN,
        }
        case = {"name": "linear-acr-2-0", "outputDigest": "0x" + "11" * 32}
        app = {
            "version": legacy.VERSION,
            "status": "passed",
            "config": cfg,
            "keys": keyset,
            "cases": [case],
            "kmsCalls": 1,
            "plaintextInGateway": False,
        }
        results = {
            "classification": "smoke-not-evaluation",
            "parameters": "Test",
            "setup": keyset,
            "rows": [{
                "case": case["name"],
                "correct": True,
                "output_digest": case["outputDigest"],
            }],
        }
        write_json(self.run / "config/campaign.json", cfg)
        write_json(self.run / "state.json", state)
        write_json(self.run / "keyset/ready.json", keyset)
        write_json(self.run / "reports/application.json", app)
        write_json(self.run / "reports/results.json", results)
        for name in ("compose.json", "setup-compose.json", "besu.json"):
            write_json(self.run / name, {"synthetic": name})
        for name in ("kms-campaign", "kms-server", "kms-gen-keys", "kms-init"):
            target = self.run / "bin" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((name + "\n").encode())
        installed = {}
        for name, digest in self.source.items():
            installed[name] = {
                "sha256": digest,
                "bytes": (self.cache / "app" / name).stat().st_size,
            }
        inventory = self.run / "build-evidence/installed-files.json.gz"
        inventory.parent.mkdir(parents=True)
        with gzip.open(inventory, "wt", encoding="utf-8") as stream:
            json.dump(installed, stream, sort_keys=True)
        self.reseal()

    def reseal(self):
        inventory = legacy._historical_seal_inventory(self.run)
        files = {name: sha256(self.run / Path(*name.split("/")))
                 for name in sorted(inventory)}
        write_json(self.run / "seal.json", {
            "version": legacy.VERSION,
            "source": self.source,
            "files": files,
            "parameters": "Test",
            "classification": "smoke-not-evaluation",
            "halves": ["linear"],
        })

    def verify(self, **kwargs):
        with patch.object(legacy, "DATASETS", self.datasets):
            return legacy.verify(
                self.run,
                cache_dir=kwargs.get("cache_dir", self.cache_root),
                repo_root=self.repo,
            )


class LegacyV1SealTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(temporary.name)

    def test_accepts_complete_v1_evidence_and_exact_source_cache(self):
        fixture = self.fixture()
        summary = fixture.verify()
        self.assertEqual(summary["status"], "verified")
        self.assertEqual(summary["version"], legacy.VERSION)
        self.assertEqual(summary["sourceCache"], str(fixture.cache.resolve()))
        self.assertEqual(summary["datasets"], [fixture.dataset_name])

    def test_rejects_changed_sealed_artifact(self):
        fixture = self.fixture()
        (fixture.run / "bin/kms-server").write_bytes(b"changed\n")
        with self.assertRaisesRegex(legacy.LegacyV1SealError, "changed or missing V1 artifact"):
            fixture.verify()

    def test_rejects_path_traversal_in_seal(self):
        fixture = self.fixture()
        seal = json.loads((fixture.run / "seal.json").read_text())
        seal["files"]["../outside"] = "00" * 32
        write_json(fixture.run / "seal.json", seal)
        with self.assertRaisesRegex(legacy.LegacyV1SealError, "escapes its root"):
            fixture.verify()

    def test_rejects_absent_historical_cache(self):
        fixture = self.fixture()
        absent = fixture.base / "absent-cache"
        absent.mkdir()
        with self.assertRaisesRegex(legacy.LegacyV1SealError, "source cache is absent"):
            fixture.verify(cache_dir=absent)

    def test_rejects_changed_cached_source(self):
        fixture = self.fixture()
        (fixture.cache / "app/threshold-kms/campaign/export.py").write_text(
            "# changed\n", encoding="utf-8")
        with self.assertRaisesRegex(legacy.LegacyV1SealError, "changed historical cached source"):
            fixture.verify()

    def test_rejects_state_not_bound_to_sealed_config(self):
        fixture = self.fixture()
        state = json.loads((fixture.run / "state.json").read_text())
        state["config"]["ownerReleaseLimit"] = 19
        write_json(fixture.run / "state.json", state)
        fixture.reseal()
        with self.assertRaisesRegex(legacy.LegacyV1SealError, "state is not bound"):
            fixture.verify()

    def test_rejects_installed_source_inventory_mismatch(self):
        fixture = self.fixture()
        inventory_path = fixture.run / "build-evidence/installed-files.json.gz"
        with gzip.open(inventory_path, "rt", encoding="utf-8") as stream:
            installed = json.load(stream)
        installed["threshold-kms/campaign/export.py"]["sha256"] = "ff" * 32
        with gzip.open(inventory_path, "wt", encoding="utf-8") as stream:
            json.dump(installed, stream, sort_keys=True)
        fixture.reseal()
        with self.assertRaisesRegex(legacy.LegacyV1SealError, "installed source differs"):
            fixture.verify()

    def test_rejects_missing_critical_inventory_entry(self):
        fixture = self.fixture()
        seal = json.loads((fixture.run / "seal.json").read_text())
        del seal["files"]["keyset/ready.json"]
        write_json(fixture.run / "seal.json", seal)
        with self.assertRaisesRegex(legacy.LegacyV1SealError, "omits a critical run artifact"):
            fixture.verify()


if __name__ == "__main__":
    unittest.main()
