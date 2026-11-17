#!/usr/bin/env python3
"""Fail-closed offline verifier for ``dataset-threshold-campaign-v1`` seals.

This module is deliberately separate from the active V3 runner.  It verifies
the stronger invariants that can still be established from a preserved V1 run
and its content-addressed build cache.  It does not upgrade V1 evidence into
V3 on-chain-policy evidence.
"""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping


VERSION = "dataset-threshold-campaign-v1"
UPSTREAM_PIN = "986537258d8c0348f497b1860ccf63252bc238f3"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_JSON_BYTES = 256 * 1024 * 1024

REQUIRED_SEALED_FILES = frozenset({
    "config/campaign.json",
    "state.json",
    "compose.json",
    "setup-compose.json",
    "besu.json",
    "keyset/ready.json",
    "reports/application.json",
    "reports/results.json",
    "bin/kms-campaign",
    "bin/kms-server",
    "bin/kms-gen-keys",
    "bin/kms-init",
    "build-evidence/installed-files.json.gz",
})

REQUIRED_SOURCE_FILES = frozenset({
    "threshold-kms/campaign/run.py",
    "threshold-kms/campaign/Dockerfile",
    "threshold-kms/campaign/inventory.py",
    "threshold-kms/campaign/export.py",
    "threshold-kms/campaign/datasets.py",
})

SEALED_TREE_FOLDERS = (
    "reports", "fixtures", "keyset", "config", "bin", "build-evidence",
)

EXPECTED_STAGES = (
    "identities", "kms-cores", "prss", "dkg", "besu", "owner-start",
    "worker-start", "recipient-start", "evaluation",
)

DATASETS = {
    "datasets/raw/stav360/Raw_Ratings.csv": {
        "half": "linear",
        "sha256": "19e171b0704287f1492ebb2cff505ed5ea0c1f538c3972524117358b57646ead",
        "source": (
            "https://raw.githubusercontent.com/SLG-European-Projects/STAV360/"
            "ef4dd1ea35f275d4240b5886dcc0e372de73d330/Raw_Ratings.csv"
        ),
        "conversion": "none",
    },
    "data/MOS_BS_1_Driver_PRB_10.csv": {
        "half": "nonlinear",
        "sha256": "af369d082bc4d54674dd3c25cfe54d67694f9df5872114799d6544e83bff8f64",
        "source": (
            "https://raw.githubusercontent.com/telematics-lab/5G-QoERA/"
            "3add3121ded7a31f1434e863073917772993b74b/"
            "5G-QoERA/MOS_BS_1_Driver_PRB_10.tsv"
        ),
        "conversion": "tab to comma",
    },
    "data/MOS_BS_4_Driver_PRB_10.csv": {
        "half": "nonlinear",
        "sha256": "7810fe63758b128f6696a06c35704cb6473d3a747cfa8ff902275aeece37a823",
        "source": (
            "https://raw.githubusercontent.com/telematics-lab/5G-QoERA/"
            "3add3121ded7a31f1434e863073917772993b74b/"
            "5G-QoERA/MOS_BS_4_Driver_PRB_10.tsv"
        ),
        "conversion": "tab to comma",
    },
}


class LegacyV1SealError(ValueError):
    """The preserved V1 evidence is incomplete, ambiguous, or inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LegacyV1SealError(message)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LegacyV1SealError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json(payload: bytes, label: str) -> Any:
    _require(len(payload) <= MAX_JSON_BYTES, f"{label} exceeds the verification size limit")
    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LegacyV1SealError(f"invalid JSON in {label}") from error


def _object(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    _require(isinstance(value, list), f"{label} must be a JSON array")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise LegacyV1SealError(f"cannot read {path}") from error
    return digest.hexdigest()


def _valid_sha256(value: Any, label: str) -> str:
    _require(isinstance(value, str) and HEX_SHA256.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _relative_name(value: Any, label: str) -> str:
    _require(isinstance(value, str) and value, f"{label} must be a nonempty string")
    _require("\\" not in value and "\x00" not in value and ":" not in value,
             f"{label} is not a canonical POSIX relative path")
    _require(not any(ord(character) < 32 for character in value),
             f"{label} contains a control character")
    path = PurePosixPath(value)
    _require(not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts),
             f"{label} escapes its root")
    _require(path.as_posix() == value, f"{label} is not canonical")
    return value


def _native_long_path(path: Path) -> Path:
    """Use the Win32 extended prefix for preserved cache paths over MAX_PATH."""
    if os.name != "nt" or not path.is_absolute():
        return path
    value = str(path)
    if value.startswith("\\\\?\\"):
        return path
    if value.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + value[2:])
    return Path("\\\\?\\" + value)


def _without_extended_prefix(path: Path) -> Path:
    value = str(path)
    if value.startswith("\\\\?\\UNC\\"):
        return Path("\\\\" + value[8:])
    if value.startswith("\\\\?\\"):
        return Path(value[4:])
    return path


def _safe_file(root: Path, relative: str, *, reject_symlinks: bool = True) -> Path:
    name = _relative_name(relative, "file name")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise LegacyV1SealError(f"missing verification root: {root}") from error
    candidate = root.joinpath(*PurePosixPath(name).parts)
    if reject_symlinks:
        cursor = root
        for part in PurePosixPath(name).parts:
            cursor = cursor / part
            try:
                _require(not _native_long_path(cursor).is_symlink(),
                         f"symlink is forbidden in sealed path: {name}")
            except OSError as error:
                raise LegacyV1SealError(f"cannot inspect sealed path: {name}") from error
    try:
        resolved = _native_long_path(candidate).resolve(strict=True)
        _without_extended_prefix(resolved).relative_to(root)
    except (OSError, ValueError) as error:
        raise LegacyV1SealError(f"missing or escaping file: {name}") from error
    _require(resolved.is_file(), f"sealed path is not a regular file: {name}")
    return resolved


def _read_json_file(path: Path, label: str) -> Any:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise LegacyV1SealError(f"cannot read {label}") from error
    return _decode_json(payload, label)


def _validated_digest_map(value: Any, label: str) -> dict[str, str]:
    raw = _object(value, label)
    _require(raw, f"{label} must not be empty")
    result: dict[str, str] = {}
    folded: set[str] = set()
    for raw_name, raw_digest in raw.items():
        name = _relative_name(raw_name, f"{label} entry")
        _require(name.casefold() not in folded, f"ambiguous path in {label}: {name}")
        folded.add(name.casefold())
        result[name] = _valid_sha256(raw_digest, f"{label}[{name}]")
    return result


def _historical_seal_inventory(run: Path) -> set[str]:
    """Reproduce the file-selection rule used by the V1 seal writer."""
    inventory: set[str] = set()
    for folder_name in SEALED_TREE_FOLDERS:
        folder = run / folder_name
        if not folder.exists():
            continue
        _require(folder.is_dir() and not folder.is_symlink(),
                 f"invalid sealed artifact directory: {folder_name}")
        for path in folder.rglob("*"):
            _require(not path.is_symlink(),
                     f"symlink is forbidden in sealed artifact tree: {path.relative_to(run)}")
            if path.is_file() and not path.name.endswith(".key"):
                inventory.add(path.relative_to(run).as_posix())
    recipient = run / "recipient"
    if recipient.exists():
        _require(recipient.is_dir() and not recipient.is_symlink(),
                 "invalid recipient artifact directory")
        for path in recipient.glob("result-*.json"):
            _require(not path.is_symlink() and path.is_file(),
                     f"invalid recipient result: {path.name}")
            inventory.add(path.relative_to(run).as_posix())
    for name in ("state.json", "compose.json", "setup-compose.json", "besu.json"):
        if (run / name).is_file():
            inventory.add(name)
    return inventory


def _source_cache_digest(source: Mapping[str, str]) -> str:
    # This intentionally preserves the json.dumps defaults used by V1.
    payload = json.dumps(dict(source), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _literal_assignment(tree: ast.AST, name: str) -> Any:
    values = []
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    try:
                        values.append(ast.literal_eval(node.value))
                    except (ValueError, TypeError):
                        values.append(None)
    _require(len(values) == 1, f"cached V1 runner must assign {name} exactly once")
    return values[0]


def _verify_cached_sources(cache_root: Path, source: Mapping[str, str]) -> tuple[Path, str]:
    digest = _source_cache_digest(source)
    cache = cache_root.resolve() / digest
    _require(cache.is_dir() and not cache.is_symlink(),
             f"required historical V1 source cache is absent: {cache}")
    marker = _object(_read_json_file(_safe_file(cache, "complete.json"),
                                     "historical cache complete.json"),
                     "historical cache complete.json")
    _require(marker.get("source") == dict(source),
             "historical source-cache manifest differs from the V1 seal")
    _require(marker.get("upstream") == UPSTREAM_PIN,
             "historical source cache uses the wrong Zama KMS revision")
    build_files = _validated_digest_map(marker.get("buildFiles"),
                                        "historical cache buildFiles")

    expected_app = set(source)
    app = cache / "app"
    _require(app.is_dir() and not app.is_symlink(), "historical cache app directory is absent")
    actual_app: set[str] = set()
    for path in app.rglob("*"):
        _require(not path.is_symlink(),
                 f"symlink is forbidden in historical source cache: {path.relative_to(app)}")
        if path.is_file():
            actual_app.add(path.relative_to(app).as_posix())
    _require(actual_app == expected_app,
             "historical cache app tree differs from the sealed source manifest")

    for name, expected in source.items():
        cached = _safe_file(app, name)
        _require(_sha256(cached) == expected,
                 f"changed historical cached source: {name}")
        _require(build_files.get(f"app/{name}") == expected,
                 f"historical build marker does not bind app/{name}")

    docker_digest = source["threshold-kms/campaign/Dockerfile"]
    _require(build_files.get("Dockerfile") == docker_digest,
             "historical build marker does not bind the root Dockerfile")
    _require(build_files.get("upstream/vcfhe-adapter.json") is not None,
             "historical build marker omits the upstream adapter")

    # V1 recorded every build input in complete.json.  Rehash the full recorded
    # set, including the pinned upstream checkout, instead of trusting the marker.
    for name, expected in build_files.items():
        path = _safe_file(cache, name, reject_symlinks=False)
        _require(_sha256(path) == expected,
                 f"changed historical build-cache input: {name}")

    runner = _safe_file(app, "threshold-kms/campaign/run.py")
    try:
        tree = ast.parse(runner.read_text(encoding="utf-8"), filename=str(runner))
    except (OSError, UnicodeDecodeError, SyntaxError) as error:
        raise LegacyV1SealError("cached V1 runner is unreadable or invalid Python") from error
    _require(_literal_assignment(tree, "VERSION") == VERSION,
             "cached runner is not the V1 campaign implementation")
    _require(_literal_assignment(tree, "PIN") == UPSTREAM_PIN,
             "cached runner does not pin the expected Zama KMS revision")
    return cache, digest


def _read_installed_inventory(path: Path) -> dict[str, Any]:
    try:
        with gzip.open(path, "rb") as stream:
            payload = stream.read(MAX_JSON_BYTES + 1)
    except (OSError, EOFError) as error:
        raise LegacyV1SealError("invalid installed-files.json.gz") from error
    _require(len(payload) <= MAX_JSON_BYTES,
             "installed-files.json.gz exceeds the verification size limit")
    inventory = _object(_decode_json(payload, "installed-files.json.gz"),
                        "installed-files.json.gz")
    folded: set[str] = set()
    for raw_name, raw_record in inventory.items():
        name = _relative_name(raw_name, "installed inventory path")
        _require(name.casefold() not in folded,
                 f"ambiguous installed inventory path: {name}")
        folded.add(name.casefold())
        record = _object(raw_record, f"installed inventory record {name}")
        _require(set(record) == {"sha256", "bytes"},
                 f"invalid installed inventory record: {name}")
        _valid_sha256(record.get("sha256"), f"installed inventory digest {name}")
        size = record.get("bytes")
        _require(isinstance(size, int) and not isinstance(size, bool) and size >= 0,
                 f"invalid installed inventory size: {name}")
    return inventory


def _validate_installed_sources(inventory: Mapping[str, Any], source: Mapping[str, str],
                                cache: Path) -> None:
    for name, digest in source.items():
        record = inventory.get(name)
        _require(isinstance(record, dict),
                 f"installed dependency inventory omits sealed source: {name}")
        _require(record.get("sha256") == digest,
                 f"installed source differs from the V1 source manifest: {name}")
        size = _safe_file(cache / "app", name).stat().st_size
        _require(record.get("bytes") == size,
                 f"installed source size differs from the V1 source cache: {name}")


def _validate_config_and_metadata(run: Path, seal: Mapping[str, Any], source: Mapping[str, str],
                                  cfg: Mapping[str, Any], state: Mapping[str, Any],
                                  keyset: Mapping[str, Any], app: Mapping[str, Any],
                                  results: Mapping[str, Any]) -> None:
    _require(cfg.get("version") == VERSION, "campaign config is not V1")
    half = cfg.get("half")
    _require(half in {"linear", "nonlinear", "both"}, "invalid V1 campaign half")
    _require(cfg.get("parameters") in {"Default", "Test"}, "invalid V1 FHE parameters")
    _require(isinstance(cfg.get("smoke"), bool), "invalid V1 smoke flag")
    _require(cfg.get("runId") == run.name, "campaign runId differs from the run directory")
    _require(str(cfg.get("chainId")) == "46853", "V1 campaign does not bind chain 46853")
    _require(cfg.get("policyDomain") == VERSION, "V1 policy domain is inconsistent")
    _require(cfg.get("infrastructureOrder") == "kms-setup-before-besu-v1",
             "V1 infrastructure order is inconsistent")
    _require(cfg.get("ownerReleaseLimit") == 18,
             "V1 owner release limit is inconsistent")

    expected_classification = cfg.get(
        "classification",
        "smoke-not-evaluation" if cfg["smoke"] else "dataset-real-threshold-besu",
    )
    expected_halves = [half] if half != "both" else ["linear", "nonlinear"]
    _require(seal.get("parameters") == cfg.get("parameters"),
             "seal parameters differ from the campaign config")
    _require(seal.get("classification") == expected_classification,
             "seal classification differs from the campaign config")
    _require(seal.get("halves") == expected_halves,
             "seal halves differ from the campaign config")

    _require(state.get("version") == VERSION and state.get("status") == "passed",
             "V1 state is not a completed run")
    _require(state.get("source") == dict(source),
             "V1 state source differs from the seal")
    _require(state.get("config") == dict(cfg),
             "V1 state is not bound to the sealed campaign config")
    _require(state.get("upstream") == UPSTREAM_PIN,
             "V1 state uses the wrong Zama KMS revision")
    stages = _list(state.get("stages"), "state.stages")
    _require([item.get("name") if isinstance(item, dict) else None for item in stages]
             == list(EXPECTED_STAGES), "V1 stage sequence is incomplete or reordered")
    for item in stages:
        _require(item.get("status") == "passed", f"V1 stage did not pass: {item.get('name')}")
        seconds = item.get("seconds")
        _require(isinstance(seconds, (int, float)) and not isinstance(seconds, bool)
                 and math.isfinite(seconds) and seconds >= 0,
                 f"invalid V1 stage duration: {item.get('name')}")

    _require(keyset.get("status") == "passed", "V1 keyset did not pass setup")
    _require(keyset.get("parameters") == cfg.get("parameters"),
             "V1 keyset parameters differ from the campaign config")
    _require(keyset.get("parties") == 4 and keyset.get("corruptionThreshold") == 1,
             "V1 keyset does not record the four-party, t=1 profile")
    _require(keyset.get("fullPreprocessing") is True
             and keyset.get("preloadedFheKey") is False,
             "V1 keyset does not record full preprocessing and fresh DKG")
    _require(keyset.get("upstreamCommit") == UPSTREAM_PIN,
             "V1 keyset uses the wrong Zama KMS revision")

    _require(app.get("version") == VERSION and app.get("status") == "passed",
             "V1 application report is not complete")
    _require(app.get("config") == dict(cfg),
             "V1 application report differs from the campaign config")
    _require(app.get("keys") == dict(keyset),
             "V1 application report differs from the sealed keyset")
    _require(app.get("plaintextInGateway") is False,
             "V1 application report does not deny gateway plaintext")
    cases = _list(app.get("cases"), "application cases")
    _require(app.get("kmsCalls") == len(cases),
             "V1 application KMS-call count differs from its cases")
    case_names = [case.get("name") if isinstance(case, dict) else None for case in cases]
    _require(all(isinstance(name, str) and name for name in case_names)
             and len(case_names) == len(set(case_names)),
             "V1 application case names are invalid or duplicated")

    _require(results.get("classification") == expected_classification,
             "V1 result classification differs from the campaign config")
    _require(results.get("parameters") == cfg.get("parameters"),
             "V1 result parameters differ from the campaign config")
    _require(results.get("setup") == dict(keyset),
             "V1 results differ from the sealed keyset")
    rows = _list(results.get("rows"), "result rows")
    row_names = [row.get("case") if isinstance(row, dict) else None for row in rows]
    _require(row_names == case_names, "V1 result rows differ from application cases")
    for row, case in zip(rows, cases):
        _require(row.get("correct") is True, f"V1 result is not marked correct: {row.get('case')}")
        _require(row.get("output_digest") == case.get("outputDigest"),
                 f"V1 result digest differs from the application case: {row.get('case')}")


def _validate_datasets(repo_root: Path, half: str, state: Mapping[str, Any]) -> list[str]:
    datasets = _object(state.get("datasets"), "state.datasets")
    wanted = {name for name, record in DATASETS.items()
              if half == "both" or record["half"] == half}
    _require(set(datasets) == wanted, "V1 dataset inventory differs from the selected half")
    verified = []
    for name in sorted(wanted):
        _relative_name(name, "dataset path")
        record = _object(datasets[name], f"dataset record {name}")
        expected = DATASETS[name]
        _require(record == {key: expected[key] for key in ("sha256", "source", "conversion")},
                 f"V1 dataset metadata differs from the pinned definition: {name}")
        path = _safe_file(repo_root, name)
        _require(_sha256(path) == expected["sha256"],
                 f"changed or missing V1 source dataset: {name}")
        verified.append(name)
    return verified


def verify(run: Path | str, *, cache_dir: Path | str | None = None,
           repo_root: Path | str | None = None) -> dict[str, Any]:
    """Verify a preserved V1 run and return a compact verification summary."""
    try:
        run_path = Path(run).resolve(strict=True)
    except OSError as error:
        raise LegacyV1SealError(f"V1 run directory is absent: {run}") from error
    _require(run_path.is_dir(), "V1 run path is not a directory")
    module = Path(__file__).resolve().parents[1]
    cache_root = Path(cache_dir).resolve() if cache_dir is not None else module / ".cache"
    repository = Path(repo_root).resolve() if repo_root is not None else module.parent

    seal = _object(_read_json_file(_safe_file(run_path, "seal.json"), "V1 seal"), "V1 seal")
    _require(set(seal) == {"version", "source", "files", "parameters", "classification", "halves"},
             "V1 seal metadata fields are incomplete or unexpected")
    _require(seal.get("version") == VERSION, "seal is not dataset-threshold-campaign-v1")
    source = _validated_digest_map(seal.get("source"), "seal.source")
    _require(REQUIRED_SOURCE_FILES.issubset(source),
             "V1 source manifest omits a critical campaign source")
    files = _validated_digest_map(seal.get("files"), "seal.files")
    _require(REQUIRED_SEALED_FILES.issubset(files),
             "V1 seal omits a critical run artifact")
    expected_inventory = _historical_seal_inventory(run_path)
    _require(set(files) == expected_inventory,
             "V1 seal file inventory differs from the historical sealing rule")
    for name, expected in files.items():
        path = _safe_file(run_path, name)
        _require(_sha256(path) == expected, f"changed or missing V1 artifact: {name}")

    cfg = _object(_read_json_file(_safe_file(run_path, "config/campaign.json"),
                                  "campaign config"), "campaign config")
    state = _object(_read_json_file(_safe_file(run_path, "state.json"), "campaign state"),
                    "campaign state")
    keyset = _object(_read_json_file(_safe_file(run_path, "keyset/ready.json"), "keyset"),
                     "keyset")
    app = _object(_read_json_file(_safe_file(run_path, "reports/application.json"),
                                  "application report"), "application report")
    results = _object(_read_json_file(_safe_file(run_path, "reports/results.json"),
                                      "results report"), "results report")
    _validate_config_and_metadata(run_path, seal, source, cfg, state, keyset, app, results)
    verified_datasets = _validate_datasets(repository, cfg["half"], state)

    cache, cache_digest = _verify_cached_sources(cache_root, source)
    installed_path = _safe_file(run_path, "build-evidence/installed-files.json.gz")
    installed = _read_installed_inventory(installed_path)
    _validate_installed_sources(installed, source, cache)

    return {
        "version": VERSION,
        "status": "verified",
        "run": str(run_path),
        "classification": seal["classification"],
        "parameters": seal["parameters"],
        "halves": seal["halves"],
        "sealedFiles": len(files),
        "sourceFiles": len(source),
        "sourceCacheDigest": cache_digest,
        "sourceCache": str(cache),
        "installedFiles": len(installed),
        "datasets": verified_datasets,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--repo-root", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.run, cache_dir=args.cache_dir, repo_root=args.repo_root),
                     indent=2))


if __name__ == "__main__":
    try:
        main()
    except (LegacyV1SealError, OSError) as error:
        raise SystemExit(str(error))
