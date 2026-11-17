#!/usr/bin/env python3
"""Index/verify retained raw canonical artifacts without modifying those files."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path


def digest(file):
    h = hashlib.sha256()
    with file.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def paths(root):
    result = []
    for name in ("bin", "fixtures"):
        directory = root / name
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(f"missing or linked raw directory: {directory}")
        for file in directory.rglob("*"):
            if file.is_symlink():
                raise ValueError(f"symlink is not a portable artifact: {file}")
            if file.is_file():
                result.append(file)
    return sorted(result)


def inventory(root):
    return [{"path": p.relative_to(root).as_posix(), "bytes": p.stat().st_size,
             "sha256": digest(p)} for p in paths(root)]


def create(root):
    rows = inventory(root)
    encoded = json.dumps({"schema": "vcfhe-raw-files-v1", "files": rows},
                         sort_keys=True, separators=(",", ":")).encode()
    packed = gzip.compress(encoded, compresslevel=9, mtime=0)
    index = root / "raw-files.json.gz"
    summary = root / "raw-files-summary.json"
    # Do not replace an existing inventory with a new one after an unnoticed
    # raw-file change. Verification, or an explicitly new campaign, is required.
    if index.exists() or summary.exists():
        raise ValueError("inventory already exists; use verify or a new campaign")
    data = {"schema": "vcfhe-raw-inventory-v1", "run": root.name,
            "files": len(rows), "bytes": sum(r["bytes"] for r in rows),
            "inventory": index.name, "inventorySha256": hashlib.sha256(packed).hexdigest(),
            "contentSha256": hashlib.sha256(encoded).hexdigest(),
            "rawDirectories": ["bin", "fixtures"],
            "storage": "retained locally; not included in Git",
            "archiveLocation": None,
            "scope": "file-preservation index; not a new measurement or a security proof"}
    with index.open("xb") as f:
        f.write(packed)
    with summary.open("x") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(json.dumps(data, indent=2))


def verify(root):
    summary = json.loads((root / "raw-files-summary.json").read_text())
    if summary.get("schema") != "vcfhe-raw-inventory-v1" or summary.get("inventory") != "raw-files.json.gz":
        raise ValueError("unknown inventory format")
    packed = (root / "raw-files.json.gz").read_bytes()
    if hashlib.sha256(packed).hexdigest() != summary["inventorySha256"]:
        raise ValueError("compressed inventory digest differs")
    encoded = gzip.decompress(packed)
    if hashlib.sha256(encoded).hexdigest() != summary["contentSha256"]:
        raise ValueError("inventory content digest differs")
    data = json.loads(encoded)
    if data.get("schema") != "vcfhe-raw-files-v1":
        raise ValueError("unknown file inventory format")
    actual = inventory(root)
    if actual != data["files"]:
        old = {r["path"]: r for r in data["files"]}
        new = {r["path"]: r for r in actual}
        differences = sorted(p for p in old.keys() | new.keys() if old.get(p) != new.get(p))
        raise ValueError(f"raw evidence differs ({len(differences)} files): {differences[:8]}")
    if summary["files"] != len(actual) or summary["bytes"] != sum(r["bytes"] for r in actual):
        raise ValueError("inventory totals differ")
    print(f"Verified {len(actual)} raw files; every path, size and SHA-256 matches.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "verify"))
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    root = args.run_directory.resolve(strict=True)
    try:
        {"create": create, "verify": verify}[args.command](root)
    except (ValueError, KeyError, FileNotFoundError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
