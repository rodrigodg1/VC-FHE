#!/usr/bin/env python3
"""Compile the protocol proofs from source and audit every theorem's axioms."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
VERSION = "4.19.0"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def without_comments(text: str) -> str:
    """Strip Lean's nested block comments and line comments for the source gate."""
    out, pos, depth = [], 0, 0
    while pos < len(text):
        if text.startswith("/-", pos):
            depth += 1
            out.append("  ")
            pos += 2
        elif depth and text.startswith("-/", pos):
            depth -= 1
            out.append("  ")
            pos += 2
        elif not depth and text.startswith("--", pos):
            end = text.find("\n", pos)
            pos = len(text) if end < 0 else end
        else:
            char = text[pos]
            out.append(char if not depth or char == "\n" else " ")
            pos += 1
    if depth:
        raise ValueError("Unclosed Lean comment")
    return "".join(out)


def sources() -> tuple[dict[str, Path], list[str]]:
    files = {"VCFHE": ROOT / "VCFHE.lean"}
    files.update({f"VCFHE.{p.stem}": p for p in sorted((ROOT / "VCFHE").glob("*.lean"))})
    theorems = []
    for module, path in files.items():
        text = without_comments(path.read_text())
        forbidden = re.search(
            r"\b(?:sorry|sorryAx|native_decide|trustCompiler|skipKernelTC|implemented_by)\b"
            r"|^\s*(?:axiom|unsafe|opaque|set_option|elab|macro|syntax|run_elab)\b"
            r"|\[extern\b", text, re.MULTILINE)
        if forbidden:
            raise ValueError(f"Proof source gate: {path.relative_to(ROOT)}: {forbidden.group().strip()}")
        namespaces = re.findall(r"^namespace\s+(\S+)\s*$", text, re.MULTILINE)
        names = re.findall(r"^theorem\s+(\w+)\b", text, re.MULTILINE)
        if names and len(namespaces) != 1:
            raise ValueError(f"Expected one explicit namespace in {module}")
        theorems.extend(f"{namespaces[0]}.{name}" for name in names)
    if not theorems or len(theorems) != len(set(theorems)):
        raise ValueError("Theorem inventory must be nonempty and unique")
    return files, sorted(theorems)


def source_mapping() -> dict:
    manifest = json.loads((ROOT / "source-manifest.json").read_text())
    for item in manifest["files"]:
        path = ROOT.parent / item["path"]
        if not path.is_file() or digest(path) != item["sha256"]:
            raise ValueError(f"Source correspondence requires review: {item['path']}")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", default=os.environ.get("LEAN", "lean"), help="Lean executable (4.19.0)")
    parser.add_argument("--output", type=Path, help="Save a validation report in this directory")
    args = parser.parse_args()
    lean = shutil.which(args.lean)
    if lean is None:
        raise SystemExit("Install the pinned Lean toolchain or set LEAN to its executable.")
    lean = str(Path(lean).absolute())
    version = subprocess.check_output([lean, "--short-version"], cwd=ROOT, text=True).strip()
    if version != VERSION:
        raise SystemExit(f"Expected Lean {VERSION}; received {version}")
    full_version = subprocess.check_output([lean, "--version"], cwd=ROOT, text=True).strip()
    files, theorems = sources()
    mapped = source_mapping()
    before = {str(path.relative_to(ROOT)): digest(path) for path in files.values()}
    cache = ROOT / ".checked"
    cache.mkdir(exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix="run-", dir=cache))
    env = dict(os.environ, LEAN_PATH=str(build))
    logs, done, visiting = [], set(), set()

    def command(argv: list[str]) -> str:
        result = subprocess.run(argv, cwd=ROOT, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logs.append({"command": [Path(argv[0]).name] + [str(x).replace(str(build), "<fresh-build>") for x in argv[1:]],
                     "returncode": result.returncode, "output": result.stdout})
        if result.returncode or re.search(r"\bwarning:", result.stdout):
            (build / "commands.json").write_text(json.dumps(logs, indent=2) + "\n")
            raise SystemExit(f"Verification stopped:\n{result.stdout}\nLogs: {build}")
        return result.stdout

    def compile_module(module: str) -> None:
        if module in done:
            return
        if module in visiting:
            raise ValueError(f"Import cycle: {module}")
        visiting.add(module)
        path = files[module]
        for dependency in re.findall(r"^import\s+(\S+)", path.read_text(), re.MULTILINE):
            if dependency in files:
                compile_module(dependency)
            elif dependency != "Std":
                raise ValueError(f"Unexpected dependency: {dependency}")
        output = build / (module.replace(".", "/") + ".olean")
        output.parent.mkdir(parents=True, exist_ok=True)
        command([lean, "--trust=0", "-o", str(output), str(path.relative_to(ROOT))])
        done.add(module)
        visiting.remove(module)
        print(f"Verified {module}", flush=True)

    compile_module("VCFHE")
    audit = build / "AxiomAudit.lean"
    audit.write_text("import VCFHE\n" + "\n".join(f"#print axioms {name}" for name in theorems) + "\n")
    audit_text = command([lean, "--trust=0", str(audit)])
    dependencies = {}
    pattern = r"'([^']+)' (?:depends on axioms:\s*\[([^\]]*)\]|does not depend on any axioms)"
    for name, axioms in re.findall(pattern, audit_text):
        used = {item.strip() for item in axioms.split(",") if item.strip()}
        if not used <= ALLOWED_AXIOMS:
            raise ValueError(f"Unexpected axiom dependencies for {name}: {sorted(used)}")
        dependencies[name] = sorted(used)
    if set(dependencies) != set(theorems):
        raise ValueError("Axiom output does not cover the complete theorem inventory")
    statements = build / "Statements.lean"
    statements.write_text("import VCFHE\n" + "\n".join(f"#check @{name}" for name in theorems) + "\n")
    statement_text = command([lean, "--trust=0", str(statements)])
    after = {str(path.relative_to(ROOT)): digest(path) for path in files.values()}
    if before != after or source_mapping() != mapped:
        raise ValueError("Sources changed during verification; re-run on the current sources")
    report = {
        "schema": "vcfhe-lean-validation-v1", "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "lean": full_version, "trust_level": 0, "status": "passed",
        "modules": sorted(done), "theorem_count": len(theorems),
        "theorem_axioms": dependencies, "proof_sources_sha256": after,
        "source_manifest_sha256": digest(ROOT / "source-manifest.json"),
        "checker_sha256": digest(Path(__file__)),
        "mapped_source_count": len(mapped["files"]),
        "scope": "Kernel-checked protocol models with reviewed, hash-pinned source correspondence"
    }
    output = (args.output or build).resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name, content in [("validation.json", json.dumps(report, indent=2) + "\n"),
                          ("commands.json", json.dumps(logs, indent=2) + "\n"),
                          ("axioms.txt", audit_text), ("theorems.txt", statement_text)]:
        (output / name).write_text(content)
    print(f"PASS: {len(theorems)} theorems; {len(done)} modules; Lean --trust=0; standard axioms only")
    print(f"Evidence: {output}")


if __name__ == "__main__":
    main()
