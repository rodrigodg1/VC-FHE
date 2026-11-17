#!/usr/bin/env python3
"""Bounded four-party Zama KMS feasibility test, isolated from evaluation evidence."""
import argparse
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import shutil
import signal
import subprocess
import time
import importlib.util
import secrets

PIN = "986537258d8c0348f497b1860ccf63252bc238f3"
TEST = "core-client/tests/integration/integration_test.rs"
CLIENT_MANIFEST = "core-client/Cargo.toml"
ENDPOINT = "core/service/src/engine/threshold/endpoint.rs"
ROOT = Path(__file__).resolve().parents[1]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True, help="isolated v0.13.20 checkout")
    p.add_argument("--out", type=Path, required=True, help="fresh JSON report path")
    p.add_argument("--compile-only", action="store_true")
    p.add_argument("--scenario", choices=("pilot", "compatible", "integrated"), default="pilot",
                   help="compatible exercises actual FHE, grouped binding/conversion and recipient threshold decryption")
    p.add_argument("--fhe-params", choices=("Test", "Default"), default="Test",
                   help="Test is insecure; Default requests upstream production FHE parameters")
    p.add_argument("--allow-insecure-test", action="store_true")
    p.add_argument("--max-rss-gib", type=float, default=6)
    p.add_argument("--min-free-gib", type=float, default=2)
    p.add_argument("--build-timeout", type=int, default=3600)
    p.add_argument("--run-timeout", type=int, default=1200)
    p.add_argument("--max-polls", type=int, default=10000, help="upstream response-poll retry limit")
    p.add_argument("--kms-threads", type=int, default=4,
                   help="Rayon workers for KMS setup/decryption; public replay workers remain single-threaded")
    a = p.parse_args()
    if a.scenario == "integrated" and a.fhe_params == "Test" and not a.allow_insecure_test:
        p.error("integrated Test requires --allow-insecure-test; no confidentiality claim is supported")
    if any(not math.isfinite(x) or x <= 0 for x in (a.max_rss_gib, a.min_free_gib)):
        p.error("resource limits must be finite positive numbers")
    if a.build_timeout <= 0 or a.run_timeout <= 0 or a.max_polls <= 0:
        p.error("timeouts and polling limit must be positive")
    if not 1 <= a.kms_threads <= (os.cpu_count() or 1):
        p.error("KMS thread count must be positive and no greater than the host CPU count")
    source, out = a.source.resolve(), a.out.resolve()
    if out.exists():
        p.error("report exists; preserve it and select a new output path")
    out.parent.mkdir(parents=True, exist_ok=True)
    label = "Test-INSECURE" if a.fhe_params == "Test" else "Default"
    report = {"status":"preparing", "classification":"isolated-upstream-functional-pilot",
              "upstreamCommit":PIN, "evaluationIntegration":False, "fheParameters":label,
              "host":{"system":platform.system(), "release":platform.release(), "machine":platform.machine()},
              "guards":{"maxRssGiB":a.max_rss_gib, "minFreeGiB":a.min_free_gib,
                        "buildTimeoutSeconds":a.build_timeout, "runTimeoutSeconds":a.run_timeout},
              "initialFreeDiskBytes":shutil.disk_usage(out.parent).free,
              "maxClientPollIterations":a.max_polls,
              "kmsRayonThreads":a.kms_threads, "publicReplayRayonThreads":1,
              "source":str(source), "stages":[], "scriptSha256":sha(Path(__file__).read_bytes())}
    save = lambda: out.write_text(json.dumps(report, indent=2))
    env = dict(os.environ)
    # The diagnostic client's environment overrides its TOML. Keep the exact
    # recorded parameter/quorum/endpoint configuration, without logging values.
    for name in list(env):
        if name.startswith("CORE_CLIENT_"):
            del env[name]
    env["PATH"] = "/opt/homebrew/bin:" + env.get("PATH", "")
    env.update(CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0", RUST_LOG="warn", KMS_TEST_SHARED_MATERIAL="0")
    env["CARGO_TARGET_DIR"] = str(ROOT / "target/native-v01320")
    if Path("/opt/homebrew/opt/openssl@3").is_dir():
        env["OPENSSL_DIR"] = "/opt/homebrew/opt/openssl@3"
    detail = out.with_suffix(".detail.json")
    env["TOPS_KMS_PILOT_DETAIL"] = str(detail)
    env["TOPS_KMS_PILOT_PARAMS"] = a.fhe_params
    env["TOPS_KMS_PILOT_MAX_POLLS"] = str(a.max_polls)
    env["TOPS_KMS_BINDING_SCRIPT"] = str(ROOT / "scripts/compatible-binding.cjs")
    env["TOPS_KMS_LINEAR_CWD"] = str(ROOT.parent / "BN254-Signatures")
    # Single-threaded byte replay is local to the public worker subprocesses.
    # Applying it globally also serializes unrelated MPC setup work.
    env["RAYON_NUM_THREADS"] = str(a.kms_threads)
    report["scenario"] = a.scenario
    if platform.system() == "Darwin":
        report["host"]["physicalRamBytes"] = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"]))
        report["host"]["cpu"] = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args])
    def terminate(child):
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
    def run(label, command, timeout):
        logfile = out.with_suffix("." + label + ".log")
        item = {"stage":label, "command":command, "log":str(logfile),
                "sampledProcessGroupRssPeakBytes":0, "rssSamplingSeconds":1}
        report["stages"].append(item)
        if shutil.disk_usage(out.parent).free < a.min_free_gib * 2**30:
            raise RuntimeError("resource guard: insufficient free disk before " + label)
        start = time.monotonic()
        with logfile.open("x") as log:
            child = subprocess.Popen(command, cwd=source, env=env, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while child.poll() is None:
                    listing = subprocess.check_output(["ps", "-axo", "pgid=,rss="], text=True)
                    rss = sum(int(fields[1])*1024 for line in listing.splitlines()
                              if len(fields := line.split()) == 2 and int(fields[0]) == child.pid)
                    item["sampledProcessGroupRssPeakBytes"] = max(item["sampledProcessGroupRssPeakBytes"], rss)
                    if rss > a.max_rss_gib * 2**30:
                        raise RuntimeError("resource guard: configured RSS limit exceeded")
                    if shutil.disk_usage(out.parent).free < a.min_free_gib * 2**30:
                        raise RuntimeError("resource guard: configured disk reserve reached")
                    if time.monotonic() - start > timeout:
                        raise RuntimeError("configured timeout reached in " + label)
                    save()
                    time.sleep(1)
                item["exitCode"] = child.returncode
            finally:
                if child.poll() is None:
                    terminate(child)
                item["seconds"] = time.monotonic() - start
                item["logSha256"] = sha(logfile.read_bytes())
                save()
        if item["exitCode"]:
            raise RuntimeError(label + " failed; see " + str(logfile))
        return logfile
    try:
        if git("rev-parse", "HEAD").decode().strip() != PIN:
            raise ValueError("wrong upstream revision")
        changed = git("diff", "HEAD", "--name-only").decode().splitlines()
        if set(changed) - {TEST, CLIENT_MANIFEST, "Cargo.lock", ENDPOINT}:
            raise ValueError("upstream sources have unrelated modifications")
        original = git("show", PIN + ":" + TEST)
        legacy_payload = (ROOT / "patches/native-four-party-pilot.rs").read_bytes()
        inputs = {
            "fhe": ROOT / "src/compatible_fhe.rs",
            "microIsa": ROOT.parent / "fhe-pod/crates/tfhe-pod-demo/src/micro_isa.rs",
            "integration": ROOT / "patches/compatible-four-party.rs",
            "recipientValidation": ROOT / "src/recipient_validation.rs",
            "binding": ROOT / "scripts/compatible-binding.cjs",
            "contract": ROOT / "contracts/GroupedLinearVerification.sol",
            "baseContract": ROOT.parent / "BN254-Signatures/contract/MKLHS-Verification.sol",
            "bindingLibrary": ROOT.parent / "BN254-Signatures/scripts/mklhs-lib.js",
        }
        integrated = a.scenario == "integrated"
        endpoint = git("show", PIN + ":" + ENDPOINT)
        if integrated:
            spec = importlib.util.spec_from_file_location("kms_profile", ROOT / "scripts/kms-profile-build.py")
            profile = importlib.util.module_from_spec(spec); spec.loader.exec_module(profile)
            inputs["integration"] = ROOT / "patches/integrated-four-party.rs"
            inputs.update(circuitBridge=ROOT / "src/kms_circuit_bridge.rs",
                          circuit=ROOT.parent / "fhe-pod/crates/tfhe-pod-demo/src/bin/circuit-executor.rs",
                          profileBuilder=ROOT / "scripts/kms-profile-build.py",
                          publicWorker=ROOT / "scripts/kms-public-worker.mjs")
            driver = ROOT / "scripts/integrated-driver.mjs"
            if not a.compile_only:
                inputs["applicationDriver"] = driver
                for item in (ROOT / "scripts").glob("kms-*.mjs"):
                    inputs["adapter:" + item.name] = item
                inputs["recipientPolicy"] = ROOT / "scripts/recipient-output-policy.mjs"
            env["TOPS_KMS_GATEWAY_TOKEN"] = secrets.token_hex(32)
            env["TOPS_KMS_INTEGRATED_DRIVER"] = str(driver)
            runtime = out.with_suffix(".runtime")
            profile.build_runtime(runtime)
            env["TOPS_KMS_RUNTIME"] = str(runtime)
            for item in (ROOT.parent / "fhe-pod/scripts").glob("*.mjs"):
                if (runtime / "scripts" / item.name).exists(): inputs["canonical:" + item.name] = item
            report["runtime"] = str(runtime)
            report["fixedFFT"] = "experimental-force_fft_algo_dif4"
            report["evaluationIntegration"] = True
            report["classification"] = "two-path-threshold-functional-integration"
            report["securityEvidence"] = "insecure functional test" if a.fhe_params == "Test" else "secure parameters; same-host test topology"
            for item in (ROOT.parent / "fhe-pod/contracts/src").rglob("*.sol"):
                inputs["contract:" + str(item.relative_to(ROOT.parent / "fhe-pod/contracts/src"))] = item
            for name, directory in (("linear", "BN254-Signatures"), ("nonlinear", "fhe-pod")):
                inputs[name + "PackageLock"] = ROOT.parent / directory / "package-lock.json"
            report["nodeVersion"] = subprocess.check_output(["node", "--version"], env=env, text=True).strip()
        compatible_payload = (b"\nmod tops_compatible_fhe {\n" + inputs["fhe"].read_bytes() + b"\n}\n"
                              + b"mod tops_micro_isa {\n" + inputs["microIsa"].read_bytes() + b"\n}\n"
                              + b"mod tops_recipient_validation {\n" + inputs["recipientValidation"].read_bytes() + b"\n}\n"
                              + inputs["integration"].read_bytes())
        if integrated:
            compatible_payload = (b"\nmod tops_compatible_fhe {\n" + inputs["fhe"].read_bytes() + b"\n}\n"
                + b"mod tops_micro_isa {\n" + inputs["microIsa"].read_bytes() + b"\n}\n"
                + b"mod tops_recipient_validation {\n" + inputs["recipientValidation"].read_bytes() + b"\n}\n"
                + b"mod tops_kms_circuit {\n" + profile.circuit_source().encode() + b"\n}\n"
                + b"mod tops_kms_circuit_bridge {\n" + inputs["circuitBridge"].read_bytes() + b"\n}\n"
                + inputs["integration"].read_bytes())
        payload = legacy_payload if a.scenario == "pilot" else compatible_payload
        instrumented = original + b"\n" + payload
        manifest = git("show", PIN + ":" + CLIENT_MANIFEST)
        marker = b"serial_test.workspace = true\n"
        if manifest.count(marker) != 1:
            raise ValueError("unexpected pinned test-dependency layout")
        instrumented_manifest = manifest.replace(marker, b"serde_json.workspace = true\n" + (b"rayon.workspace = true\n" if integrated else b"") + marker)
        lock = git("show", PIN + ":Cargo.lock")
        package_start = lock.index(b'[[package]]\nname = "kms-core-client"')
        package_end = lock.index(b'[[package]]', package_start + 1)
        package = lock[package_start:package_end]
        marker = b' "serde",\n'
        if package.count(marker) != 1 or b' "serde_json",\n' in package:
            raise ValueError("unexpected pinned client lockfile layout")
        instrumented_lock = (lock[:package_start] + package.replace(marker, marker + b' "serde_json",\n' + (b' "rayon",\n' if integrated else b""))
                             + lock[package_end:])
        # JSON reporting is test-only. Use the already locked workspace crate;
        # no cryptographic code or dependency version is changed.
        edits = {TEST:(original, instrumented), CLIENT_MANIFEST:(manifest, instrumented_manifest),
                 "Cargo.lock":(lock, instrumented_lock),
                 ENDPOINT:(endpoint, profile.ingress_source(endpoint.decode()).encode() if integrated else endpoint)}
        previous_manifest = source / ".tops-instrumentation.json"
        previous = json.loads(previous_manifest.read_text()) if previous_manifest.exists() else {}
        for name, (before, after) in edits.items():
            current = (source / name).read_bytes()
            allowed = (before, after, original + b"\n" + legacy_payload) if name == TEST else (before, after)
            if current not in allowed and sha(current) != previous.get(name):
                raise ValueError(name + " differs from the pinned source/known pilot")
        for name, (_, after) in edits.items():
            if (source / name).read_bytes() != after:
                (source / name).write_bytes(after)
        report["instrumentation"] = {name:{"upstreamSha256":sha(before), "pilotSha256":sha(after)}
                                     for name, (before, after) in edits.items()}
        previous_manifest.write_text(json.dumps({name:sha(after) for name, (_, after) in edits.items()}))
        if a.scenario != "pilot":
            report["sourceClosure"] = {name:{"path":str(p),"sha256":sha(p.read_bytes())} for name,p in inputs.items()}
        report.update(pilotSha256=sha(payload), instrumentedTestSha256=sha(instrumented),
                      cargoLockSha256=sha((source / "Cargo.lock").read_bytes()),
                      rustc=subprocess.check_output(["rustc", "+1.94.0", "--version"], env=env, text=True).strip())
        report["status"] = "building"
        save()
        log = run("build", ["cargo", "+1.94.0", "test", "--locked", "--offline",
                  "-p", "kms-core-client", "--test", "integration_test", "--features", "threshold_tests,tfhe/experimental-force_fft_algo_dif4" if integrated else "threshold_tests",
                  "--profile", "release-lto-off", "--no-run", "--message-format=json-render-diagnostics"], a.build_timeout)
        executables = []
        for line in log.read_text().splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == "integration_test" and row.get("executable"):
                executables.append(Path(row["executable"]))
        if len(set(executables)) != 1:
            raise ValueError("expected one compiled integration-test executable")
        binary = executables[0]
        # Preserve the exact executable outside the mutable Cargo target tree.
        # This directory is local raw evidence, excluded from Git.
        binary_dir = out.with_suffix(".native-bin")
        binary_dir.mkdir()
        saved_binary = binary_dir / "integration-test"
        shutil.copy2(binary, saved_binary)
        report["buildTargetExecutable"] = str(binary)
        binary = saved_binary
        report.update(binary=str(binary), binarySha256=sha(binary.read_bytes()))
        if not a.compile_only:
            report["status"] = "running"
            test_name = {"pilot":"tops_local_four_party_pilot", "compatible":"tops_compatible_four_party", "integrated":"tops_integrated_four_party"}[a.scenario]
            run("test", [str(binary), test_name, "--exact", "--nocapture", "--test-threads=1"], a.run_timeout)
            result = json.loads(detail.read_text())
            if result.get("status") != "passed" or result.get("fheParameters") != label:
                raise ValueError("missing or invalid pilot result")
            report.update(result=result, detailSha256=sha(detail.read_bytes()))
            if a.scenario == "pilot":
                ciphertext = detail.with_suffix(".cipher.bin")
                report.update(ciphertextFile=str(ciphertext), ciphertextSha256=sha(ciphertext.read_bytes()))
            else:
                report["publicArtifactHashes"] = {str(p.relative_to(detail.parent)):sha(p.read_bytes())
                    for p in detail.with_suffix(".public").rglob("*") if p.is_file()}
        for item in report.get("sourceClosure", {}).values():
            if sha(Path(item["path"]).read_bytes()) != item["sha256"]:
                raise ValueError("component source changed during execution")
        if sha(binary.read_bytes()) != report["binarySha256"]:
            raise ValueError("component executable changed during execution")
        report["status"] = "compiled-only" if a.compile_only else "passed"
    except KeyboardInterrupt:
        report.update(status="interrupted", error="interrupted before completion; not a passing run")
        raise
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        save()

if __name__ == "__main__":
    main()
