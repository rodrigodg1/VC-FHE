import test from "node:test";
import assert from "node:assert/strict";
import { buildConfig, deriveThreshold } from "./generate-client-config.mjs";
import {
  buildClientCommand,
  extractRequestId,
  parseArgs,
  verdictDecryptArgs, keygenCommands, validateDeployment, parseClientConfig
} from "./run-kms-verdict-opening.mjs";

test("n=4 config reproduces the upstream client_local_threshold.toml defaults", () => {
  const { toml, summary } = buildConfig({ n: 4 });
  // Values must match zama-ai/kms core-client/config/client_local_threshold.toml
  assert.equal(summary.t, 1);
  assert.equal(summary.numMajority, 2);
  assert.equal(summary.numReconstruct, 3);
  assert.deepEqual(summary.cores, [
    "localhost:50100",
    "localhost:50200",
    "localhost:50300",
    "localhost:50400"
  ]);
  assert.match(toml, /kms_type = "threshold"/);
  assert.match(toml, /num_parties = 4/);
  assert.match(toml, /num_majority = 2/);
  assert.match(toml, /num_reconstruct = 3/);
  assert.match(toml, /decryption_mode = "NoiseFloodSmall"/);
  assert.match(toml, /object_folder = "PUB-p4"/);
  assert.match(toml, /s3_endpoint = "http:\/\/localhost:9000\/kms"/);
  assert.match(toml, /chain_id = 8006/);
});

test("threshold derivation follows n >= 3t+1 and scales with the pool", () => {
  assert.equal(deriveThreshold(4), 1);
  assert.equal(deriveThreshold(6), 1);
  assert.equal(deriveThreshold(7), 2);
  assert.equal(deriveThreshold(10), 3);
  const { summary } = buildConfig({ n: 7 });
  assert.equal(summary.t, 2);
  assert.equal(summary.numMajority, 3);
  assert.equal(summary.numReconstruct, 5);
  assert.equal(summary.cores.length, 7);
});

test("multi-machine core lists are accepted and invalid inputs rejected", () => {
  const { summary } = buildConfig({
    cores: "10.0.0.11:50100,10.0.0.12:50100,10.0.0.13:50100,10.0.0.14:50100",
    s3: "http://10.0.0.11:9000/kms"
  });
  assert.equal(summary.n, 4);
  assert.equal(summary.cores[2], "10.0.0.13:50100");
  assert.equal(summary.s3, "http://10.0.0.11:9000/kms");

  assert.throws(() => buildConfig({ n: 3 }), />= 4/);
  assert.throws(() => buildConfig({ n: 4, threshold: 2 }), /3t\+1/);
  assert.throws(() => buildConfig({ cores: "badentry" }), /host:port/);
  assert.throws(() => buildConfig({ n: 4, fheParams: "Huge" }), /Test/);
});

test("public-decrypt invocation matches the documented kms-core-client CLI", () => {
  assert.deepEqual(verdictDecryptArgs(1, "abc123"), [
    "public-decrypt", "from-args",
    "--to-encrypt", "01",
    "--data-type", "ebool",
    "--key-id", "abc123",
    "--num-requests", "1",
    "--batch-size", "1"
  ]);
  assert.equal(verdictDecryptArgs(0, "k")[3], "00");
});

test("cargo and docker invocations are built as documented", () => {
  const cargoArgs = parseArgs(["--kms-repo", "/workspace/kms", "--key-id", "k1"]);
  const cargoCmd = buildClientCommand(cargoArgs, ["public-decrypt"]);
  assert.equal(cargoCmd.command, "cargo");
  assert.deepEqual(cargoCmd.argv.slice(0, 6), ["run", "--release", "--bin", "kms-core-client", "--", "-f"]);
  assert.ok(cargoCmd.argv[6].endsWith("client_local_threshold.toml"));
  assert.ok(cargoCmd.options.cwd.endsWith("core-client"));

  const dockerArgs = parseArgs(["--mode", "docker", "--client-config", "/tmp/cfg/client.toml", "--key-id", "k1"]);
  const dockerCmd = buildClientCommand(dockerArgs, ["public-decrypt"]);
  assert.equal(dockerCmd.command, "docker");
  assert.ok(dockerCmd.argv.includes("ghcr.io/zama-ai/kms/core-client:latest"));
  assert.ok(dockerCmd.argv.includes("--network"));
  assert.ok(dockerCmd.argv.some((a) => a.endsWith(":/config")));
  assert.ok(dockerCmd.argv.includes("-f"));
});

test("request-id extraction follows the documented output format", () => {
  const sample = 'response { "request_id": "0a1b2c3d4e5f" } done';
  assert.equal(extractRequestId(sample), "0a1b2c3d4e5f");
  assert.equal(extractRequestId("no id here"), null);
});

test("argument validation rejects malformed verdict lists and modes", () => {
  assert.throws(() => parseArgs(["--kms-repo", "/x", "--verdicts", "1,2,0"]), /0\/1 bits/);
  assert.throws(() => parseArgs(["--mode", "ssh"]), /cargo or docker/);
  assert.throws(() => parseArgs([]), /--kms-repo/);
  const ok = parseArgs(["--kms-repo", "/x", "--verdicts", "1,0,1"]);
  assert.deepEqual(ok.verdicts, [1, 0, 1]);
});

test("client TOML parsing extracts the deployment parameters", async () => {
  const { parseClientConfig } = await import("./run-kms-verdict-opening.mjs");
  const { buildConfig } = await import("./generate-client-config.mjs");
  const { toml } = buildConfig({ n: 4 });
  const d = parseClientConfig(toml);
  assert.equal(d.kmsType, "threshold");
  assert.equal(d.numParties, 4);
  assert.equal(d.numMajority, 2);
  assert.equal(d.numReconstruct, 3);
  assert.equal(d.decryptionMode, "NoiseFloodSmall");
  assert.equal(d.fheParams, "Default");
  assert.deepEqual(d.cores, [
    "localhost:50100",
    "localhost:50200",
    "localhost:50300",
    "localhost:50400"
  ]);
});

test("latency statistics are evaluation-grade (mean/median/std/95% CI)", async () => {
  const { latencyStats } = await import("./run-kms-verdict-opening.mjs");
  const s = latencyStats([100, 110, 90, 105, 95]);
  assert.equal(s.samples, 5);
  assert.equal(s.meanMs, 100);
  assert.equal(s.medianMs, 100);
  assert.equal(s.minMs, 90);
  assert.equal(s.maxMs, 110);
  assert.ok(Math.abs(s.stdMs - 7.91) < 0.02); // sample std of the set
  assert.ok(Math.abs(s.ci95Ms - 1.96 * (s.stdMs / Math.sqrt(5))) < 0.02);
  const single = latencyStats([42]);
  assert.equal(single.stdMs, 0);
  assert.equal(single.ci95Ms, 0);
});

test("repeats and merge/dry-run argument handling", () => {
  const r = parseArgs(["--kms-repo", "/x", "--repeats", "10"]);
  assert.equal(r.repeats, 10);
  assert.equal(r.warmup, true);
  const nw = parseArgs(["--kms-repo", "/x", "--no-warmup", "-r", "3"]);
  assert.equal(nw.warmup, false);
  assert.equal(nw.repeats, 3);
  assert.throws(() => parseArgs(["--kms-repo", "/x", "--repeats", "0"]), />= 1/);
  // merge and dry-run skip deployment validation entirely
  assert.equal(parseArgs(["--merge"]).merge, true);
  assert.equal(parseArgs(["--dry-run"]).dryRun, true);
});


test("secure KMS setup never silently chooses test parameters or dealer keygen", () => {
  const { toml } = buildConfig({ n: 4 });
  validateDeployment(parseClientConfig(toml));
  assert.deepEqual(keygenCommands(), ["preproc-key-gen", "key-gen"]);
  assert.deepEqual(keygenCommands(true), ["insecure-preproc-key-gen", "insecure-key-gen"]);
  const insecure = parseClientConfig(buildConfig({ n: 4, fheParams: "Test" }).toml);
  assert.throws(() => validateDeployment(insecure), /insecure-test/);
  validateDeployment(insecure, true);
  assert.throws(() => validateDeployment({ ...insecure, kmsType: "centralized" }, true), /threshold/);
  assert.throws(() => validateDeployment({ ...insecure, numReconstruct: 2 }, true), /quorums/);
  assert.equal(extractRequestId("preproc done - 0abc123"), "0abc123");
});
