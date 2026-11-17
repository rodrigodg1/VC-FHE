#!/usr/bin/env node
/**
 * Real threshold-FHE verdict opening against a running Zama KMS deployment,
 * instrumented for evaluation-grade data collection.
 *
 * Replaces the modeled threshold-opening service of the fhe-pod evaluation:
 * each audit verdict bit (support / dissent) is encrypted as a TFHE `ebool`
 * under the KMS threshold key and opened via the KMS `public-decrypt`
 * gRPC flow, i.e., the real maliciously-secure MPC threshold decryption
 * (Noah's Ark protocol; see zama-ai/kms). End-to-end wall-clock latency is
 * measured per opening, over R repeats with an untimed warmup, and archived
 * with the full deployment parameters parsed from the client TOML.
 *
 * Usage examples (see ../README.md for the full reproduction guide):
 *   node scripts/run-kms-verdict-opening.mjs --kms-repo ~/kms --keygen
 *   node scripts/run-kms-verdict-opening.mjs --kms-repo ~/kms \
 *     --key-id <KEY_ID> --verdicts 1,1,1,0,1,1 --repeats 10
 *   node scripts/run-kms-verdict-opening.mjs --mode docker \
 *     --client-config ./client_threshold_lan.toml --key-id <KEY_ID>
 *   node scripts/run-kms-verdict-opening.mjs --merge   # summary CSV across runs
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const moduleRoot = path.resolve(scriptDir, "..");
const defaultOutDir = path.resolve(moduleRoot, "..", "fhe-pod", "artifacts", "evaluations");

// The default verdict pattern mirrors the pinned regulatory_qoe_compliance
// run (application-layer-20260707T210925Z): three supporting verdicts on the
// honest job, then one dissent and two supports on the corrupted job.
const DEFAULT_VERDICTS = [1, 1, 1, 0, 1, 1];

export function parseArgs(argv) {
  const args = {
    mode: "cargo", // cargo | docker
    kmsRepo: process.env.KMS_REPO ?? null,
    clientConfig: null,
    keyId: null,
    keygen: false,
    insecureTest: false,
    verdicts: DEFAULT_VERDICTS,
    repeats: 10,
    warmup: true,
    numRequests: 1,
    batchSize: 1,
    runDir: null,
    outDir: defaultOutDir,
    merge: false,
    dryRun: false
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === "--mode") args.mode = next();
    else if (a === "--kms-repo") args.kmsRepo = next();
    else if (a === "--client-config") args.clientConfig = next();
    else if (a === "--key-id") args.keyId = next();
    else if (a === "--keygen") args.keygen = true;
    else if (a === "--insecure-test") args.insecureTest = true;
    else if (a === "--verdicts")
      args.verdicts = next()
        .split(",")
        .map((v) => Number.parseInt(v.trim(), 10));
    else if (a === "--repeats" || a === "-r") args.repeats = Number.parseInt(next(), 10);
    else if (a === "--no-warmup") args.warmup = false;
    else if (a === "--num-requests") args.numRequests = Number.parseInt(next(), 10);
    else if (a === "--batch-size") args.batchSize = Number.parseInt(next(), 10);
    else if (a === "--run-dir") args.runDir = next();
    else if (a === "--out-dir") args.outDir = next();
    else if (a === "--merge") args.merge = true;
    else if (a === "--dry-run") args.dryRun = true;
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (args.merge || args.dryRun) return args;
  if (!["cargo", "docker"].includes(args.mode)) throw new Error("--mode must be cargo or docker");
  if (args.mode === "cargo" && !args.kmsRepo) {
    throw new Error("--kms-repo (or KMS_REPO env) is required in cargo mode: path to a zama-ai/kms checkout");
  }
  if (!args.verdicts.every((v) => v === 0 || v === 1)) {
    throw new Error("--verdicts must be a comma-separated list of 0/1 bits");
  }
  if (!Number.isInteger(args.repeats) || args.repeats < 1) {
    throw new Error("--repeats must be an integer >= 1");
  }
  if (!args.clientConfig) {
    args.clientConfig = args.kmsRepo
      ? path.join(args.kmsRepo, "core-client", "config", "client_local_threshold.toml")
      : "/config/client_local_threshold.toml";
  }
  return args;
}

/** Parse the deployment parameters from a kms-core-client TOML config. */
export function parseClientConfig(toml) {
  const get = (key) => {
    const m = toml.match(new RegExp(`^\\s*${key}\\s*=\\s*"?([^"\\n#]+)"?`, "m"));
    return m ? m[1].trim() : null;
  };
  const cores = [...toml.matchAll(/^\s*address\s*=\s*"([^"]+)"/gm)].map((m) => m[1]);
  const numParties = get("num_parties");
  return {
    kmsType: get("kms_type"),
    numParties: numParties ? Number.parseInt(numParties, 10) : cores.length,
    numMajority: Number.parseInt(get("num_majority") ?? "0", 10) || null,
    numReconstruct: Number.parseInt(get("num_reconstruct") ?? "0", 10) || null,
    decryptionMode: get("decryption_mode"),
    fheParams: get("fhe_params"),
    cores
  };
}

/** Normal-approximation summary statistics over latency samples. */
export function latencyStats(samples) {
  const n = samples.length;
  const sorted = [...samples].sort((a, b) => a - b);
  const mean = samples.reduce((a, b) => a + b, 0) / n;
  const variance = n > 1 ? samples.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1) : 0;
  const std = Math.sqrt(variance);
  const ci95 = n > 1 ? 1.96 * (std / Math.sqrt(n)) : 0;
  return {
    samples: n,
    meanMs: round2(mean),
    medianMs: round2(sorted[Math.floor(n / 2)]),
    stdMs: round2(std),
    ci95Ms: round2(ci95),
    minMs: round2(sorted[0]),
    maxMs: round2(sorted[n - 1])
  };
}
const round2 = (x) => Math.round(x * 100) / 100;

/** Build the kms-core-client invocation (documented CLI of zama-ai/kms). */
export function buildClientCommand(args, clientArgs) {
  if (args.mode === "cargo") {
    return {
      command: "cargo",
      argv: ["run", "--release", "--bin", "kms-core-client", "--", "-f", args.clientConfig, ...clientArgs],
      options: { cwd: path.join(args.kmsRepo, "core-client") }
    };
  }
  // docker mode: mount the directory containing the client config.
  const configDir = path.dirname(path.resolve(args.clientConfig));
  const configName = path.basename(args.clientConfig);
  return {
    command: "docker",
    argv: [
      "run", "--rm", "--network", "host",
      "-v", `${configDir}:/config`,
      "ghcr.io/zama-ai/kms/core-client:latest",
      "kms-core-client", "-f", `/config/${configName}`, ...clientArgs
    ],
    options: {}
  };
}

/** Documented public-decrypt invocation for one ebool verdict bit. */
export function verdictDecryptArgs(bit, keyId, { numRequests = 1, batchSize = 1 } = {}) {
  return [
    "public-decrypt", "from-args",
    "--to-encrypt", bit ? "01" : "00",
    "--data-type", "ebool",
    "--key-id", keyId,
    "--num-requests", String(numRequests),
    "--batch-size", String(batchSize)
  ];
}

function runClient(args, clientArgs, label) {
  const { command, argv, options } = buildClientCommand(args, clientArgs);
  const started = process.hrtime.bigint();
  const result = spawnSync(command, argv, { ...options, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${label} failed (exit ${result.status}):\n${result.stderr}\n${result.stdout}`);
  }
  return { stdout: result.stdout, stderr: result.stderr, elapsedMs };
}

export function extractRequestId(stdout) {
  // core-client prints request_id in its JSON-ish output; documented grep:
  //   grep request_id | cut -d'"' -f4
  // i.e. lines of the form: "request_id": "<hex>"
  const m = stdout.match(/["']?request_id["']?\s*[:=]\s*["']([0-9a-fA-Fx]+)["']/);
  return m ? m[1] : (stdout.match(/preproc done\s*-\s*([0-9a-fA-Fx]+)/)?.[1] ?? null);
}

export function keygenCommands(insecureTest = false) {
  return insecureTest
    ? ["insecure-preproc-key-gen", "insecure-key-gen"]
    : ["preproc-key-gen", "key-gen"];
}

export function validateDeployment(deployment, insecureTest = false) {
  if (deployment.kmsType !== "threshold" || deployment.numParties < 4 ||
      !deployment.numMajority || !deployment.numReconstruct) {
    throw new Error("A documented threshold deployment with at least four cores is required");
  }
  const t = deployment.numMajority - 1;
  if (t < 1 || deployment.numParties < 3 * t + 1 || deployment.numReconstruct !== 2 * t + 1) {
    throw new Error("Inconsistent threshold quorums");
  }
  if (!["Default", "Test"].includes(deployment.fheParams) ||
      (deployment.fheParams !== "Default" && !insecureTest)) {
    throw new Error("Secure measurement requires Default parameters; Test requires --insecure-test");
  }
}

function generateKey(args) {
  const [preCommand, keyCommand] = keygenCommands(args.insecureTest);
  console.log(`[keygen] ${preCommand} ...`);
  const pre = runClient(args, [preCommand], preCommand);
  const preprocId = extractRequestId(pre.stdout);
  if (!preprocId) throw new Error(`could not parse preproc request_id from:\n${pre.stdout}`);
  console.log(`[keygen] preproc id: ${preprocId}; ${keyCommand} ...`);
  const kg = runClient(args, [keyCommand, "--preproc-id", preprocId], keyCommand);
  const keyId = extractRequestId(kg.stdout);
  if (!keyId) throw new Error(`could not parse key id from:\n${kg.stdout}`);
  console.log(`[keygen] key id: ${keyId} (preproc ${pre.elapsedMs.toFixed(0)} ms, keygen ${kg.elapsedMs.toFixed(0)} ms)`);
  return { keyId, method: args.insecureTest ? "insecure-test" : "distributed-secure",
    preprocMs: round2(pre.elapsedMs), keygenMs: round2(kg.elapsedMs) };
}

const CSV_COLUMNS = [
  "generatedAt", "mode", "numParties", "threshold_t", "numMajority", "numReconstruct",
  "fheParams", "decryptionMode", "coresList", "verdictsPerRepeat", "repeats",
  "totalOpenings", "meanMs", "medianMs", "stdMs", "ci95Ms", "minMs", "maxMs",
  "keygenMs", "securityClassification", "clientConfig", "sourceRunDir", "artifactFile"
];

function mergeArtifacts(outDir) {
  const files = fs
    .readdirSync(outDir)
    .filter((f) => f.startsWith("kms-threshold-opening-") && f.endsWith(".json") && !f.includes("summary"))
    .sort();
  if (files.length === 0) throw new Error(`No kms-threshold-opening-*.json artifacts in ${outDir}`);
  const rows = files.map((f) => {
    const a = JSON.parse(fs.readFileSync(path.join(outDir, f), "utf8"));
    const d = a.deployment ?? {};
    return {
      generatedAt: a.generatedAt,
      mode: a.mode,
      numParties: d.numParties ?? "",
      threshold_t: d.numMajority ? d.numMajority - 1 : "",
      numMajority: d.numMajority ?? "",
      numReconstruct: d.numReconstruct ?? "",
      fheParams: d.fheParams ?? "",
      decryptionMode: d.decryptionMode ?? "",
      coresList: (d.cores ?? []).join(";"),
      verdictsPerRepeat: a.verdicts?.length ?? "",
      repeats: a.repeats ?? "",
      totalOpenings: a.summary?.samples ?? a.summary?.count ?? "",
      meanMs: a.summary?.meanMs ?? "",
      medianMs: a.summary?.medianMs ?? "",
      stdMs: a.summary?.stdMs ?? "",
      ci95Ms: a.summary?.ci95Ms ?? "",
      minMs: a.summary?.minMs ?? "",
      maxMs: a.summary?.maxMs ?? "",
      keygenMs: a.keygen?.keygenMs ?? "",
      securityClassification: a.securityClassification ?? "unverified-legacy",
      clientConfig: a.clientConfig,
      sourceRunDir: a.sourceRunDir ?? "",
      artifactFile: f
    };
  });
  const csv = [CSV_COLUMNS.join(",")]
    .concat(rows.map((r) => CSV_COLUMNS.map((c) => String(r[c]).replaceAll(",", ";")).join(",")))
    .join("\n");
  const outCsv = path.join(outDir, "kms-threshold-opening-summary.csv");
  fs.writeFileSync(outCsv, `${csv}\n`, "utf8");
  console.log(`Merged ${rows.length} artifacts -> ${outCsv}`);
  for (const r of rows) {
    console.log(
      `n=${r.numParties} (${r.fheParams}/${r.decryptionMode}, ${r.mode}): mean ${r.meanMs} ms +- ${r.ci95Ms} (95% CI), ${r.totalOpenings} openings`
    );
  }
  return outCsv;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.merge) {
    mergeArtifacts(args.outDir);
    return;
  }

  if (args.dryRun) {
    const demo = buildClientCommand(
      { ...args, kmsRepo: args.kmsRepo ?? "<kms-checkout>" },
      verdictDecryptArgs(1, args.keyId ?? "<KEY_ID>")
    );
    console.log(JSON.stringify({ dryRun: true, exampleInvocation: demo, verdicts: args.verdicts, repeats: args.repeats }, null, 2));
    return;
  }

  const deployment = parseClientConfig(fs.readFileSync(args.clientConfig, "utf8"));
  validateDeployment(deployment, args.insecureTest);

  let keygen = null;
  let keyId = args.keyId;
  if (args.keygen) {
    keygen = generateKey(args);
    keyId = keygen.keyId;
  }
  if (!keyId) throw new Error("--key-id is required (or pass --keygen for distributed key generation)");

  if (args.warmup) {
    console.log("[warmup] untimed opening (excluded from statistics; absorbs cargo build / cold caches) ...");
    runClient(args, verdictDecryptArgs(1, keyId), "warmup public-decrypt");
  }

  const openings = [];
  for (let rep = 0; rep < args.repeats; rep += 1) {
    args.verdicts.forEach((bit, index) => {
      const r = runClient(
        args,
        verdictDecryptArgs(bit, keyId, { numRequests: args.numRequests, batchSize: args.batchSize }),
        `public-decrypt repeat[${rep}] verdict[${index}]`
      );
      openings.push({
        repeat: rep,
        index,
        verdictBit: bit,
        wallClockMs: round2(r.elapsedMs)
      });
      console.log(`[repeat ${rep + 1}/${args.repeats}] verdict[${index}]=${bit} -> ${r.elapsedMs.toFixed(0)} ms`);
    });
  }

  const summary = latencyStats(openings.map((o) => o.wallClockMs));
  const artifact = {
    tool: "VC-FHE/threshold-kms run-kms-verdict-opening",
    backend: "zama-ai/kms client-driven threshold decryption measurement",
    securityClassification: args.insecureTest ? "insecure-test"
      : keygen?.method === "distributed-secure" ? "secure-configuration-requires-provenance-review"
      : "external-key-provenance-unverified",
    mode: args.mode,
    clientConfig: args.clientConfig,
    deployment,
    keyId,
    keygen,
    dataType: "ebool (one encrypted verdict bit per audited stage)",
    verdicts: args.verdicts,
    repeats: args.repeats,
    warmupExcluded: args.warmup,
    numRequestsPerOpening: args.numRequests,
    batchSize: args.batchSize,
    sourceRunDir: args.runDir,
    openings,
    summary,
    note:
      "Wall-clock includes client-side encryption, gRPC round trips to all cores, the MPC threshold decryption, and response verification against num_majority matching responses. Measured on the deployment described by `deployment`; latency depends on host resources and inter-node network. CI is a 95% normal approximation across all timed openings.",
    generatedAt: new Date().toISOString()
  };

  fs.mkdirSync(args.outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const outPath = path.join(args.outDir, `kms-threshold-opening-${stamp}.json`);
  fs.writeFileSync(outPath, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
  console.log(`\nWrote ${outPath}`);
  console.log(JSON.stringify(summary, null, 1));
  console.log("Aggregate all runs into a CSV with: node scripts/run-kms-verdict-opening.mjs --merge");
}

const invokedDirectly =
  process.argv[1] && import.meta.url.endsWith(process.argv[1].split(/[\\/]/).pop());
if (invokedDirectly) {
  main();
}
