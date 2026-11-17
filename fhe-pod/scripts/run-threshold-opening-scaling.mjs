#!/usr/bin/env node
/**
 * Threshold-opening scaling analysis (reviewer concern: "threshold decryption
 * introduces network latency and liveness dependencies, which might become a
 * bottleneck as the number of auditors increases").
 *
 * What this measures (real, on the local EVM):
 *   For growing auditor/decryptor pools, the per-task verdict-opening surface
 *   of VerifiableFHEDisputeGame: number and gas of `openVerdict` transactions,
 *   decryptor registrations, and audit submissions. By design the per-task
 *   opening committee is a constant-size sample (DECRYPTOR_SAMPLE_SIZE = 3,
 *   THRESHOLD_SHARES = 2), so opening transactions and gas must remain
 *   constant as the pools grow; this run verifies that claim empirically.
 *
 * What this models (explicit assumption, not a measurement):
 *   Share-network latency. The PoC does not implement a production threshold
 *   FHE decryption protocol; per-share delays d are model parameters. Task
 *   opening latency is reported under two bounds:
 *     parallel:   L = d               (all assigned decryptors act concurrently)
 *     sequential: L = t * d           (worst case, shares strictly serialized)
 *   with t = THRESHOLD_SHARES per audited stage.
 *
 * Usage (from VC-FHE/fhe-pod):
 *   node scripts/run-threshold-opening-scaling.mjs --auditors 4 --decryptors 8
 *   node scripts/run-threshold-opening-scaling.mjs --merge   # summarize all runs
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDir, "..");
const runsDir = path.join(projectRoot, "artifacts", "runs");
const evalDir = path.join(projectRoot, "artifacts", "evaluations");

const WORKLOAD = "regulatory_qoe_compliance";
const MODEL_DELAYS_MS = [50, 100, 200];
const THRESHOLD_SHARES = 2; // contract constant, see VerifiableFHEDisputeGame.sol
const DECRYPTOR_SAMPLE_SIZE = 3; // contract constant

function parseArgs(argv) {
  const args = { auditors: 4, decryptors: 4, merge: false, skipRun: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === "--auditors") args.auditors = Number.parseInt(next(), 10);
    else if (a === "--decryptors") args.decryptors = Number.parseInt(next(), 10);
    else if (a === "--merge") args.merge = true;
    else if (a === "--skip-run") args.skipRun = true;
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (!Number.isInteger(args.auditors) || args.auditors < 3) throw new Error("--auditors must be >= 3");
  if (!Number.isInteger(args.decryptors) || args.decryptors < 3) throw new Error("--decryptors must be >= 3");
  return args;
}

function runEval(auditors, decryptors) {
  return new Promise((resolve, reject) => {
    const command = process.platform === "win32" ? "npm.cmd" : "npm";
    const child = spawn(
      command,
      [
        "run", "eval:applications", "--",
        "--workloads", WORKLOAD,
        "--auditors", String(auditors),
        "--decryptors", String(decryptors)
      ],
      { cwd: projectRoot, env: { ...process.env }, stdio: ["ignore", "inherit", "inherit"], shell: false }
    );
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) reject(new Error(`eval:applications exited ${code}`));
      else resolve();
    });
  });
}

function latestRunDirForWorkload() {
  const entries = fs
    .readdirSync(runsDir)
    .filter((e) => e.includes(`-${WORKLOAD}`))
    .sort();
  if (entries.length === 0) throw new Error(`No run dirs found for ${WORKLOAD}`);
  return path.join(runsDir, entries[entries.length - 1]);
}

function analyzeRun(runDir, auditors, decryptors) {
  const result = JSON.parse(
    fs.readFileSync(path.join(runDir, "hardhat_dispute_result.json"), "utf8")
  );
  const txs = result.transactions ?? [];
  const byLabel = (label) => txs.filter((t) => (t.label ?? "") === label);
  const gasSum = (list) => list.reduce((acc, t) => acc + Number(t.gasUsed ?? 0), 0);

  const open = byLabel("openVerdict");
  const regDec = byLabel("registerDecryptor");
  const regAud = byLabel("registerAuditor");
  const audits = txs.filter((t) => (t.label ?? "").startsWith("submitAudit"));

  const row = {
    workloadId: WORKLOAD,
    runDir: path.basename(runDir),
    auditorPool: auditors,
    decryptorPool: decryptors,
    assignedDecryptorsPerTask: DECRYPTOR_SAMPLE_SIZE,
    openingThreshold: THRESHOLD_SHARES,
    auditSubmissions: audits.length,
    openVerdictTxCount: open.length,
    openVerdictGasTotal: gasSum(open),
    openVerdictGasPerTx: open.length ? Math.round(gasSum(open) / open.length) : 0,
    registerDecryptorTxCount: regDec.length,
    registerDecryptorGasTotal: gasSum(regDec),
    registerAuditorTxCount: regAud.length,
    totalTxCount: txs.length,
    totalGas: gasSum(txs)
  };
  for (const d of MODEL_DELAYS_MS) {
    row[`modeledOpeningLatencyMs_parallel_d${d}`] = d;
    row[`modeledOpeningLatencyMs_sequential_d${d}`] = THRESHOLD_SHARES * d;
  }
  return row;
}

const HEADER_NOTE = {
  claim:
    "Per-task verdict opening uses a constant-size sampled committee (3 assigned decryptors, 2-of-3 opening threshold); on-chain opening transactions and gas are therefore independent of the auditor and decryptor pool sizes.",
  assumption:
    "Share-network latency is a model parameter, not a measurement: the PoC does not implement production threshold-FHE decryption. Modeled task opening latency is d (parallel shares) to t*d (fully serialized shares) per audited stage, with t = 2. Liveness is bounded by the on-chain open-phase deadline; unopened verdicts are treated as lazy and slashed.",
  reproduction:
    "node scripts/run-threshold-opening-scaling.mjs --auditors A --decryptors D (repeat per config); node scripts/run-threshold-opening-scaling.mjs --merge"
};

function writeRow(row) {
  fs.mkdirSync(evalDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const outJson = path.join(evalDir, `threshold-opening-scaling-${stamp}.json`);
  fs.writeFileSync(outJson, `${JSON.stringify({ ...HEADER_NOTE, row }, null, 2)}\n`, "utf8");
  console.log(`Wrote ${outJson}`);
  console.log(JSON.stringify(row, null, 1));
}

function merge() {
  const files = fs
    .readdirSync(evalDir)
    .filter((f) => f.startsWith("threshold-opening-scaling-") && f.endsWith(".json") && !f.includes("summary"))
    .sort();

  // One row per (auditorPool, decryptorPool), keeping the most recent.
  //
  // This directory accumulates: a re-run, an aborted campaign, or a single
  // point measured by hand to validate a fix all leave artifacts behind. Merging
  // the directory verbatim silently emitted the same pool size several times,
  // once per campaign that had ever produced it -- so the summary CSV grew
  // duplicate rows and the scaling figure plotted duplicate points, with no
  // error anywhere. Filenames are ISO timestamps, so sorted order is
  // chronological and the last write for a configuration wins.
  const latest = new Map();
  const superseded = [];
  for (const file of files) {
    const row = JSON.parse(fs.readFileSync(path.join(evalDir, file), "utf8")).row;
    const key = `${row.auditorPool}x${row.decryptorPool}`;
    if (latest.has(key)) superseded.push({ key, file: latest.get(key).file });
    latest.set(key, { file, row });
  }

  const rows = [...latest.values()]
    .sort((a, b) => a.row.auditorPool - b.row.auditorPool || a.row.decryptorPool - b.row.decryptorPool)
    .map((entry) => entry.row);
  if (rows.length === 0) throw new Error("No threshold-opening-scaling artifacts to merge");

  // Say what was dropped. A merge that quietly discards inputs reads as
  // "everything was included" when it was not.
  for (const { key, file } of superseded) {
    console.log(`  superseded ${key}: ${file}`);
  }
  const cols = Object.keys(rows[0]);
  const csv = [cols.join(",")]
    .concat(rows.map((r) => cols.map((c) => r[c]).join(",")))
    .join("\n");
  const outCsv = path.join(evalDir, "threshold-opening-scaling-summary.csv");
  fs.writeFileSync(outCsv, `${csv}\n`, "utf8");
  const outJson = path.join(evalDir, "threshold-opening-scaling-summary.json");
  fs.writeFileSync(outJson, `${JSON.stringify({ ...HEADER_NOTE, rows }, null, 2)}\n`, "utf8");
  console.log(`Merged ${rows.length} rows -> ${outCsv}`);
  for (const r of rows) {
    console.log(
      `pools a=${r.auditorPool} d=${r.decryptorPool}: openVerdict tx=${r.openVerdictTxCount} gas/tx=${r.openVerdictGasPerTx} totalGas=${r.totalGas}`
    );
  }
}

const args = parseArgs(process.argv.slice(2));
if (args.merge) {
  merge();
} else {
  if (!args.skipRun) {
    await runEval(args.auditors, args.decryptors);
  }
  const runDir = latestRunDirForWorkload();
  writeRow(analyzeRun(runDir, args.auditors, args.decryptors));
}
