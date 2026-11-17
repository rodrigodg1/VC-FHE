#!/usr/bin/env node
/**
 * run-full-pipeline.mjs
 *
 * Single command that runs the entire PoC pipeline with clear console output:
 *   1. Rust FHE execution + trace generation
 *   2. Solidity contract compilation
 *   3. EVM adversarial regression suite
 *   4. Hardhat dispute demo (deploy, audit, bisection, FHEVM decision, slashing)
 *      — supports N repetitions
 *   5. Evaluation report: JSON + CSV (operations, repetitions, transactions)
 *
 * Usage:
 *   npm run pipeline
 *   npm run pipeline -- --skip-rust --run-dir artifacts/runs/session-...
 *   npm run pipeline -- --auditors 5 --decryptors 4 --manipulated-leaf-index 2
 *   npm run pipeline -- --skip-rust --repetitions 3
 */

import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { latestRunDir, projectRoot } from "./evm-lib.mjs";
import { generateEvaluationReport } from "./evaluation-report.mjs";

const args = process.argv.slice(2);

const config = {
  skipRust: false,
  skipTests: false,
  runDir: null,
  auditors: "3",
  decryptors: "3",
  manipulatedLeafIndex: "4",
  repetitions: 1
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  const next = () => { i++; return args[i]; };
  if (arg === "--skip-rust") config.skipRust = true;
  else if (arg === "--skip-tests") config.skipTests = true;
  else if (arg === "--run-dir") config.runDir = next();
  else if (arg === "--auditors") config.auditors = next();
  else if (arg === "--decryptors") config.decryptors = next();
  else if (arg === "--manipulated-leaf-index") config.manipulatedLeafIndex = next();
  else if (arg === "--repetitions") config.repetitions = Number(next());
  else if (arg === "--help" || arg === "-h") { printHelp(); process.exit(0); }
  else { console.error(`Unknown argument: ${arg}`); process.exit(1); }
}

function printHelp() {
  console.log(`
Usage: npm run pipeline -- [options]

Options:
  --skip-rust                    Reuse existing FHE artifacts (latest or --run-dir)
  --skip-tests                   Skip adversarial EVM regression tests
  --run-dir <path>               FHE artifacts directory to reuse
  --auditors <n>                 Registered auditor pool size (default: 3, min: 3)
  --decryptors <n>               Registered decryptor pool size (default: 3, min: 3)
  --manipulated-leaf-index <n>   Micro-trace leaf to mutate (default: 4)
  --repetitions <n>              Number of Hardhat dispute repetitions (default: 1)
`);
}

// ── Pretty printing ─────────────────────────────────────────────────────

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const MAGENTA = "\x1b[35m";
const WHITE = "\x1b[37m";

function banner(stage, title, subtitle = "") {
  const width = 68;
  const line = "═".repeat(width);
  console.log("");
  console.log(`${CYAN}╔${line}╗${RESET}`);
  console.log(`${CYAN}║${RESET}  ${BOLD}${WHITE}STAGE ${stage}${RESET}  ${BOLD}${title}${RESET}`);
  if (subtitle) {
    console.log(`${CYAN}║${RESET}  ${DIM}${subtitle}${RESET}`);
  }
  console.log(`${CYAN}╚${line}╝${RESET}`);
  console.log("");
}

function summary(label, value, color = WHITE) {
  console.log(`  ${DIM}│${RESET}  ${label.padEnd(32)} ${color}${value}${RESET}`);
}

function sectionDone(label, elapsedMs) {
  const seconds = (elapsedMs / 1000).toFixed(1);
  console.log("");
  console.log(`  ${GREEN}✔ ${label}${RESET}  ${DIM}(${seconds}s)${RESET}`);
}

function sectionFailed(label, elapsedMs) {
  const seconds = (elapsedMs / 1000).toFixed(1);
  console.log("");
  console.log(`  ${RED}✘ ${label}${RESET}  ${DIM}(${seconds}s)${RESET}`);
}

// ── Command runner ──────────────────────────────────────────────────────

function run(command, args, env = {}) {
  return new Promise((resolve, reject) => {
    const resolvedCommand =
      process.platform === "win32" && command === "npm" ? "npm.cmd" : command;
    const child = spawn(resolvedCommand, args, {
      cwd: projectRoot,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32" && resolvedCommand.endsWith(".cmd")
    });
    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) reject(new Error(`Command failed with exit code ${code}`));
      else resolve();
    });
  });
}

// ── Pipeline stages ─────────────────────────────────────────────────────

const pipelineStart = Date.now();
const stages = [];

async function stage(number, title, subtitle, fn) {
  banner(number, title, subtitle);
  const start = Date.now();
  try {
    const result = await fn();
    const elapsed = Date.now() - start;
    sectionDone(title, elapsed);
    stages.push({ number, title, status: "passed", elapsedMs: elapsed });
    return result;
  } catch (err) {
    const elapsed = Date.now() - start;
    sectionFailed(title, elapsed);
    stages.push({ number, title, status: "failed", elapsedMs: elapsed });
    throw err;
  }
}

try {
  // ── Header ──────────────────────────────────────────────────────────
  console.log("");
  console.log(`${BOLD}${MAGENTA}  ┌─────────────────────────────────────────────────────────┐${RESET}`);
  console.log(`${BOLD}${MAGENTA}  │         FHE-PoD Full Pipeline — Single Command          │${RESET}`);
  console.log(`${BOLD}${MAGENTA}  │   Rust FHE → Compile → Dispute → Evaluate → CSV/JSON   │${RESET}`);
  console.log(`${BOLD}${MAGENTA}  └─────────────────────────────────────────────────────────┘${RESET}`);
  console.log("");
  summary("skipRust", config.skipRust);
  summary("skipTests", config.skipTests);
  summary("auditors", config.auditors);
  summary("decryptors", config.decryptors);
  summary("manipulatedLeafIndex", config.manipulatedLeafIndex);
  summary("repetitions", config.repetitions);
  if (config.runDir) summary("runDir", config.runDir);
  console.log("");

  // ── Stage 1: Rust FHE ───────────────────────────────────────────────
  let runDir;

  if (config.skipRust) {
    runDir = config.runDir
      ? path.resolve(projectRoot, config.runDir)
      : await latestRunDir();
    console.log(`${YELLOW}  ⏭  Skipping Rust FHE — reusing: ${runDir}${RESET}`);
    console.log("");
    stages.push({ number: 1, title: "FHE execution (skipped)", status: "skipped", elapsedMs: 0 });
  } else {
    await stage(
      1,
      "FHE execution with tfhe-rs",
      "cargo run -p tfhe-pod-demo  →  generates trace_bundle, micro_trace, proofs, attestation",
      () => run("cargo", ["run", "-p", "tfhe-pod-demo"])
    );
    runDir = await latestRunDir();
  }
  summary("runDir", runDir, CYAN);
  console.log("");

  // ── Stage 2: Compile contracts ──────────────────────────────────────
  await stage(
    2,
    "Compile Solidity contracts",
    "npm run compile:contracts  →  LegacyConfigurableDisputeGame + FHEVM verifier + local runtime (regression mode)",
    () => run("npm", ["run", "compile:contracts"])
  );

  // ── Stage 3: Adversarial EVM regression tests ───────────────────────
  if (config.skipTests) {
    console.log(`${YELLOW}  ⏭  Skipping adversarial EVM regression tests${RESET}`);
    console.log("");
    stages.push({ number: 3, title: "Adversarial EVM regression suite (skipped)", status: "skipped", elapsedMs: 0 });
  } else {
    await stage(
      3,
      "Adversarial EVM regression suite",
      "npm run test:evm  →  optimistic, malicious operator, false challenger, lazy auditor, bond, defender and FHEVM scenarios",
      () => run("npm", ["run", "test:evm"])
    );
  }

  // ── Stage 4: Hardhat dispute demo (with repetitions) ────────────────
  const hardhatResults = [];
  for (let rep = 1; rep <= config.repetitions; rep++) {
    const repLabel = config.repetitions > 1
      ? `Hardhat dispute (${rep}/${config.repetitions})`
      : "Hardhat dispute demo with FHEVM finality";
    const repSubtitle = config.repetitions > 1
      ? `repetition ${rep} of ${config.repetitions}  →  deploy, audit, challenge, bisection, FHEVM, slashing`
      : "npm run demo:hardhat  →  deploy, stake, audit, challenge, bisection, FHEVM decision, slashing";

    await stage(
      config.repetitions > 1 ? `4.${rep}` : 4,
      repLabel,
      repSubtitle,
      () => run("npm", ["run", "demo:hardhat"], {
        FHE_POD_RUN_DIR: runDir,
        DEMO_AUDITOR_COUNT: config.auditors,
        DEMO_DECRYPTOR_COUNT: config.decryptors,
        DEMO_MANIPULATED_LEAF_INDEX: config.manipulatedLeafIndex,
        DEMO_REPETITION: String(rep)
      })
    );

    // Read the result JSON just produced
    const resultPath = path.join(runDir, "hardhat_dispute_result.json");
    const result = JSON.parse(await fs.readFile(resultPath, "utf8"));
    hardhatResults.push(result);
  }

  // ── Stage 5: Generate evaluation report (JSON + CSV) ────────────────
  const evalResult = await stage(
    5,
    "Generate evaluation report (JSON + CSV)",
    "artifacts/evaluations/  →  repetitions.csv, transactions.csv, operations.csv, adversarial-scenarios.csv, report.json",
    async () => {
      return generateEvaluationReport({
        runDir,
        config: {
          auditors: Number(config.auditors),
          decryptors: Number(config.decryptors),
          operators: 2,
          manipulatedLeafIndex: Number(config.manipulatedLeafIndex),
          repetitions: config.repetitions,
          adversarialTests: config.skipTests ? "skipped" : "passed"
        },
        hardhatResults
      });
    }
  );

  // ── Final summary ──────────────────────────────────────────────────
  const totalElapsed = ((Date.now() - pipelineStart) / 1000).toFixed(1);
  console.log("");
  console.log(`${BOLD}${GREEN}╔════════════════════════════════════════════════════════════════════╗${RESET}`);
  console.log(`${BOLD}${GREEN}║                    PIPELINE COMPLETE                              ║${RESET}`);
  console.log(`${BOLD}${GREEN}╚════════════════════════════════════════════════════════════════════╝${RESET}`);
  console.log("");
  for (const s of stages) {
    const icon = s.status === "passed" ? `${GREEN}✔` : s.status === "skipped" ? `${YELLOW}⏭` : `${RED}✘`;
    const time = s.elapsedMs > 0 ? `${DIM}(${(s.elapsedMs / 1000).toFixed(1)}s)${RESET}` : "";
    console.log(`  ${icon} Stage ${s.number}${RESET}  ${s.title}  ${time}`);
  }
  console.log("");
  summary("Total time", `${totalElapsed}s`, GREEN);
  summary("FHE artifacts", runDir, CYAN);
  summary("Dispute result", path.join(runDir, "hardhat_dispute_result.json"), CYAN);
  if (evalResult) {
    console.log("");
    summary("Evaluation JSON", evalResult.evaluationPath, CYAN);
  summary("Repetitions CSV", evalResult.csvPaths.repetitions, CYAN);
  summary("Transactions CSV", evalResult.csvPaths.transactions, CYAN);
  summary("Operations CSV", evalResult.csvPaths.operations, CYAN);
  summary("Adversarial scenarios CSV", evalResult.csvPaths.adversarialScenarios, CYAN);
    console.log("");
    summary("CSV rows: repetitions", evalResult.aggregate.csvRows.repetitions);
  summary("CSV rows: transactions", evalResult.aggregate.csvRows.transactions);
  summary("CSV rows: operations", evalResult.aggregate.csvRows.operations);
  summary("CSV rows: adversarial scenarios", evalResult.aggregate.csvRows.adversarialScenarios);
    summary("All dishonest slashed", evalResult.aggregate.allDishonestOperatorsSlashed, GREEN);
    summary("All honest accepted", evalResult.aggregate.allHonestOperatorsAccepted, GREEN);
  }
  console.log("");
  console.log(`${DIM}  Tip: inspect transactions with:${RESET}`);
  console.log(`${DIM}    cat ${path.join(runDir, "hardhat_dispute_result.json")} | python3 -m json.tool | grep -A5 '"label"'${RESET}`);
  console.log(`${DIM}  Or open the local documentation reader:${RESET}`);
  console.log(`${DIM}    npm run reader:dev${RESET}`);
  console.log("");

} catch (err) {
  const totalElapsed = ((Date.now() - pipelineStart) / 1000).toFixed(1);
  console.log("");
  console.log(`${BOLD}${RED}╔════════════════════════════════════════════════════════════════════╗${RESET}`);
  console.log(`${BOLD}${RED}║                    PIPELINE FAILED                                ║${RESET}`);
  console.log(`${BOLD}${RED}╚════════════════════════════════════════════════════════════════════╝${RESET}`);
  console.log("");
  for (const s of stages) {
    const icon = s.status === "passed" ? `${GREEN}✔` : s.status === "skipped" ? `${YELLOW}⏭` : `${RED}✘`;
    const time = s.elapsedMs > 0 ? `${DIM}(${(s.elapsedMs / 1000).toFixed(1)}s)${RESET}` : "";
    console.log(`  ${icon} Stage ${s.number}${RESET}  ${s.title}  ${time}`);
  }
  console.log("");
  console.log(`  ${RED}Error: ${err.message}${RESET}`);
  console.log(`  ${DIM}Total time: ${totalElapsed}s${RESET}`);
  console.log("");
  process.exit(1);
}
