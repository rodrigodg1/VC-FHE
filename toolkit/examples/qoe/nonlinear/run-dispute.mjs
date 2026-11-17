/**
 * NON-LINEAR QoE examples, end to end, with nothing abstracted.
 *
 * Two real-data workloads (both consumed from the production fixtures that are
 * derived from VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv):
 *
 *   qoe_mos_degradation_alarm   drive-test MOS degradation alarm: quantized
 *                               poor-QoE inference over an encrypted
 *                               throughput measurement (row 3, 3000 kbps).
 *   regulatory_qoe_compliance   regulatory compliance monitor: share of good
 *                               sessions over a real 16-row stride panel vs.
 *                               a 950-permille target.
 *
 * Pipeline stages executed by this runner (all production code paths):
 *   0. toolkit front end: the alarm predicate is classified to the
 *      non-linear pipeline by the production classifier;
 *   1. fixtures: regenerated deterministically from the raw CSV
 *      (fhe-pod fixtures:qoe-mos / fixtures:regulatory), proving provenance;
 *   2. real TFHE: `cargo test -p tfhe-pod-demo --test fhe_correctness` runs
 *      the same workload computations over real tfhe-rs ciphertexts
 *      (skippable with SKIP_FHE_CORRECTNESS=1 when the suite was already run);
 *   3. lowering: the workload is lowered to the 15-opcode micro-ISA by the
 *      production lowering module (via fhe-pod eval:applications);
 *   4. blockchain: `npm run demo:hardhat` (inside eval:applications) deploys
 *      the dispute-game contracts on Hardhat and runs BOTH an honest node
 *      (optimistic acceptance) and a dishonest node whose manipulated leaf is
 *      challenged, bisected, and resolved by the on-chain objective verifier,
 *      slashing the dishonest operator;
 *   5. verification: this runner asserts the on-chain outcome from the
 *      evaluation artifacts (honest accepted; dishonest slashed; challenger
 *      rewarded).
 *
 * Usage:
 *   node nonlinear/run-dispute.mjs qoe_mos_degradation_alarm
 *   node nonlinear/run-dispute.mjs regulatory_qoe_compliance
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const exampleRoot = path.join(here, "..");
const vcfheRoot = path.join(exampleRoot, "..", "..", "..");
const fhePodDir = path.join(vcfheRoot, "fhe-pod");

export const WORKLOADS = {
  qoe_mos_degradation_alarm: {
    fixtureScript: "fixtures:qoe-mos",
    fixtureJson: "scripts/qoe-mos-fixtures.json",
    describe:
      "Drive-test MOS degradation alarm (3000 kbps): predictedPoor = (throughput*100) < (bitrate*headroom)",
    toolkitExpression: "lt(x1 * 100, 216000)",
  },
  regulatory_qoe_compliance: {
    fixtureScript: "fixtures:regulatory",
    fixtureJson: "scripts/regulatory-fixtures.json",
    describe:
      "Regulatory QoE compliance monitor: goodCount*1000 >= n*950 over a real 16-session panel",
    toolkitExpression: null, // aggregation over 16 encrypted indicators; lowered by the production module
  },
};

function sh(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? fhePodDir,
    stdio: "inherit",
    env: { ...process.env, ...(options.env ?? {}) },
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
}

export function latestEvaluation() {
  const p = path.join(fhePodDir, "artifacts", "evaluations", "latest_application_layer_evaluation.json");
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

export function assertWorkloadOutcome(report, workloadId) {
  const row = report.rows.find((r) => r.workloadId === workloadId);
  if (!row) throw new Error(`workload ${workloadId} missing from evaluation report`);
  const checks = {
    honestAccepted: row.honestDecision === 1,
    dishonestSlashed: row.dishonestDecision === 2,
    operatorLeafInvalid: row.operatorValid === false,
    challengerLeafValid: row.challengerValid === true,
    operatorStakeSlashed: BigInt(row.dishonestOperatorSlashWei ?? 0) < 0n,
    challengerRewarded: BigInt(row.challengerRewardWei ?? 0) > 0n,
    bisectionRan: Number(row.bisectionRounds) > 0,
  };
  const failed = Object.entries(checks).filter(([, ok]) => !ok);
  if (failed.length > 0) {
    throw new Error(`${workloadId}: on-chain outcome checks failed: ${failed.map(([k]) => k).join(", ")}`);
  }
  return { row, checks };
}

export async function runWorkload(workloadId, { skipFheCorrectness = false } = {}) {
  const spec = WORKLOADS[workloadId];
  if (!spec) throw new Error(`unknown workload ${workloadId}; expected one of ${Object.keys(WORKLOADS).join(", ")}`);

  console.log(`== Workload: ${workloadId} ==`);
  console.log(`   ${spec.describe}`);

  // Step 0 -- toolkit front end (classification of the alarm predicate).
  if (spec.toolkitExpression) {
    const { inspectExpression } = await import(
      `file://${path.join(vcfheRoot, "toolkit", "src", "index.mjs")}`
    );
    const info = inspectExpression(spec.toolkitExpression);
    console.log(`   toolkit: "${spec.toolkitExpression}" -> pipeline=${info.pipeline}`);
    if (info.pipeline !== "non-linear") throw new Error("expected non-linear classification");
  }

  // Step 1 -- regenerate the fixture from the raw drive-test CSV.
  console.log(`\n== Step 1: regenerate fixture from VC-FHE/data (real CSV) ==`);
  sh("npm", ["run", spec.fixtureScript]);
  const fixture = JSON.parse(fs.readFileSync(path.join(fhePodDir, spec.fixtureJson), "utf8"));
  console.log(`   fixture regenerated: ${spec.fixtureJson} (dataset ${fixture.dataset?.id})`);

  // Step 2 -- real TFHE computation of the workload (tfhe-rs).
  if (skipFheCorrectness || process.env.SKIP_FHE_CORRECTNESS === "1") {
    console.log(`\n== Step 2: real-TFHE correctness suite SKIPPED (SKIP_FHE_CORRECTNESS=1) ==`);
  } else {
    console.log(`\n== Step 2: real-TFHE workload computation (cargo test fhe_correctness) ==`);
    sh("cargo", ["test", "-p", "tfhe-pod-demo", "--test", "fhe_correctness", "--", "--nocapture"]);
  }

  // Steps 3-4 -- production lowering + Hardhat dispute (honest + dishonest).
  console.log(`\n== Steps 3-4: micro-ISA lowering + Hardhat on-chain dispute ==`);
  sh("npm", ["run", "eval:applications", "--", "--workloads", workloadId, "--surface-checks", "skip"]);

  // Step 5 -- assert the on-chain outcome from the evaluation artifacts.
  console.log(`\n== Step 5: verify the on-chain outcome ==`);
  const report = latestEvaluation();
  const { row, checks } = assertWorkloadOutcome(report, workloadId);
  console.log(`   honest node decision      : ${row.honestDecision} (1 = accepted)`);
  console.log(`   dishonest node decision   : ${row.dishonestDecision} (2 = challenger wins, operator slashed)`);
  console.log(`   manipulated leaf/opcode   : ${row.manipulatedLeafIndex} / ${row.manipulatedOpcode}`);
  console.log(`   bisection rounds          : ${row.bisectionRounds}`);
  console.log(`   operator stake delta (wei): ${row.dishonestOperatorSlashWei}`);
  console.log(`   challenger reward (wei)   : ${row.challengerRewardWei}`);
  console.log(`   hardhat result artifact   : ${row.hardhatResultPath}`);

  const artifactDir = path.join(exampleRoot, "artifacts");
  fs.mkdirSync(artifactDir, { recursive: true });
  const outPath = path.join(artifactDir, `nonlinear_${workloadId}_result.json`);
  fs.writeFileSync(outPath, JSON.stringify({ workloadId, checks, row }, null, 2) + "\n");
  console.log(`\nWorkload ${workloadId} verified end to end. Artifact: ${outPath}`);
  return { row, checks };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const workloadId = process.argv[2];
  runWorkload(workloadId).catch((e) => { console.error(e); process.exit(1); });
}
