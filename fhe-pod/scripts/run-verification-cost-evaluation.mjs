#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { ethers } from "ethers";
import {
  buildMerkleTree,
  projectRoot,
  writeJson
} from "./evm-lib.mjs";
import { OPCODES, checkWitness, assertTraceSemantics } from "./micro-isa.mjs";
import {
  EVALUATION_SCHEMA_VERSION,
  collectRunContext,
  contextColumns,
  repoRelative,
  requireChain
} from "./run-context.mjs";

const startedAt = new Date();
const evaluationId = `verification-cost-${startedAt
  .toISOString()
  .replace(/[-:]/g, "")
  .replace(/\.\d{3}Z$/, "Z")}`;
const evaluationsDir = path.join(projectRoot, "artifacts", "evaluations");
const runsDir = path.join(projectRoot, "artifacts", "runs");
const config = parseArgs(process.argv.slice(2));

function parseArgs(args) {
  const parsed = {
    auditors: readInteger(process.env.COST_EVAL_AUDITORS, 4, "COST_EVAL_AUDITORS", { min: 3 }),
    decryptors: readInteger(process.env.COST_EVAL_DECRYPTORS, 4, "COST_EVAL_DECRYPTORS", { min: 3 }),
    scaleSizes: parseIntegerList(process.env.COST_EVAL_SCALE_SIZES, [8, 16, 32, 64], "COST_EVAL_SCALE_SIZES"),
    granularitySemanticOps: readInteger(process.env.COST_EVAL_GRANULARITY_SEMANTIC_OPS, 64, "COST_EVAL_GRANULARITY_SEMANTIC_OPS", { min: 8 }),
    granularityGroupSizes: parseIntegerList(process.env.COST_EVAL_GRANULARITY_GROUP_SIZES, [1, 2, 4, 8], "COST_EVAL_GRANULARITY_GROUP_SIZES"),
    manipulatedLeafIndex: null,
    pObservation: readNumber(process.env.COST_EVAL_P_OBSERVATION, 0.95, "COST_EVAL_P_OBSERVATION", { min: 0, max: 1 }),
    pLive: readNumber(process.env.COST_EVAL_P_LIVE, 0.98, "COST_EVAL_P_LIVE", { min: 0, max: 1 })
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = () => {
      index += 1;
      if (index >= args.length) throw new Error(`${arg} requires a value`);
      return args[index];
    };

    if (arg === "--auditors") {
      parsed.auditors = readInteger(next(), parsed.auditors, arg, { min: 3 });
    } else if (arg === "--decryptors") {
      parsed.decryptors = readInteger(next(), parsed.decryptors, arg, { min: 3 });
    } else if (arg === "--scale-sizes") {
      parsed.scaleSizes = parseIntegerList(next(), parsed.scaleSizes, arg);
    } else if (arg === "--granularity-semantic-ops") {
      parsed.granularitySemanticOps = readInteger(next(), parsed.granularitySemanticOps, arg, { min: 8 });
    } else if (arg === "--granularity-group-sizes") {
      parsed.granularityGroupSizes = parseIntegerList(next(), parsed.granularityGroupSizes, arg);
    } else if (arg === "--manipulated-leaf-index") {
      parsed.manipulatedLeafIndex = readInteger(next(), 0, arg, { min: 0 });
    } else if (arg === "--p-observation") {
      parsed.pObservation = readNumber(next(), parsed.pObservation, arg, { min: 0, max: 1 });
    } else if (arg === "--p-live") {
      parsed.pLive = readNumber(next(), parsed.pLive, arg, { min: 0, max: 1 });
    } else if (arg === "--help" || arg === "-h") {
      printUsageAndExit();
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  validatePowerOfTwoList(parsed.scaleSizes, "--scale-sizes");
  validatePowerOfTwo(parsed.granularitySemanticOps, "--granularity-semantic-ops");
  for (const groupSize of parsed.granularityGroupSizes) {
    if (parsed.granularitySemanticOps % groupSize !== 0) {
      throw new Error(`granularity group size ${groupSize} must divide ${parsed.granularitySemanticOps}`);
    }
    validatePowerOfTwo(parsed.granularitySemanticOps / groupSize, `leaf count for group size ${groupSize}`);
  }
  return parsed;
}

function readInteger(raw, fallback, label, { min = 0 } = {}) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${label} must be an integer >= ${min}; received ${raw}`);
  }
  return value;
}

function readNumber(raw, fallback, label, { min = -Infinity, max = Infinity } = {}) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const value = Number.parseFloat(raw);
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new Error(`${label} must be a number in [${min}, ${max}]; received ${raw}`);
  }
  return value;
}

function parseIntegerList(raw, fallback, label) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const values = String(raw)
    .split(",")
    .map((value) => Number.parseInt(value.trim(), 10))
    .filter((value) => Number.isInteger(value));
  if (values.length === 0) {
    throw new Error(`${label} must contain at least one integer`);
  }
  return values;
}

function validatePowerOfTwo(value, label) {
  if (value <= 0 || (value & (value - 1)) !== 0) {
    throw new Error(`${label} must be a positive power of two; received ${value}`);
  }
}

function validatePowerOfTwoList(values, label) {
  for (const value of values) validatePowerOfTwo(value, label);
}

function printUsageAndExit() {
  console.log(`Usage:
  npm run eval:costs -- [options]

Options:
  --auditors <n>                       Auditor pool size, minimum 3, default 4
  --decryptors <n>                     Threshold-opening pool size, minimum 3, default 4
  --scale-sizes <csv>                  Power-of-two leaf counts, default 8,16,32,64
  --granularity-semantic-ops <n>       Total synthetic semantic ops, default 64
  --granularity-group-sizes <csv>      Group sizes for coarse leaves, default 1,2,4,8
  --manipulated-leaf-index <n>         Override corrupted leaf index for all traces
  --p-observation <p>                  Accountability model observation probability, default 0.95
  --p-live <p>                         Accountability model dispute liveness probability, default 0.98`);
  process.exit(0);
}

function csvCell(value) {
  if (value === undefined || value === null) return "";
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  if (/[",\n\r]/.test(text)) return `"${text.replaceAll('"', '""')}"`;
  return text;
}

async function writeCsv(filePath, rows, columns) {
  const header = columns.join(",");
  const body = rows.map((row) => columns.map((column) => csvCell(row[column])).join(","));
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, [header, ...body].join("\n") + "\n");
}

function resolveCommand(command) {
  if (process.platform === "win32" && command === "npm") return "npm.cmd";
  return command;
}

function printTitle(title) {
  console.log("");
  console.log("============================================================");
  console.log(title);
  console.log("============================================================");
}

function printStep(title, details = []) {
  console.log("");
  console.log(title);
  for (const detail of details) console.log(`  - ${detail}`);
}

/**
 * Builds one synthetic trace leaf for the cost sweeps.
 *
 * The opcode table and the validity relation come from `scripts/micro-isa.mjs`,
 * the same module the lowering engine uses, so this harness can no longer emit
 * an opcode number or an arithmetic claim that the on-chain verifier would
 * reject. Before this change the harness carried a private six-entry opcode map
 * that could silently drift from the contract.
 */
function leaf(leafIndex, opcodeName, lhs, rhs, claimed, note) {
  const opcode = OPCODES[opcodeName];
  if (!opcode) throw new Error(`Unsupported synthetic opcode ${opcodeName}`);
  const witness = {
    leaf_index: leafIndex,
    opcode,
    opcode_name: opcodeName,
    lhs,
    rhs,
    claimed,
    note
  };
  const verdict = checkWitness(witness);
  if (!verdict.ok) {
    throw new Error(
      `synthetic leaf ${leafIndex} ${opcodeName}(${lhs}, ${rhs}) violates the micro-ISA: ${verdict.reason}`
    );
  }
  return witness;
}

function makeScalingTrace(leafCount) {
  return Array.from({ length: leafCount }, (_unused, index) => {
    const lhs = index + 1;
    const rhs = (index % 7) + 2;
    return leaf(index, "ADD", lhs, rhs, lhs + rhs, "synthetic one-op leaf");
  });
}

function makeGranularityTrace(totalSemanticOps, groupSize) {
  const leafCount = totalSemanticOps / groupSize;
  return Array.from({ length: leafCount }, (_unused, index) => {
    const initialValue = index * groupSize;
    return leaf(
      index,
      "ADD_CHAIN",
      initialValue,
      groupSize,
      initialValue + groupSize,
      `compound leaf executing ${groupSize} repeated +1 semantic operation(s)`
    );
  });
}

function resultHash(payload) {
  return ethers.sha256(ethers.toUtf8Bytes(JSON.stringify(payload)));
}

async function writeSyntheticRun({ runDir, scenarioId, traceKind, semanticOps, groupSize, witnesses, manipulatedLeafIndex }) {
  const tree = buildMerkleTree(witnesses);
  const payload = {
    scenarioId,
    traceKind,
    semanticOps,
    groupSize,
    leafCount: witnesses.length,
    generatedAt: startedAt.toISOString()
  };
  const microTraceBundle = {
    session_id: scenarioId,
    workload: scenarioId,
    title: `Verification cost synthetic trace: ${scenarioId}`,
    domain: "Synthetic verification-cost evaluation",
    micro_trace_root: tree.root.slice(2),
    leaf_count: witnesses.length,
    synthetic: true,
    trace_kind: traceKind,
    semantic_ops: semanticOps,
    group_size: groupSize,
    manipulated_leaf_index: manipulatedLeafIndex,
    witnesses,
    limitation:
      "Synthetic traces isolate dispute-cost scaling. They are not application-level correctness claims."
  };
  const attestationPayload = {
    version: "pod-evm-v2",
    domain_name: "VerifiableFHEDisputeGame",
    domain_version: "2",
    primary_type: "TaskClaim",
    chain_family: "evm",
    proof_type: "POD_DISPUTE_GAME_VERIFICATION_COST_EVALUATION",
    session_id: scenarioId,
    task_id_keccak256: ethers.keccak256(ethers.toUtf8Bytes(scenarioId)),
    trace_root_keccak256: tree.root.slice(2),
    micro_trace_root_keccak256: tree.root.slice(2),
    result_hash_sha256: resultHash(payload),
    metadata_hash_keccak256: ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(payload))),
    content_uri_hint: runDir,
    content_uri_hash_keccak256: ethers.keccak256(ethers.toUtf8Bytes(runDir)),
    objective_verifier_hint:
      "Synthetic trace used to measure how challenge, bisection and objective leaf finality scale with leaf count."
  };
  const summary = {
    evaluation_id: evaluationId,
    scenario_id: scenarioId,
    trace_kind: traceKind,
    output_dir: runDir,
    micro_trace_root: tree.root.slice(2),
    semantic_ops: semanticOps,
    group_size: groupSize,
    leaf_count: witnesses.length,
    manipulated_leaf_index: manipulatedLeafIndex,
    manipulated_operation: witnesses[manipulatedLeafIndex].opcode_name
  };
  await fs.mkdir(runDir, { recursive: true });
  await Promise.all([
    writeJson(path.join(runDir, "micro_trace_bundle.json"), microTraceBundle),
    writeJson(path.join(runDir, "attestation_payload.json"), attestationPayload),
    writeJson(path.join(runDir, "summary.json"), summary),
    fs.writeFile(path.join(runDir, "root.txt"), `${tree.root}\n`)
  ]);
  return { tree, summary };
}

function runHardhatDispute(runDir, manipulatedLeafIndex, repetition) {
  return new Promise((resolve, reject) => {
    const command = resolveCommand("npm");
    const child = spawn(command, ["run", "demo:hardhat"], {
      cwd: projectRoot,
      env: {
        ...process.env,
        FHE_POD_RUN_DIR: runDir,
        DEMO_AUDITOR_COUNT: String(config.auditors),
        DEMO_DECRYPTOR_COUNT: String(config.decryptors),
        DEMO_MANIPULATED_LEAF_INDEX: String(manipulatedLeafIndex),
        DEMO_REPETITION: String(repetition),
        DEMO_SKIP_SURFACE_CHECKS: "1"
      },
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32" && command.endsWith(".cmd")
    });
    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`npm run demo:hardhat failed for ${runDir} with exit code ${code}`));
        return;
      }
      resolve();
    });
  });
}

function sumGas(transactions, predicate = () => true) {
  return (transactions ?? [])
    .filter(predicate)
    .reduce((total, tx) => total + BigInt(tx.gasUsed ?? 0), 0n);
}

function txByLabel(label) {
  return (tx) => String(tx.label ?? "") === label;
}

function startsWithLabel(prefix) {
  return (tx) => String(tx.label ?? "").startsWith(prefix);
}

function formatRatio(numerator, denominator) {
  const den = Number(denominator);
  if (!Number.isFinite(den) || den === 0) return "";
  return (Number(numerator) / den).toFixed(6);
}

function ethAt10Gwei(gas) {
  const wei = BigInt(gas) * 10_000_000_000n;
  const whole = wei / 1_000_000_000_000_000_000n;
  const fraction = (wei % 1_000_000_000_000_000_000n)
    .toString()
    .padStart(18, "0")
    .slice(0, 8);
  return `${whole}.${fraction}`;
}

function summarizeHardhatResult({ result, scenario, hardhatWallClockMs, hardhatResultPath }) {
  const transactions = result.transactions ?? [];
  const dishonestTaskId = ethers.encodeBytes32String("dishonest-node").toLowerCase();
  const honestTaskId = ethers.encodeBytes32String("honest-node").toLowerCase();
  const isDishonestTaskTx = (tx) => String(tx.taskId ?? "").toLowerCase() === dishonestTaskId;
  const isHonestTaskTx = (tx) => String(tx.taskId ?? "").toLowerCase() === honestTaskId;
// Labels that settle the isolated leaf. `settleLeafViaAttestedDecision` is the
// route a dispute over real ciphertext handles takes: the leaf is decided by
// FHE.eq over the ciphertexts and the two bits arrive with t+1 signatures. The
// two `*FhevmLeafResolution` labels are the older on-chain-recompute route and
// are kept so archived runs still classify. Omitting the new label does not
// merely mislabel a transaction: it drops the settlement out of the challenged
// path total and reports a leaf-resolution gas of zero, which is what the
// implementation's "Leaf gas" column would then print.
const LEAF_SETTLEMENT_LABELS = [
  "settleLeafViaAttestedDecision",
  "requestFhevmLeafResolution",
  "finalizeFhevmLeafResolution",
  "resolveLeafDispute"
];

  const challengedPathPredicate = (tx) =>
    isDishonestTaskTx(tx) &&
    [
      "createTask:dishonest",
      "registerInputOrigins",
      "authorizeTaskStatement",
      "submitAudit:dishonest-node",
      "openVerdict",
      "sealDiligenceRandomness",
      "proveAuditDiligence",
      "openChallenge",
      "publishDisputedTrace",
      "submitBisection",
      "advanceDispute",
      ...LEAF_SETTLEMENT_LABELS
    ].some((prefix) => String(tx.label ?? "").startsWith(prefix));
  const optimisticPathPredicate = (tx) =>
    isHonestTaskTx(tx) &&
    [
      "createTask:honest",
      "registerInputOrigins",
      "authorizeTaskStatement",
      "submitAudit:honest-node",
      "openVerdict",
      "finalizeUnchallenged"
    ].some((prefix) => String(tx.label ?? "").startsWith(prefix));
  const bisectionPredicate = (tx) =>
    isDishonestTaskTx(tx) &&
    (startsWithLabel("submitBisection")(tx) || startsWithLabel("advanceDispute")(tx));
  const leafResolutionPredicate = (tx) =>
    isDishonestTaskTx(tx) && LEAF_SETTLEMENT_LABELS.includes(String(tx.label ?? ""));
  const podDiligencePredicate = (tx) =>
    isDishonestTaskTx(tx) &&
      (txByLabel("sealDiligenceRandomness")(tx) || txByLabel("proveAuditDiligence")(tx));
  const isProvenanceSetupTx = (tx) =>
    txByLabel("registerInputOrigins")(tx) || txByLabel("authorizeTaskStatement")(tx);
  const traceDisclosurePredicate = (tx) =>
    isDishonestTaskTx(tx) && startsWithLabel("publishDisputedTrace")(tx);
  const challengedPathGas = sumGas(transactions, challengedPathPredicate);
  const optimisticPathGas = sumGas(transactions, optimisticPathPredicate);
  const leafResolutionGas = sumGas(transactions, leafResolutionPredicate);
  const podDiligenceGas = sumGas(transactions, podDiligencePredicate);
  const noPodEstimate = challengedPathGas > podDiligenceGas
    ? challengedPathGas - podDiligenceGas
    : 0n;
  const fullOnchainEstimate = leafResolutionGas * BigInt(scenario.leafCount);
  const expectedRounds = Math.ceil(Math.log2(scenario.leafCount));

  return {
    evaluationId,
    scenarioId: scenario.scenarioId,
    experimentKind: scenario.experimentKind,
    traceKind: scenario.traceKind,
    semanticOps: scenario.semanticOps,
    groupSize: scenario.groupSize,
    leafCount: scenario.leafCount,
    manipulatedLeafIndex: scenario.manipulatedLeafIndex,
    manipulatedOpcode: scenario.manipulatedOpcode,
    expectedBisectionRounds: expectedRounds,
    observedBisectionRounds: result.dishonestNode?.bisectionRounds?.length ?? 0,
    transactionCount: transactions.length,
    optimisticPathGasUsed: optimisticPathGas.toString(),
    challengedPathGasUsed: challengedPathGas.toString(),
    totalGasUsed: sumGas(transactions).toString(),
    deploymentGasUsed: sumGas(transactions, startsWithLabel("deploy:")).toString(),
    challengeOpeningGasUsed: sumGas(transactions, (tx) =>
      isDishonestTaskTx(tx) &&
      (txByLabel("sealDiligenceRandomness")(tx) ||
        txByLabel("proveAuditDiligence")(tx) ||
        txByLabel("openChallenge")(tx))
    ).toString(),
    podDiligenceGasUsed: podDiligenceGas.toString(),
    openChallengeGasUsed: sumGas(transactions, (tx) =>
      isDishonestTaskTx(tx) && txByLabel("openChallenge")(tx)
    ).toString(),
    bisectionGasUsed: sumGas(transactions, bisectionPredicate).toString(),
    leafResolutionGasUsed: leafResolutionGas.toString(),
    optimisticProvenanceSetupGasUsed: sumGas(
      transactions,
      (tx) => isHonestTaskTx(tx) && isProvenanceSetupTx(tx)
    ).toString(),
    challengedProvenanceSetupGasUsed: sumGas(
      transactions,
      (tx) => isDishonestTaskTx(tx) && isProvenanceSetupTx(tx)
    ).toString(),
    traceDisclosureGasUsed: sumGas(transactions, traceDisclosurePredicate).toString(),
    noPodChallengeGasEstimate: noPodEstimate.toString(),
    fullOnchainLeafVerificationGasEstimate: fullOnchainEstimate.toString(),
    challengedVsFullOnchainEstimateRatio: formatRatio(challengedPathGas, fullOnchainEstimate),
    optimisticCostEthAt10Gwei: ethAt10Gwei(optimisticPathGas),
    challengedCostEthAt10Gwei: ethAt10Gwei(challengedPathGas),
    fullOnchainEstimateCostEthAt10Gwei: ethAt10Gwei(fullOnchainEstimate),
    hardhatWallClockMs,
    operatorValid: result.dishonestNode?.leafCheck?.operatorValid,
    challengerValid: result.dishonestNode?.leafCheck?.challengerValid,
    honestDecision: result.honestNode?.decision,
    dishonestDecision: result.dishonestNode?.decision,
    measurementType: "mixed-direct-receipts-and-derived-baseline",
    runDir: scenario.runDir,
    hardhatResultPath
  };
}

function baselineRowsFromMeasuredRow(row) {
  const semanticOps = Number(row.semanticOps);
  const leafCount = Number(row.leafCount);
  const challenged = BigInt(row.challengedPathGasUsed);
  const optimistic = BigInt(row.optimisticPathGasUsed);
  const fullEstimate = BigInt(row.fullOnchainLeafVerificationGasEstimate);
  const noPodEstimate = BigInt(row.noPodChallengeGasEstimate);
  return [
    {
      evaluationId,
      scenarioId: row.scenarioId,
      baseline: "trust_worker_no_verification",
      measurementType: "conceptual-baseline",
      onchainGasUsedOrEstimate: "0",
      offchainVerifierWorkUnits: "0",
      detectsIncorrectWorker: false,
      detectsLazyAuditor: false,
      slashingGranularity: "none",
      note: "No verification cost, but no correctness guarantee."
    },
    {
      evaluationId,
      scenarioId: row.scenarioId,
      baseline: "optimistic_acceptance_current_protocol",
      measurementType: "direct-hardhat-receipts",
      onchainGasUsedOrEstimate: optimistic.toString(),
      offchainVerifierWorkUnits: String(semanticOps),
      detectsIncorrectWorker: "only-if-challenged",
      detectsLazyAuditor: "partially-through-protocol-tests",
      slashingGranularity: "none-on-unchallenged-path",
      note: "Measured honest path until finalizeUnchallenged."
    },
    {
      evaluationId,
      scenarioId: row.scenarioId,
      baseline: "full_onchain_leaf_verification",
      measurementType: "derived-estimate",
      onchainGasUsedOrEstimate: fullEstimate.toString(),
      offchainVerifierWorkUnits: "0",
      detectsIncorrectWorker: true,
      detectsLazyAuditor: false,
      slashingGranularity: "worker",
      note: "Naive same-verifier repetition proxy: measured two-claim FHEVM leaf-resolution gas multiplied by leaf count. It is not a benchmark of an optimized full-execution verifier."
    },
    {
      evaluationId,
      scenarioId: row.scenarioId,
      baseline: "optimistic_dispute_without_pod_checkpoint",
      measurementType: "derived-estimate",
      onchainGasUsedOrEstimate: noPodEstimate.toString(),
      offchainVerifierWorkUnits: String(semanticOps),
      detectsIncorrectWorker: true,
      detectsLazyAuditor: false,
      slashingGranularity: "worker/challenger",
      note: "Estimated by subtracting sealDiligenceRandomness and proveAuditDiligence gas from the measured challenged path."
    },
    {
      evaluationId,
      scenarioId: row.scenarioId,
      baseline: "fhe_pod_challenged_path",
      measurementType: "direct-hardhat-receipts",
      onchainGasUsedOrEstimate: challenged.toString(),
      offchainVerifierWorkUnits: String(semanticOps),
      detectsIncorrectWorker: true,
      detectsLazyAuditor: true,
      slashingGranularity: "worker/challenger/same-stage-auditor",
      note: "Measured task authorization, complete disputed-trace disclosure, PoD-bound challenge, bisection, FHEVM leaf finality and slashing."
    },
    {
      evaluationId,
      scenarioId: row.scenarioId,
      baseline: "full_offchain_recomputation_by_all_auditors",
      measurementType: "work-model",
      onchainGasUsedOrEstimate: optimistic.toString(),
      offchainVerifierWorkUnits: String(semanticOps * config.auditors),
      detectsIncorrectWorker: "if-auditors-act",
      detectsLazyAuditor: false,
      slashingGranularity: "worker",
      note: "Models verifier work as auditors times semantic operations; not a gas measurement."
    },
    {
      evaluationId,
      scenarioId: row.scenarioId,
      baseline: "wasm_nitro_style_fraud_proof",
      measurementType: "conceptual-not-benchmarked",
      onchainGasUsedOrEstimate: "",
      offchainVerifierWorkUnits: "depends-on-compiled-wasm-trace",
      detectsIncorrectWorker: "if-validator-challenges",
      detectsLazyAuditor: false,
      slashingGranularity: "asserter/challenger",
      note: "Included for related-work comparison only; this repository does not benchmark Nitro/WASM."
    }
  ].map((entry) => ({
    ...entry,
    leafCount,
    semanticOps,
    groupSize: row.groupSize,
    challengedPathGasUsed: row.challengedPathGasUsed,
    optimisticPathGasUsed: row.optimisticPathGasUsed
  }));
}

function accountabilityRows(referenceRow) {
  if (!referenceRow) return [];
  const optimistic = Number(referenceRow.optimisticPathGasUsed);
  const challenged = Number(referenceRow.challengedPathGasUsed);
  const cohortSizes = [1, 2, 3, 4, 5, 8];
  const lazyFractions = [0, 0.25, 0.5, 0.75];
  const rows = [];
  for (const cohortSize of cohortSizes) {
    for (const lazyFraction of lazyFractions) {
      const pAct = Math.max(0, 1 - lazyFraction);
      const pDetect = 1 - ((1 - config.pObservation * pAct) ** cohortSize);
      const pEffective = pDetect * config.pLive;
      rows.push({
        evaluationId,
        model: "stage-cohort-detection",
        measurementType: "probabilistic-model",
        referenceScenarioId: referenceRow.scenarioId,
        referenceLeafCount: referenceRow.leafCount,
        cohortSize,
        lazyFraction,
        pObservation: config.pObservation,
        pAct: Number(pAct.toFixed(6)),
        pLive: config.pLive,
        pDetect: Number(pDetect.toFixed(6)),
        pEffective: Number(pEffective.toFixed(6)),
        pWrongAcceptance: Number((1 - pEffective).toFixed(6)),
        expectedGas: Math.round(optimistic + pEffective * (challenged - optimistic)),
        note:
          "Models detection probability; protocol regressions test concrete lazy/wrong slashing behavior in npm run test:evm."
      });
    }
  }
  return rows;
}

async function runScenario(scenario, repetition) {
  printStep(`Scenario ${scenario.scenarioId}`, [
    `kind=${scenario.experimentKind}`,
    `leafCount=${scenario.leafCount}`,
    `semanticOps=${scenario.semanticOps}`,
    `groupSize=${scenario.groupSize}`,
    `manipulatedLeafIndex=${scenario.manipulatedLeafIndex}`
  ]);
  await writeSyntheticRun(scenario);
  const hardhatStart = performance.now();
  await runHardhatDispute(scenario.runDir, scenario.manipulatedLeafIndex, repetition);
  const hardhatWallClockMs = Math.round(performance.now() - hardhatStart);
  const hardhatResultPath = path.join(scenario.runDir, "hardhat_dispute_result.json");
  const result = JSON.parse(await fs.readFile(hardhatResultPath, "utf8"));
  const row = summarizeHardhatResult({
    result,
    scenario,
    hardhatWallClockMs,
    hardhatResultPath
  });
  if (row.dishonestDecision !== 2 || row.operatorValid !== false || row.challengerValid !== true) {
    throw new Error(`${scenario.scenarioId}: dishonest worker was not objectively slashed`);
  }
  return row;
}

function scenarioRunDir(scenarioId) {
  return path.join(runsDir, `${evaluationId}-${scenarioId}`);
}

function buildScenarios() {
  const scaling = config.scaleSizes.map((leafCount) => {
    const manipulatedLeafIndex = Math.min(
      config.manipulatedLeafIndex ?? Math.max(0, Math.floor(leafCount / 2)),
      leafCount - 1
    );
    const scenarioId = `scale-n${leafCount}`;
    const witnesses = makeScalingTrace(leafCount);
    // The honest synthetic trace must satisfy the same relation the on-chain
    // verifier enforces; the optimistic path checks no leaf, so this is the
    // only place a malformed sweep trace would be caught.
    assertTraceSemantics(witnesses, scenarioId);
    return {
      scenarioId,
      experimentKind: "scaling",
      traceKind: "one-op-per-leaf",
      semanticOps: leafCount,
      groupSize: 1,
      leafCount,
      manipulatedLeafIndex,
      manipulatedOpcode: witnesses[manipulatedLeafIndex].opcode_name,
      runDir: scenarioRunDir(scenarioId),
      witnesses
    };
  });

  const granularity = config.granularityGroupSizes.map((groupSize) => {
    const leafCount = config.granularitySemanticOps / groupSize;
    const manipulatedLeafIndex = Math.min(
      config.manipulatedLeafIndex ?? Math.max(0, Math.floor(leafCount / 2)),
      leafCount - 1
    );
    const scenarioId = `granularity-g${groupSize}-n${leafCount}`;
    const witnesses = makeGranularityTrace(config.granularitySemanticOps, groupSize);
    // Same invariant as the scaling sweep. This also pins the ADD_CHAIN group
    // size to 1..MAX_COMPOUND_OPS, which the contract enforces and the sweep
    // parameterises from the command line.
    assertTraceSemantics(witnesses, scenarioId);
    return {
      scenarioId,
      experimentKind: "granularity",
      traceKind: "compound-add-chain-leaf",
      semanticOps: config.granularitySemanticOps,
      groupSize,
      leafCount,
      manipulatedLeafIndex,
      manipulatedOpcode: witnesses[manipulatedLeafIndex].opcode_name,
      runDir: scenarioRunDir(scenarioId),
      witnesses
    };
  });

  const seen = new Set();
  const uniqueGranularity = granularity.filter((scenario) => {
    const key = `${scenario.experimentKind}:${scenario.groupSize}:${scenario.leafCount}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { scaling, granularity: uniqueGranularity };
}

const metricColumns = [
  "evaluationId",
  "scenarioId",
  "experimentKind",
  "traceKind",
  "semanticOps",
  "groupSize",
  "leafCount",
  "manipulatedLeafIndex",
  "manipulatedOpcode",
  "expectedBisectionRounds",
  "observedBisectionRounds",
  "transactionCount",
  "optimisticPathGasUsed",
  "challengedPathGasUsed",
  "challengeOpeningGasUsed",
  "podDiligenceGasUsed",
  "openChallengeGasUsed",
  "bisectionGasUsed",
  "leafResolutionGasUsed",
  "optimisticProvenanceSetupGasUsed",
  "challengedProvenanceSetupGasUsed",
  "traceDisclosureGasUsed",
  "noPodChallengeGasEstimate",
  "fullOnchainLeafVerificationGasEstimate",
  "challengedVsFullOnchainEstimateRatio",
  "totalGasUsed",
  "deploymentGasUsed",
  "optimisticCostEthAt10Gwei",
  "challengedCostEthAt10Gwei",
  "fullOnchainEstimateCostEthAt10Gwei",
  "hardhatWallClockMs",
  "operatorValid",
  "challengerValid",
  "honestDecision",
  "dishonestDecision",
  "measurementType",
  "runDir",
  "hardhatResultPath"
];

const baselineColumns = [
  "evaluationId",
  "scenarioId",
  "leafCount",
  "semanticOps",
  "groupSize",
  "baseline",
  "measurementType",
  "onchainGasUsedOrEstimate",
  "offchainVerifierWorkUnits",
  "challengedPathGasUsed",
  "optimisticPathGasUsed",
  "detectsIncorrectWorker",
  "detectsLazyAuditor",
  "slashingGranularity",
  "note"
];

const accountabilityColumns = [
  "evaluationId",
  "model",
  "measurementType",
  "referenceScenarioId",
  "referenceLeafCount",
  "cohortSize",
  "lazyFraction",
  "pObservation",
  "pAct",
  "pLive",
  "pDetect",
  "pEffective",
  "pWrongAcceptance",
  "expectedGas",
  "note"
];

printTitle("Verification-cost evaluation for FHE-PoD");
printStep("Configuration", [
  `evaluationId=${evaluationId}`,
  `auditors=${config.auditors}`,
  `decryptors=${config.decryptors}`,
  `scaleSizes=${config.scaleSizes.join(",")}`,
  `granularitySemanticOps=${config.granularitySemanticOps}`,
  `granularityGroupSizes=${config.granularityGroupSizes.join(",")}`,
  `pObservation=${config.pObservation}`,
  `pLive=${config.pLive}`
]);

const { scaling: scalingScenarios, granularity: granularityScenarios } = buildScenarios();
const scalingRows = [];
const granularityRows = [];
let repetition = 1;

for (const scenario of scalingScenarios) {
  scalingRows.push(await runScenario(scenario, repetition++));
}
for (const scenario of granularityScenarios) {
  granularityRows.push(await runScenario(scenario, repetition++));
}

const allMeasuredRows = [...scalingRows, ...granularityRows];
const baselineRows = allMeasuredRows.flatMap((row) => baselineRowsFromMeasuredRow(row));
const referenceRow = scalingRows.at(-1) ?? allMeasuredRows.at(-1);
const accountabilityModelRows = accountabilityRows(referenceRow);

const paths = {
  jsonPath: path.join(evaluationsDir, `${evaluationId}.json`),
  latestJsonPath: path.join(evaluationsDir, "latest_verification_cost_evaluation.json"),
  scalingCsvPath: path.join(evaluationsDir, `${evaluationId}-scaling.csv`),
  latestScalingCsvPath: path.join(evaluationsDir, "latest_verification_cost_scaling.csv"),
  granularityCsvPath: path.join(evaluationsDir, `${evaluationId}-granularity.csv`),
  latestGranularityCsvPath: path.join(evaluationsDir, "latest_verification_cost_granularity.csv"),
  baselinesCsvPath: path.join(evaluationsDir, `${evaluationId}-baselines.csv`),
  latestBaselinesCsvPath: path.join(evaluationsDir, "latest_verification_cost_baselines.csv"),
  accountabilityCsvPath: path.join(evaluationsDir, `${evaluationId}-accountability.csv`),
  latestAccountabilityCsvPath: path.join(evaluationsDir, "latest_verification_cost_accountability.csv")
};

// Execution provenance, stamped onto the report and onto every CSV row. The
// scaling and granularity sweeps are the source of the implementation's O(N)/O(log N)
// claims, so the venue that produced them has to travel with the numbers.
const runContext = await collectRunContext();
requireChain(runContext, {
  allowDevEvm: process.argv.includes("--allow-dev-evm"),
  label: "verification-cost evaluation"
});
const { columns: contextCsvColumns, values: contextValues } = contextColumns(runContext);
metricColumns.push(...contextCsvColumns);
for (const row of [...scalingRows, ...granularityRows]) Object.assign(row, contextValues);
for (const row of [...scalingRows, ...granularityRows]) {
  // Absolute paths in a committed CSV are unusable elsewhere.
  if (row.runDir) row.runDir = repoRelative(row.runDir);
  if (row.hardhatResultPath) row.hardhatResultPath = repoRelative(row.hardhatResultPath);
}

const report = {
  schemaVersion: EVALUATION_SCHEMA_VERSION,
  evaluationId,
  startedAt: startedAt.toISOString(),
  finishedAt: new Date().toISOString(),
  status: "passed",
  context: runContext,
  config,
  claim:
    "Verification-cost evaluation for FHE-POD: challenged on-chain settlement scales with bisection depth, while final leaf resolution remains constant for the supported micro-instruction surface.",
  criticalBoundary:
    "Scaling and granularity traces are synthetic. Direct gas rows come from Hardhat receipts; full-on-chain and no-PoD baselines are derived estimates; accountability rows are probabilistic models, not direct protocol executions.",
  artifacts: paths,
  scalingRows,
  granularityRows,
  baselineRows,
  accountabilityModelRows,
  summary: {
    scalingRowCount: scalingRows.length,
    granularityRowCount: granularityRows.length,
    baselineRowCount: baselineRows.length,
    accountabilityRowCount: accountabilityModelRows.length,
    referenceScenarioId: referenceRow?.scenarioId,
    minLeafResolutionGasUsed: allMeasuredRows
      .map((row) => BigInt(row.leafResolutionGasUsed))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))[0]?.toString(),
    maxLeafResolutionGasUsed: allMeasuredRows
      .map((row) => BigInt(row.leafResolutionGasUsed))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
      .at(-1)?.toString()
  }
};

await writeCsv(paths.scalingCsvPath, scalingRows, metricColumns);
await writeCsv(paths.latestScalingCsvPath, scalingRows, metricColumns);
await writeCsv(paths.granularityCsvPath, granularityRows, metricColumns);
await writeCsv(paths.latestGranularityCsvPath, granularityRows, metricColumns);
await writeCsv(paths.baselinesCsvPath, baselineRows, baselineColumns);
await writeCsv(paths.latestBaselinesCsvPath, baselineRows, baselineColumns);
await writeCsv(paths.accountabilityCsvPath, accountabilityModelRows, accountabilityColumns);
await writeCsv(paths.latestAccountabilityCsvPath, accountabilityModelRows, accountabilityColumns);
await writeJson(paths.jsonPath, report);
await writeJson(paths.latestJsonPath, report);

printStep("Verification-cost evaluation complete", [
  `json=${paths.jsonPath}`,
  `scalingCsv=${paths.scalingCsvPath}`,
  `granularityCsv=${paths.granularityCsvPath}`,
  `baselinesCsv=${paths.baselinesCsvPath}`,
  `accountabilityCsv=${paths.accountabilityCsvPath}`
]);
