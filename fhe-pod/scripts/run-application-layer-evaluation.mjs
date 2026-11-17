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
import {
  allApplicationWorkloadSpecs,
  lowerWorkloadSpec,
  opcodeCounts
} from "./application-lowering.mjs";
import {
  EVALUATION_SCHEMA_VERSION,
  collectRunContext,
  contextColumns,
  repoRelative,
  requireChain
} from "./run-context.mjs";

const startedAt = new Date();
const evaluationId = `application-layer-${startedAt
  .toISOString()
  .replace(/[-:]/g, "")
  .replace(/\.\d{3}Z$/, "Z")}`;
const evaluationsDir = path.join(projectRoot, "artifacts", "evaluations");

// Canonical experiment set (kept in sync with CANONICAL_EXPERIMENT_WORKLOADS in
// run-experiment-evaluation.mjs): the two sensitive-data compliance workloads the
// implementation evaluates. `--workloads all` still runs every registered workload;
// the archived eleven-workload campaign lives in `archive/nonlinear-11-workloads/`.
const CANONICAL_EXPERIMENT_WORKLOADS = [
  "regulatory_qoe_compliance",
  "regional_qoe_compliance"
];

const config = parseArgs(process.argv.slice(2));

function parseArgs(args) {
  const parsed = {
    workloads: CANONICAL_EXPERIMENT_WORKLOADS.join(","),
    runDisputes: true,
    auditors: parseInteger(process.env.APP_LAYER_AUDITORS, 4, "APP_LAYER_AUDITORS", { min: 3 }),
    decryptors: parseInteger(process.env.APP_LAYER_DECRYPTORS, 4, "APP_LAYER_DECRYPTORS", { min: 3 }),
    surfaceChecks: process.env.APP_LAYER_SURFACE_CHECKS ?? "all",
    manipulatedLeafIndex: null,
    repeats: parseInteger(process.env.APP_LAYER_REPEATS, 1, "APP_LAYER_REPEATS", { min: 1 }),
    // The blockchain is the substrate of the evaluation; see requireChain().
    allowDevEvm: false
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const nextValue = () => {
      index += 1;
      if (index >= args.length) throw new Error(`${arg} requires a value`);
      return args[index];
    };

    if (arg === "--workloads") {
      parsed.workloads = nextValue();
    } else if (arg === "--skip-disputes") {
      parsed.runDisputes = false;
    } else if (arg === "--auditors") {
      parsed.auditors = parseInteger(nextValue(), parsed.auditors, arg, { min: 3 });
    } else if (arg === "--decryptors") {
      parsed.decryptors = parseInteger(nextValue(), parsed.decryptors, arg, { min: 3 });
    } else if (arg === "--manipulated-leaf-index") {
      parsed.manipulatedLeafIndex = parseInteger(nextValue(), 0, arg, { min: 0 });
    } else if (arg === "--repeats") {
      parsed.repeats = parseInteger(nextValue(), 1, arg, { min: 1 });
    } else if (arg === "--allow-dev-evm") {
      parsed.allowDevEvm = true;
    } else if (arg === "--surface-checks") {
      parsed.surfaceChecks = nextValue();
    } else if (arg === "--help" || arg === "-h") {
      printUsageAndExit();
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!["all", "once", "skip"].includes(parsed.surfaceChecks)) {
    throw new Error("APP_LAYER_SURFACE_CHECKS/--surface-checks must be all, once, or skip");
  }

  return parsed;
}

function parseInteger(raw, fallback, label, { min = 0 } = {}) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${label} must be an integer >= ${min}; received ${raw}`);
  }
  return value;
}

function printUsageAndExit() {
  console.log(`Usage:
  npm run eval:applications -- [options]

Options:
  --workloads <list>             Comma-separated workload ids, or "all".
                                 Default: the canonical two-workload experiment set
                                 (regulatory_qoe_compliance,regional_qoe_compliance)
  --skip-disputes                Only generate traces/CSV; do not run Hardhat disputes
  --auditors <n>                 Registered auditor pool size, minimum 3, default 4
  --decryptors <n>               Registered threshold-opening pool size, minimum 3, default 4
  --surface-checks <mode>        Full 15-opcode checks: all, once, or skip (default: all)
  --manipulated-leaf-index <n>   Override manipulated leaf for every workload
  --repeats <n>                 Fresh dispute deployments per workload (default: 1)`);
  process.exit(0);
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

function assertPowerOfTwo(n, workloadId) {
  if (n <= 0 || (n & (n - 1)) !== 0) {
    throw new Error(`Workload ${workloadId} produced ${n} leaves; leaf count must be a power of two`);
  }
}

function selectedWorkloads() {
  if (config.workloads === "all") return allApplicationWorkloadSpecs();
  const wanted = new Set(config.workloads.split(",").map((s) => s.trim()).filter(Boolean));
  const selected = allApplicationWorkloadSpecs().filter((w) => wanted.has(w.id));
  const missing = [...wanted].filter((id) => !allApplicationWorkloadSpecs().some((w) => w.id === id));
  if (missing.length > 0) throw new Error(`Unknown workload(s): ${missing.join(", ")}`);
  return selected;
}

function csvCell(value) {
  if (value === undefined || value === null) return "";
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  if (/[",\n\r]/.test(text)) return `"${text.replaceAll('"', '""')}"`;
  return text;
}

async function writeCsv(filePath, rows, columns) {
  const header = columns.join(",");
  const body = rows.map((row) => columns.map((col) => csvCell(row[col])).join(","));
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, [header, ...body].join("\n") + "\n");
}

function resolveCommand(command) {
  if (process.platform === "win32" && command === "npm") return "npm.cmd";
  return command;
}

function runHardhatDispute(runDir, workloadId, manipulatedLeafIndex, skipSurfaceChecks) {
  return new Promise((resolve, reject) => {
    const command = resolveCommand("npm");
    const child = spawn(command, ["run", "demo:hardhat"], {
      cwd: projectRoot,
      env: {
        ...process.env,
        FHE_POD_RUN_DIR: runDir,
        // Which entries of artifacts/fhe/ciphertext-manifest.json hold the
        // ciphertext handles of this run's two traces. The run directory also
        // names the workload (micro_trace_bundle.json), but the demo is the
        // component that must never guess, so the id travels explicitly.
        DEMO_FHE_WORKLOAD_ID: workloadId,
        DEMO_AUDITOR_COUNT: String(config.auditors),
        DEMO_DECRYPTOR_COUNT: String(config.decryptors),
        DEMO_MANIPULATED_LEAF_INDEX: String(manipulatedLeafIndex),
        DEMO_SKIP_SURFACE_CHECKS: skipSurfaceChecks ? "1" : "0"
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
    .reduce((total, tx) => total + BigInt(tx.gasUsed ?? 0), 0n)
    .toString();
}

function sumWei(transactions, field, predicate = () => true) {
  return (transactions ?? [])
    .filter(predicate)
    .reduce((total, tx) => total + BigInt(tx[field] ?? 0), 0n)
    .toString();
}

function sumDurationMs(transactions, predicate = () => true) {
  return (transactions ?? [])
    .filter(predicate)
    .reduce((total, tx) => total + Number(tx.durationMs ?? 0), 0);
}

function ethCostAtGasPrice(gasUsed, gwei) {
  const wei = BigInt(gasUsed ?? 0) * BigInt(gwei) * 1_000_000_000n;
  const whole = wei / 1_000_000_000_000_000_000n;
  const fraction = (wei % 1_000_000_000_000_000_000n)
    .toString()
    .padStart(18, "0")
    .slice(0, 8);
  return `${whole}.${fraction}`;
}

/**
 * Wall-clock interval spanned by a set of transactions, in milliseconds.
 *
 * WHY THIS EXISTS. `durationMs` measures one transaction from submission to
 * receipt, so a sum of durations reports the time spent INSIDE transactions and
 * silently drops the time between them, which is where a protocol window
 * elapses. The interval below is measured from the submission of the first
 * transaction of the phase to the mining of the last, so waiting is included.
 *
 * Returns `null` when the ledger predates the timestamp instrumentation of
 * run-hardhat-dispute-demo.mjs (`startedAtMs` / `minedAtMs`), which is what the
 * downstream CSV writes as an empty cell rather than as a zero: a zero would be
 * indistinguishable from an instantaneous phase.
 */
function phaseWallClockMs(txs, predicate) {
  const selected = (txs ?? []).filter(predicate);
  if (selected.length === 0) return null;
  const starts = selected
    .map((tx) => Number(tx.startedAtMs))
    .filter((value) => Number.isFinite(value) && value > 0);
  const ends = selected
    .map((tx) => Number(tx.minedAtMs))
    .filter((value) => Number.isFinite(value) && value > 0);
  if (starts.length === 0 || ends.length === 0) return null;
  return Math.round(Math.max(...ends) - Math.min(...starts));
}

function readDecisionSummary(result, hardhatDisputeWallClockMs = 0) {
  const txs = result.transactions ?? [];
  const dishonestTaskId = ethers.encodeBytes32String("dishonest-node");
  const isDishonestTaskTx = (tx) => String(tx.taskId ?? "").toLowerCase() === dishonestTaskId.toLowerCase();
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
  const bisectionPredicate = (tx) =>
    String(tx.label ?? "").startsWith("submitBisection") ||
    String(tx.label ?? "").startsWith("advanceDispute");
  const leafResolutionPredicate = (tx) =>
    LEAF_SETTLEMENT_LABELS.includes(String(tx.label ?? ""));
  const challengedPathGasUsed = sumGas(txs, challengedPathPredicate);
  const leafResolutionGasUsed = sumGas(txs, leafResolutionPredicate);

  // ── The dispute proper ────────────────────────────────────────────────────
  // Everything before `openChallenge` is task setup: deployment, the opcode
  // surface sweep, participant registration, the honest task, the audits and
  // the commit and opening windows. A dispute begins when a dissenting auditor
  // accuses, and ends when the isolated leaf is settled. The interval below is
  // that, and only that, so it includes the disclosure of the trace, every
  // bisection round, the homomorphic recomputation of the disputed leaf, and
  // the waiting between those transactions.
  const disclosurePredicate = (tx) =>
    isDishonestTaskTx(tx) && String(tx.label ?? "").startsWith("publishDisputedTrace");
  const disputeStart = (txs ?? [])
    .filter((tx) => isDishonestTaskTx(tx) && String(tx.label ?? "").startsWith("openChallenge"))
    .map((tx) => Number(tx.startedAtMs))
    .filter((value) => Number.isFinite(value) && value > 0)
    .sort((a, b) => a - b)[0];
  const disputeEnd = (txs ?? [])
    .filter(leafResolutionPredicate)
    .map((tx) => Number(tx.minedAtMs))
    .filter((value) => Number.isFinite(value) && value > 0)
    .sort((a, b) => b - a)[0];
  const disputeWallClockMs =
    Number.isFinite(disputeStart) && Number.isFinite(disputeEnd) && disputeEnd >= disputeStart
      ? Math.round(disputeEnd - disputeStart)
      : null;
  // Transactions of the dispute window: the accusation, the disclosure, the
  // bisection rounds and the settlement. Their summed durations are the part of
  // the dispute spent inside transactions; the remainder is waiting.
  const disputeTxPredicate = (tx) =>
    Number.isFinite(disputeStart) &&
    Number(tx.startedAtMs) >= disputeStart &&
    Number(tx.minedAtMs) <= (Number.isFinite(disputeEnd) ? disputeEnd : Infinity);
  const disputeTxDurationMs =
    disputeWallClockMs === null ? null : sumDurationMs(txs, disputeTxPredicate);
  const disputeWaitMs =
    disputeWallClockMs === null ? null : Math.max(0, disputeWallClockMs - disputeTxDurationMs);
  const disputeDisclosureWallClockMs = phaseWallClockMs(txs, disclosurePredicate);
  const disputeBisectionWallClockMs = phaseWallClockMs(txs, bisectionPredicate);
  const disputeSettlementWallClockMs = phaseWallClockMs(txs, leafResolutionPredicate);
  const provenanceSetupGasUsed = sumGas(
    txs,
    (tx) => isDishonestTaskTx(tx) &&
      ["registerInputOrigins", "authorizeTaskStatement"].includes(String(tx.label ?? ""))
  );
  const traceDisclosureGasUsed = sumGas(
    txs,
    (tx) => isDishonestTaskTx(tx) && String(tx.label ?? "").startsWith("publishDisputedTrace")
  );
  return {
    transactionCount: txs.length,
    totalGasUsed: sumGas(txs),
    totalTransactionCostWei: sumWei(txs, "transactionCostWei"),
    deploymentGasUsed: sumGas(txs, (tx) => String(tx.label ?? "").startsWith("deploy:")),
    opcodeSurfaceGasUsed: sumGas(txs, (tx) => String(tx.label ?? "").startsWith("fhevmSurface:")),
    challengedPathGasUsed,
    provenanceSetupGasUsed,
    traceDisclosureGasUsed,
    bisectionGasUsed: sumGas(txs, bisectionPredicate),
    leafResolutionGasUsed,
    observedTotalTransactionCostWei: sumWei(txs, "transactionCostWei"),
    observedChallengedPathTransactionCostWei: sumWei(txs, "transactionCostWei", challengedPathPredicate),
    observedLeafResolutionTransactionCostWei: sumWei(txs, "transactionCostWei", leafResolutionPredicate),
    challengedPathTransactionCostWei: sumWei(txs, "transactionCostWei", challengedPathPredicate),
    leafResolutionTransactionCostWei: sumWei(txs, "transactionCostWei", leafResolutionPredicate),
    localOnchainTotalTxDurationMs: sumDurationMs(txs),
    localOnchainChallengedPathTxDurationMs: sumDurationMs(txs, challengedPathPredicate),
    localOnchainLeafResolutionTxDurationMs: sumDurationMs(txs, leafResolutionPredicate),
    // Whole per-workload run: deployment, opcode sweep, honest task, corrupted
    // task, dispute and settlement. Kept under its historical name so archived
    // artifacts stay readable, and mirrored under `runWallClockMs`, which says
    // what it actually measures.
    hardhatDisputeWallClockMs,
    runWallClockMs: hardhatDisputeWallClockMs,
    // The dispute alone: `openChallenge` to leaf settlement.
    disputeWallClockMs,
    disputeTxDurationMs,
    disputeWaitMs,
    disputeDisclosureWallClockMs,
    disputeBisectionWallClockMs,
    disputeSettlementWallClockMs,
    challengedPathCostEthAt1Gwei: ethCostAtGasPrice(challengedPathGasUsed, 1),
    challengedPathCostEthAt10Gwei: ethCostAtGasPrice(challengedPathGasUsed, 10),
    challengedPathCostEthAt30Gwei: ethCostAtGasPrice(challengedPathGasUsed, 30),
    leafResolutionCostEthAt10Gwei: ethCostAtGasPrice(leafResolutionGasUsed, 10),
    dishonestDecision: result.dishonestNode?.decision,
    honestDecision: result.honestNode?.decision,
    bisectionRounds: result.dishonestNode?.bisectionRounds?.length ?? 0,
    operatorValid: result.dishonestNode?.leafCheck?.operatorValid,
    challengerValid: result.dishonestNode?.leafCheck?.challengerValid,
    // --- cost of the leaf DECISION itself -----------------------------------
    // The settlement rule recomputes the disputed instruction homomorphically
    // and compares each claim with FHE.eq, decrypting only the bit. That work
    // is off-chain and its cost depends on which operation was disputed (a MUL
    // is orders of magnitude dearer than a BITAND), whereas the transaction
    // that carries the two attested bits on-chain is one call of flat cost.
    // Reporting both separates "how long does the chain take to settle a leaf"
    // from "how long does it take to decide it".
    disputedLeafOpcode: result.dishonestNode?.leafCheck?.opcode ?? "",
    leafDecisionBackend: result.dishonestNode?.fhevmResolution?.decidedBy ?? "",
    leafDecisionRecomputeMs: result.dishonestNode?.fhevmResolution?.eqDetail?.recomputeMs ?? "",
    leafDecisionEqMs: result.dishonestNode?.fhevmResolution?.eqDetail?.eqMs ?? "",
    leafDecisionOffchainMs:
      result.dishonestNode?.fhevmResolution?.eqDetail?.offchainDecisionMs ?? "",
    dishonestOperatorSlashWei: result.dishonestNode?.dishonestStakeDeltaWei,
    challengerRewardWei: result.dishonestNode?.challengerStakeDeltaWei,
    // Per-row execution venue, read back from the dispute run itself rather
    // than from the ambient environment. Without these columns a committed CSV
    // could not be attributed to the QBFT validator network or to the
    // in-process EVM, which is precisely the distinction the implementation draws
    // when it reports wall-clock and consensus behaviour.
    runNetwork: result.network ?? "",
    runChainId: result.chainId ?? "",
    runSecureTraceMode: result.secureTraceMode ?? "",
    ciphertextHandlesReady: result.ciphertextHandlesReady ?? false,
    runOpeningBackend: result.verdictOpening ?? result.openingBackend ?? "",
    firstBlockNumber: firstBlock(txs),
    lastBlockNumber: lastBlock(txs)
  };
}

/**
 * Aggregates observed gas per transaction label across every workload.
 *
 * Produces `{label: {count, minGas, maxGas, meanGas, totalGas}}`. Per-mechanism
 * cost tables (for example the gas of a single `authorizeTaskStatement`) are
 * derived from this instead of from a separate hand-run benchmark, so they can
 * never disagree with the runs that produced the aggregate figures.
 */
function aggregateGasByLabel(results) {
  const buckets = new Map();
  for (const { transactions } of results) {
    for (const tx of transactions ?? []) {
      const label = String(tx.label ?? "").split(":")[0];
      const gas = Number(tx.gasUsed);
      if (!label || !Number.isFinite(gas)) continue;
      if (!buckets.has(label)) buckets.set(label, []);
      buckets.get(label).push(gas);
    }
  }
  return Object.fromEntries(
    [...buckets.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([label, values]) => [
      label,
      {
        count: values.length,
        minGas: Math.min(...values),
        maxGas: Math.max(...values),
        meanGas: Math.round(values.reduce((sum, v) => sum + v, 0) / values.length),
        totalGas: values.reduce((sum, v) => sum + v, 0)
      }
    ])
  );
}

/** First block number observed in a run's transaction ledger (audit trail). */
function firstBlock(txs) {
  const blocks = txs.map((tx) => Number(tx.blockNumber)).filter(Number.isFinite);
  return blocks.length ? Math.min(...blocks) : "";
}

/** Last block number observed in a run's transaction ledger (audit trail). */
function lastBlock(txs) {
  const blocks = txs.map((tx) => Number(tx.blockNumber)).filter(Number.isFinite);
  return blocks.length ? Math.max(...blocks) : "";
}

async function writeWorkloadArtifacts(workload, runDir, manipulatedLeafIndex) {
  assertPowerOfTwo(workload.witnesses.length, workload.id);
  if (manipulatedLeafIndex >= workload.witnesses.length) {
    throw new Error(
      `${workload.id}: manipulated leaf ${manipulatedLeafIndex} outside ${workload.witnesses.length} leaves`
    );
  }
  const tree = buildMerkleTree(workload.witnesses);
  const resultPayload = {
    workloadId: workload.id,
    title: workload.title,
    model: workload.model,
    lowering: workload.lowering,
    finalClaimed: workload.witnesses.at(-1)?.claimed,
    generatedAt: startedAt.toISOString()
  };
  const resultHash = ethers.sha256(ethers.toUtf8Bytes(JSON.stringify(resultPayload)));
  const metadataHash = ethers.keccak256(
    ethers.toUtf8Bytes(JSON.stringify({
      workloadId: workload.id,
      domain: workload.domain,
      title: workload.title,
      applicability: workload.applicability,
      limitation: workload.limitation
    }))
  );

  const microTraceBundle = {
    session_id: `${evaluationId}-${workload.id}`,
    workload: workload.id,
    title: workload.title,
    domain: workload.domain,
    micro_trace_root: tree.root.slice(2),
    leaf_count: workload.witnesses.length,
    lowering: workload.lowering,
    witnesses: workload.witnesses,
    applicability: workload.applicability,
    limitation: workload.limitation
  };
  const attestationPayload = {
    version: "pod-evm-v2",
    domain_name: "VerifiableFHEDisputeGame",
    domain_version: "2",
    primary_type: "TaskClaim",
    chain_family: "evm",
    proof_type: "POD_DISPUTE_GAME_APPLICATION_LAYER_EVALUATION",
    session_id: `${evaluationId}-${workload.id}`,
    task_id_keccak256: ethers.keccak256(ethers.toUtf8Bytes(`${evaluationId}-${workload.id}`)),
    trace_root_keccak256: tree.root.slice(2),
    micro_trace_root_keccak256: tree.root.slice(2),
    result_hash_sha256: resultHash,
    metadata_hash_keccak256: metadataHash,
    content_uri_hint: runDir,
    content_uri_hash_keccak256: ethers.keccak256(ethers.toUtf8Bytes(runDir)),
    objective_verifier_hint:
      "Application-layer workload lowered to supported deterministic micro-instructions; contested leaf uses local FHEVM objective verifier."
  };
  const summary = {
    evaluation_id: evaluationId,
    workload_id: workload.id,
    title: workload.title,
    domain: workload.domain,
    output_dir: runDir,
    micro_trace_root: tree.root.slice(2),
    micro_steps: workload.witnesses.length,
    manipulated_leaf_index: manipulatedLeafIndex,
    manipulated_operation: workload.witnesses[manipulatedLeafIndex].opcode_name,
    opcode_counts: opcodeCounts(workload.witnesses),
    lowering_engine: workload.lowering?.engineVersion,
    operation_type: workload.lowering?.operationType,
    applicability: workload.applicability,
    limitation: workload.limitation
  };

  await fs.mkdir(runDir, { recursive: true });
  await Promise.all([
    writeJson(path.join(runDir, "application_workload.json"), workload),
    writeJson(path.join(runDir, "micro_trace_bundle.json"), microTraceBundle),
    writeJson(path.join(runDir, "attestation_payload.json"), attestationPayload),
    writeJson(path.join(runDir, "summary.json"), summary),
    fs.writeFile(path.join(runDir, "root.txt"), `${tree.root}\n`)
  ]);
  return { tree, summary };
}

/**
 * Canonical column order of `artifacts/evaluations/*application_layer*.csv`.
 *
 * Grouped so that a downstream analysis can select by prefix:
 *   - identity/provenance : evaluationId, workloadId, run*, context*
 *   - lowering            : loweringEngine .. opcodeCounts, microIsa*
 *   - dispute outcome     : honestDecision .. bisectionRounds
 *   - timing              : *DurationMs, *WallClockMs
 *   - cost                : *GasUsed, *Wei, *CostEth*
 *
 * `context*` columns are appended by `contextColumns()` at write time, so the
 * venue of every row travels with the row.
 */
const csvColumns = [
  "evaluationId",
  "schemaVersion",
  "workloadId",
  "repetition",
  "domain",
  "title",
  "applicability",
  "limitation",
  "runDir",
  "runNetwork",
  "runChainId",
  "runSecureTraceMode",
  "ciphertextHandlesReady",
  "runOpeningBackend",
  "firstBlockNumber",
  "lastBlockNumber",
  "loweringEngine",
  "operationType",
  "loweringWarnings",
  "leafCount",
  "opcodeCounts",
  "microIsaSize",
  "microIsaVerified",
  "manipulatedLeafIndex",
  "manipulatedOpcode",
  "disputeRun",
  "honestDecision",
  "dishonestDecision",
  "operatorValid",
  "challengerValid",
  "bisectionRounds",
  "transactionCount",
  "offchainPreparationDurationMs",
  "loweringDurationMs",
  "artifactPreparationDurationMs",
  "workloadWallClockMs",
  "hardhatDisputeWallClockMs",
  "runWallClockMs",
  "disputeWallClockMs",
  "disputeTxDurationMs",
  "disputeWaitMs",
  "disputeDisclosureWallClockMs",
  "disputeBisectionWallClockMs",
  "disputeSettlementWallClockMs",
  "localOnchainTotalTxDurationMs",
  "localOnchainChallengedPathTxDurationMs",
  "localOnchainLeafResolutionTxDurationMs",
  "totalGasUsed",
  "totalTransactionCostWei",
  "observedTotalTransactionCostWei",
  "deploymentGasUsed",
  "opcodeSurfaceGasUsed",
  "challengedPathGasUsed",
  "provenanceSetupGasUsed",
  "traceDisclosureGasUsed",
  "bisectionGasUsed",
  "leafResolutionGasUsed",
  "observedChallengedPathTransactionCostWei",
  "observedLeafResolutionTransactionCostWei",
  "challengedPathTransactionCostWei",
  "leafResolutionTransactionCostWei",
  "challengedPathCostEthAt1Gwei",
  "challengedPathCostEthAt10Gwei",
  "challengedPathCostEthAt30Gwei",
  "leafResolutionCostEthAt10Gwei",
  "disputedLeafOpcode",
  "leafDecisionBackend",
  "leafDecisionRecomputeMs",
  "leafDecisionEqMs",
  "leafDecisionOffchainMs",
  "dishonestOperatorSlashWei",
  "challengerRewardWei",
  "hardhatResultPath"
];

printTitle("Application-layer evaluation for FHE-PoD");
printStep("Configuration", [
  `evaluationId=${evaluationId}`,
  `workloads=${config.workloads}`,
  `runDisputes=${config.runDisputes}`,
  `auditors=${config.auditors}`,
  `decryptors=${config.decryptors}`,
  `surfaceChecks=${config.surfaceChecks}`
]);

// Execution provenance, resolved once and stamped onto every row.
const runContext = await collectRunContext();
requireChain(runContext, {
  allowDevEvm: config.allowDevEvm,
  label: "application-layer evaluation"
});
const { columns: contextCsvColumns, values: contextValues } = contextColumns(runContext);
csvColumns.push(...contextCsvColumns);
printStep("Execution context", [
  `venue=${runContext.venue}`,
  `network=${runContext.network} chainId=${runContext.chainId || "unknown"}`,
  `secureTraceMode=${runContext.secureTraceMode}`,
  `openingBackend=${runContext.openingBackend}`,
  `gitCommit=${(runContext.gitCommit || "unknown").slice(0, 12)}${runContext.gitDirty ? " (dirty)" : ""}`
]);

const rows = [];
const fullResults = [];
const schedule = selectedWorkloads().flatMap(workloadSpec =>
  Array.from({ length: config.repeats }, (_, i) => ({ workloadSpec, repetition: i + 1 })));
for (const [workloadIndex, { workloadSpec, repetition }] of schedule.entries()) {
  const workloadStart = performance.now();
  const loweringStart = performance.now();
  const workload = lowerWorkloadSpec(workloadSpec);
  const loweringDurationMs = Math.round(performance.now() - loweringStart);
  const manipulatedLeafIndex =
    config.manipulatedLeafIndex ?? workload.defaultManipulatedLeafIndex;
  const runDir = path.join(projectRoot, "artifacts", "runs", `${evaluationId}-${workload.id}-r${repetition}`);
  printStep(`Workload: ${workload.id}`, [
    `repetition=${repetition}/${config.repeats}`,
    `domain=${workload.domain}`,
    `title=${workload.title}`,
    `leafCount=${workload.witnesses.length}`,
    `manipulatedLeafIndex=${manipulatedLeafIndex}`
  ]);
  const artifactStart = performance.now();
  const { summary } = await writeWorkloadArtifacts(workload, runDir, manipulatedLeafIndex);
  const artifactPreparationDurationMs = Math.round(performance.now() - artifactStart);
  const offchainPreparationDurationMs = loweringDurationMs + artifactPreparationDurationMs;

  let disputeSummary = {};
  let hardhatResultPath = "";
  let transactionLedger = [];
  if (config.runDisputes) {
    const hardhatStart = performance.now();
    const skipSurfaceChecks =
      config.surfaceChecks === "skip" ||
      (config.surfaceChecks === "once" && workloadIndex > 0);
    await runHardhatDispute(runDir, workload.id, manipulatedLeafIndex, skipSurfaceChecks);
    const hardhatDisputeWallClockMs = Math.round(performance.now() - hardhatStart);
    hardhatResultPath = path.join(runDir, "hardhat_dispute_result.json");
    const hardhatResult = JSON.parse(await fs.readFile(hardhatResultPath, "utf8"));
    transactionLedger = hardhatResult.transactions ?? [];
    disputeSummary = readDecisionSummary(hardhatResult, hardhatDisputeWallClockMs);
    if (disputeSummary.honestDecision !== 1 ||
        disputeSummary.dishonestDecision !== 2 ||
        disputeSummary.operatorValid !== false ||
        disputeSummary.challengerValid !== true) {
      throw new Error(`${workload.id}: dispute did not slash dishonest operator correctly`);
    }
  }

  const row = {
    evaluationId,
    schemaVersion: EVALUATION_SCHEMA_VERSION,
    workloadId: workload.id,
    repetition,
    domain: workload.domain,
    title: workload.title,
    applicability: workload.applicability,
    limitation: workload.limitation,
    // Repo-relative: absolute paths in a committed CSV are unusable on any
    // other machine, and the previous artifacts carried a container home dir.
    runDir: repoRelative(runDir),
    loweringEngine: workload.lowering?.engineVersion,
    operationType: workload.lowering?.operationType,
    loweringWarnings: workload.lowering?.warnings ?? [],
    leafCount: workload.witnesses.length,
    opcodeCounts: summary.opcode_counts,
    microIsaSize: workload.lowering?.microIsaSize,
    microIsaVerified: workload.lowering?.microIsaVerified,
    manipulatedLeafIndex,
    manipulatedOpcode: workload.witnesses[manipulatedLeafIndex].opcode_name,
    disputeRun: config.runDisputes,
    offchainPreparationDurationMs,
    loweringDurationMs,
    artifactPreparationDurationMs,
    workloadWallClockMs: Math.round(performance.now() - workloadStart),
    hardhatResultPath: repoRelative(hardhatResultPath),
    ...disputeSummary,
    ...contextValues
  };
  rows.push(row);
  // `artifacts/runs/` is gitignored, so the per-run transaction ledger is
  // copied into the canonical JSON report. Without this the receipts backing
  // every gas figure do not survive into the repository.
  fullResults.push({ workload, summary, row, transactions: transactionLedger });
}

const csvPath = path.join(evaluationsDir, `${evaluationId}.csv`);
const latestCsvPath = path.join(evaluationsDir, "latest_application_layer_evaluation.csv");
const jsonPath = path.join(evaluationsDir, `${evaluationId}.json`);
const latestJsonPath = path.join(evaluationsDir, "latest_application_layer_evaluation.json");
// Long-format ("tidy") transaction ledger: one row per on-chain transaction.
// The wide per-workload CSV above answers "how much did the challenged path
// cost"; this one answers "which call cost what", which is what a per-mechanism
// table (e.g. the cost of a single `authorizeTaskStatement`) needs and what the
// previous artifacts could not express. Keeping it separate avoids widening the
// per-workload CSV with dozens of per-label columns.
const transactionsCsvPath = path.join(evaluationsDir, `${evaluationId}-transactions.csv`);
const latestTransactionsCsvPath = path.join(
  evaluationsDir,
  "latest_application_layer_transactions.csv"
);
const transactionColumns = [
  "evaluationId",
  "schemaVersion",
  "workloadId",
  "repetition",
  "txIndex",
  "label",
  "taskId",
  "gasUsed",
  "transactionCostWei",
  "blockNumber",
  "durationMs",
  "startedAtMs",
  "minedAtMs",
  "contextVenue",
  "contextNetwork",
  "contextChainId"
];
const transactionRows = fullResults.flatMap(({ row, transactions }) =>
  (transactions ?? []).map((tx, txIndex) => ({
    evaluationId,
    schemaVersion: EVALUATION_SCHEMA_VERSION,
    workloadId: row.workloadId,
    repetition: row.repetition,
    txIndex,
    label: tx.label ?? "",
    taskId: tx.taskId ?? "",
    gasUsed: tx.gasUsed ?? "",
    transactionCostWei: tx.transactionCostWei ?? "",
    blockNumber: tx.blockNumber ?? "",
    durationMs: tx.durationMs ?? "",
    startedAtMs: tx.startedAtMs ?? "",
    minedAtMs: tx.minedAtMs ?? "",
    contextVenue: runContext.venue,
    contextNetwork: runContext.network,
    contextChainId: runContext.chainId
  }))
);

const report = {
  schemaVersion: EVALUATION_SCHEMA_VERSION,
  evaluationId,
  startedAt: startedAt.toISOString(),
  finishedAt: new Date().toISOString(),
  // Where this ran, on what code, with which protocol parameters.
  context: runContext,
  config,
  status: "passed",
  claim:
    "Application-layer workloads are admissible when lowered to deterministic supported micro-instructions; contested leaves can be settled by the existing dispute game and local FHEVM verifier.",
  criticalBoundary:
    "Repeated fresh dispute deployments reuse one encrypted fixture per workload. Fault position is supplied by a controlled corruption fixture. This is neither independent fault detection nor repeated full-FHE execution, distributed MPC, or a matched replication baseline.",
  rows,
  artifacts: {
    csvPath: repoRelative(csvPath),
    latestCsvPath: repoRelative(latestCsvPath),
    transactionsCsvPath: repoRelative(transactionsCsvPath),
    latestTransactionsCsvPath: repoRelative(latestTransactionsCsvPath),
    jsonPath: repoRelative(jsonPath),
    latestJsonPath: repoRelative(latestJsonPath)
  },
  // Per-call gas, aggregated by transaction label across all workloads. This is
  // the source for per-mechanism cost tables; the long-format CSV holds the
  // unaggregated rows.
  gasByLabel: aggregateGasByLabel(fullResults),
  workloads: fullResults
};

await writeCsv(csvPath, rows, csvColumns);
await writeCsv(latestCsvPath, rows, csvColumns);
await writeCsv(transactionsCsvPath, transactionRows, transactionColumns);
await writeCsv(latestTransactionsCsvPath, transactionRows, transactionColumns);
await writeJson(jsonPath, report);
await writeJson(latestJsonPath, report);

printStep("Application-layer evaluation complete", [
  `rows=${rows.length}`,
  `transactions=${transactionRows.length}`,
  `venue=${runContext.venue} (chainId=${runContext.chainId || "unknown"})`,
  `csv=${repoRelative(csvPath)}`,
  `transactionsCsv=${repoRelative(transactionsCsvPath)}`,
  `json=${repoRelative(jsonPath)}`
]);
