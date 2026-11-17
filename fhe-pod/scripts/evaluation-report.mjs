/**
 * evaluation-report.mjs
 *
 * Shared module for building evaluation reports and exporting CSV/JSON artifacts.
 * Used by run-full-pipeline.mjs to generate evaluation-quality metrics.
 */

import fs from "node:fs/promises";
import path from "node:path";
import { projectRoot, writeJson, latestRunDir } from "./evm-lib.mjs";

export const evaluationsDir = path.join(projectRoot, "artifacts", "evaluations");

// ── CSV utilities ───────────────────────────────────────────────────────

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

// ── Wei helpers ─────────────────────────────────────────────────────────

function parseWei(v) { return v === undefined || v === null || v === "" ? 0n : BigInt(v); }
function sumWei(values) { return values.reduce((t, v) => t + parseWei(v), 0n); }
function positiveWei(v) { const p = parseWei(v); return p > 0n ? p : 0n; }
function negativeWeiAbs(v) { const p = parseWei(v); return p < 0n ? -p : 0n; }

// ── Report builders ─────────────────────────────────────────────────────

export function summarizeFheOperations(microTraceBundle, hardhatResults) {
  const witnesses = microTraceBundle.witnesses ?? [];
  const byOpcode = new Map();
  for (const w of witnesses) {
    const key = `${w.opcode}:${w.opcode_name ?? "UNKNOWN"}`;
    const cur = byOpcode.get(key) ?? { opcode: Number(w.opcode), name: w.opcode_name ?? "UNKNOWN", count: 0 };
    cur.count += 1;
    byOpcode.set(key, cur);
  }
  const rep = hardhatResults.at(-1) ?? {};
  return {
    totalMicroSteps: witnesses.length,
    opcodes: [...byOpcode.values()].sort((a, b) => a.opcode - b.opcode),
    supportedOperationSurface: {
      objectiveVerifierCount: rep.supportedOperations?.length ?? 0,
      fhevmVerifierCount: rep.supportedFhevmOperations?.length ?? 0,
      objectiveVerifierAllPassed: (rep.supportedOperations ?? []).every(
        (o) => o.acceptedCorrectClaim && o.rejectedWrongClaim
      ),
      fhevmVerifierAllPassed: (rep.supportedFhevmOperations ?? []).every(
        (o) => o.operatorValid === false && o.challengerValid === true &&
               o.finalizedOperatorValid === false && o.finalizedChallengerValid === true
      )
    },
    manipulatedLeafIndex: rep.manipulatedLeafIndex,
    honestLeaf: rep.honestLeaf,
    dishonestLeaf: rep.dishonestLeaf,
    fhevmResolution: rep.dishonestNode?.fhevmResolution ?? null
  };
}

export function summarizeDecisionProcess(hardhatResults) {
  const rep = hardhatResults.at(-1) ?? {};
  const dn = rep.dishonestNode ?? {};
  return {
    architecture: rep.architecture,
    localFhevm: rep.localFhevm,
    honestDecision: rep.honestNode?.decision,
    dishonestDecision: dn.decision,
    challenge: dn.challenge,
    bisectionRounds: dn.bisectionRounds ?? [],
    leafCheck: dn.leafCheck,
    dishonestStakeDeltaWei: dn.dishonestStakeDeltaWei,
    challengerStakeDeltaWei: dn.challengerStakeDeltaWei,
    repetitions: hardhatResults.map((r, i) => ({
      repetition: i + 1,
      honestDecision: r.honestNode?.decision,
      dishonestDecision: r.dishonestNode?.decision,
      leafIndex: r.dishonestNode?.leafCheck?.leafIndex,
      opcode: r.dishonestNode?.leafCheck?.opcode,
      operatorValid: r.dishonestNode?.leafCheck?.operatorValid,
      challengerValid: r.dishonestNode?.leafCheck?.challengerValid,
      transactionCount: r.transactions?.length ?? 0
    })),
    finalClaim:
      "The contested task is decided by FHEVM local leaf verification and on-chain slashing, not by auditor majority."
  };
}

export const adversarialScenarioMatrix = [
  {
    scenarioId: "optimistic_honest",
    maliciousParty: "none",
    claimTested: "An unchallenged honest FHE computation can finalize without bisection.",
    expectedOutcome: "OperatorAccepted"
  },
  {
    scenarioId: "malicious_operator_dissenting_auditor",
    maliciousParty: "operator",
    claimTested: "A single diligent dissenting auditor can defeat an incorrect operator even if other auditors support the operator.",
    expectedOutcome: "OperatorSlashed"
  },
  {
    scenarioId: "wrong_verdict_stage_scoping",
    maliciousParty: "auditor",
    claimTested: "Wrong-verdict slashing is limited to auditors assigned to the challenged stage.",
    expectedOutcome: "StageScopedSlashing"
  },
  {
    scenarioId: "invalid_pod_evidence",
    maliciousParty: "challenger",
    claimTested: "A challenge must reveal evidence already bound by the auditor's PoD commitment.",
    expectedOutcome: "ChallengeRejected"
  },
  {
    scenarioId: "false_challenger",
    maliciousParty: "challenger",
    claimTested: "A challenger is punished when the disputed leaf objectively supports the operator.",
    expectedOutcome: "ChallengerSlashed"
  },
  {
    scenarioId: "party_abandonment_during_bisection",
    maliciousParty: "operator_or_challenger",
    claimTested: "Same-side opened auditors can continue bisection if the original party stops responding.",
    expectedOutcome: "BisectionContinues"
  },
  {
    scenarioId: "challenge_bond_spam",
    maliciousParty: "challenger",
    claimTested: "Refundable dispute bonds limit concurrent low-cost challenge spam.",
    expectedOutcome: "BondEnforced"
  },
  {
    scenarioId: "local_fhevm_leaf_finality",
    maliciousParty: "operator",
    claimTested: "The isolated disputed micro-instruction is finalized by the on-chain FHEVM-compatible verifier.",
    expectedOutcome: "FhevmLeafResolved"
  },
  {
    scenarioId: "lazy_auditor_and_threshold_opening",
    maliciousParty: "auditor_or_single_revealer",
    claimTested: "A lazy auditor can be slashed and a single threshold participant cannot open a verdict alone.",
    expectedOutcome: "LazyAuditorSlashed"
  },
  {
    scenarioId: "operation_surface",
    maliciousParty: "operator",
    claimTested: "Every currently supported micro-opcode accepts correct claims and rejects wrong claims.",
    expectedOutcome: "AllSupportedOpcodesChecked"
  }
];

function buildAdversarialScenarioRows(evaluationId, config) {
  const suiteRan = config.adversarialTests === "passed";
  return adversarialScenarioMatrix.map((scenario) => ({
    evaluationId,
    ...scenario,
    coveredBy: "contracts/test/registry.test.mjs",
    status: suiteRan ? "passed" : "not_run",
    limitation: suiteRan
      ? "Regression scenario covered; not a randomized corruption-rate experiment."
      : "Skipped by --skip-tests; do not use this run as complete evaluation evidence."
  }));
}

// ── CSV row builders ────────────────────────────────────────────────────

function buildRepetitionCsvRows(evaluationId, runDir, config, hardhatResults, repetitionArtifacts) {
  return hardhatResults.map((result, index) => {
    const txs = result.transactions ?? [];
    const dn = result.dishonestNode ?? {};
    const lc = dn.leafCheck ?? {};
    const ch = dn.challenge ?? {};
    const dishonestSlash = negativeWeiAbs(dn.dishonestStakeDeltaWei);
    const challengerReward = positiveWei(dn.challengerStakeDeltaWei);
    const wrongVerdictSlash = challengerReward > dishonestSlash ? challengerReward - dishonestSlash : 0n;
    return {
      evaluationId,
      repetition: index + 1,
      runDir,
      hardhatArtifact: repetitionArtifacts[index],
      network: result.network,
      architecture: result.architecture,
      auditors: config.auditors,
      decryptors: config.decryptors,
      operators: config.operators ?? 2,
      manipulatedLeafIndex: result.manipulatedLeafIndex,
      assignedAuditors: (dn.assignedAuditors ?? []).join(";"),
      assignedDecryptors: (dn.assignedDecryptors ?? []).join(";"),
      leafIndex: lc.leafIndex,
      opcode: lc.opcode,
      honestDecision: result.honestNode?.decision,
      dishonestDecision: dn.decision,
      operatorValid: lc.operatorValid,
      challengerValid: lc.challengerValid,
      bisectionRoundCount: dn.bisectionRounds?.length ?? 0,
      transactionCount: txs.length,
      totalGasUsed: sumWei(txs.map((t) => t.gasUsed)).toString(),
      totalTransactionCostWei: sumWei(txs.map((t) => t.transactionCostWei)).toString(),
      dishonestOperatorSlashWei: dishonestSlash.toString(),
      wrongVerdictAuditorSlashWei: wrongVerdictSlash.toString(),
      totalSlashWei: challengerReward.toString(),
      challengerRewardWei: challengerReward.toString(),
      dishonestStakeDeltaWei: dn.dishonestStakeDeltaWei,
      challengerStakeDeltaWei: dn.challengerStakeDeltaWei,
      localFhevmVerifier: result.localFhevm?.verifier,
      objectiveVerifier: result.objectiveVerifier,
      challengeErrorDigest: ch.errorDigest,
      challengePodRoot: ch.podRoot
    };
  });
}

function buildTransactionCsvRows(evaluationId, allTransactions) {
  return allTransactions.map((tx) => ({
    evaluationId,
    repetition: tx.repetition,
    label: tx.label,
    hash: tx.hash,
    blockNumber: tx.blockNumber,
    status: tx.status,
    gasUsed: tx.gasUsed,
    gasPriceWei: tx.gasPriceWei,
    transactionCostWei: tx.transactionCostWei,
    taskId: tx.taskId,
    leafIndex: tx.leafIndex,
    opcode: tx.opcode,
    operatorValid: tx.operatorValid,
    challengerValid: tx.challengerValid,
    operator: tx.operator,
    auditor: tx.auditor,
    decryptor: tx.decryptor,
    challenger: tx.challenger,
    verifier: tx.verifier,
    address: tx.address,
    verdict: tx.verdict,
    podRoot: tx.podRoot,
    traceRoot: tx.traceRoot
  }));
}

function buildOperationCsvRows(evaluationId, microTraceBundle, hardhatResults) {
  const traceCounts = new Map();
  for (const w of microTraceBundle.witnesses ?? []) {
    traceCounts.set(Number(w.opcode), {
      opcode: Number(w.opcode),
      name: w.opcode_name ?? "UNKNOWN",
      traceCount: (traceCounts.get(Number(w.opcode))?.traceCount ?? 0) + 1
    });
  }
  const rep = hardhatResults.at(-1) ?? {};
  const fhevmByOpcode = new Map(
    (rep.supportedFhevmOperations ?? []).map((o) => [Number(o.opcode), o])
  );
  const manipulatedOpcode = Number(rep.honestLeaf?.opcode);
  return (rep.supportedOperations ?? []).map((o) => {
    const tc = traceCounts.get(Number(o.opcode));
    const fo = fhevmByOpcode.get(Number(o.opcode));
    return {
      evaluationId,
      opcode: o.opcode,
      name: o.name,
      traceCount: tc?.traceCount ?? 0,
      sampleLhs: o.sample?.lhs,
      sampleRhs: o.sample?.rhs,
      sampleClaimed: o.sample?.claimed,
      acceptedCorrectClaim: o.acceptedCorrectClaim,
      rejectedWrongClaim: o.rejectedWrongClaim,
      fhevmOperatorWrongRejected: fo?.operatorValid === false,
      fhevmChallengerCorrectAccepted: fo?.challengerValid === true,
      fhevmFinalizeOperatorWrongRejected: fo?.finalizedOperatorValid === false,
      fhevmFinalizeChallengerCorrectAccepted: fo?.finalizedChallengerValid === true,
      fhevmOperatorValidHandle: fo?.operatorValidHandle,
      fhevmChallengerValidHandle: fo?.challengerValidHandle,
      expression: o.expression,
      manipulated: Number(o.opcode) === manipulatedOpcode
    };
  });
}

// ── Column definitions ──────────────────────────────────────────────────

const repetitionColumns = [
  "evaluationId", "repetition", "runDir", "hardhatArtifact", "network",
  "architecture", "auditors", "decryptors", "operators", "manipulatedLeafIndex",
  "assignedAuditors", "assignedDecryptors", "leafIndex", "opcode",
  "honestDecision", "dishonestDecision", "operatorValid", "challengerValid",
  "bisectionRoundCount", "transactionCount", "totalGasUsed",
  "totalTransactionCostWei", "dishonestOperatorSlashWei",
  "wrongVerdictAuditorSlashWei", "totalSlashWei", "challengerRewardWei",
  "dishonestStakeDeltaWei", "challengerStakeDeltaWei",
  "localFhevmVerifier", "objectiveVerifier", "challengeErrorDigest", "challengePodRoot"
];

const transactionColumns = [
  "evaluationId", "repetition", "label", "hash", "blockNumber", "status",
  "gasUsed", "gasPriceWei", "transactionCostWei", "taskId", "leafIndex",
  "opcode", "operatorValid", "challengerValid", "operator", "auditor",
  "decryptor", "challenger", "verifier", "address", "verdict", "podRoot", "traceRoot"
];

const operationColumns = [
  "evaluationId", "opcode", "name", "traceCount", "sampleLhs", "sampleRhs",
  "sampleClaimed", "acceptedCorrectClaim", "rejectedWrongClaim",
  "fhevmOperatorWrongRejected", "fhevmChallengerCorrectAccepted",
  "fhevmFinalizeOperatorWrongRejected", "fhevmFinalizeChallengerCorrectAccepted",
  "fhevmOperatorValidHandle", "fhevmChallengerValidHandle",
  "expression", "manipulated"
];

const adversarialScenarioColumns = [
  "evaluationId", "scenarioId", "maliciousParty", "claimTested",
  "expectedOutcome", "coveredBy", "status", "limitation"
];

// ── Main export ─────────────────────────────────────────────────────────

/**
 * Generates the full evaluation report: JSON + 3 CSVs + latest symlinks.
 *
 * @param {object} opts
 * @param {string} opts.runDir - Path to the FHE run session
 * @param {object} opts.config - Pipeline config (auditors, decryptors, etc.)
 * @param {object[]} opts.hardhatResults - Array of parsed hardhat_dispute_result.json
 * @returns {object} report summary
 */
export async function generateEvaluationReport({ runDir, config, hardhatResults }) {
  const startedAt = new Date();
  const evaluationId = `evaluation-eval-${startedAt.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z")}`;

  await fs.mkdir(evaluationsDir, { recursive: true });

  // Read trace artifacts
  const [attestationPayload, microTraceBundle] = await Promise.all([
    fs.readFile(path.join(runDir, "attestation_payload.json"), "utf8").then(JSON.parse),
    fs.readFile(path.join(runDir, "micro_trace_bundle.json"), "utf8").then(JSON.parse)
  ]);

  // Copy per-repetition results
  const repetitionArtifacts = [];
  for (let i = 0; i < hardhatResults.length; i++) {
    const target = path.join(evaluationsDir, `${evaluationId}-hardhat-repetition-${i + 1}.json`);
    const enriched = { ...hardhatResults[i], evaluationEvaluationId: evaluationId, repetition: i + 1 };
    await writeJson(target, enriched);
    repetitionArtifacts.push(target);
  }

  // Build all transactions list
  const allTransactions = hardhatResults.flatMap((r, i) =>
    (r.transactions ?? []).map((tx) => ({ repetition: i + 1, ...tx }))
  );

  // Build CSV rows
  const repetitionRows = buildRepetitionCsvRows(evaluationId, runDir, config, hardhatResults, repetitionArtifacts);
  const transactionRows = buildTransactionCsvRows(evaluationId, allTransactions);
  const operationRows = buildOperationCsvRows(evaluationId, microTraceBundle, hardhatResults);
  const adversarialScenarioRows = buildAdversarialScenarioRows(evaluationId, config);

  // Write CSVs (timestamped + latest)
  const csvPaths = {
    repetitions: path.join(evaluationsDir, `${evaluationId}-repetitions.csv`),
    transactions: path.join(evaluationsDir, `${evaluationId}-transactions.csv`),
    operations: path.join(evaluationsDir, `${evaluationId}-operations.csv`),
    adversarialScenarios: path.join(evaluationsDir, `${evaluationId}-adversarial-scenarios.csv`),
    latestRepetitions: path.join(evaluationsDir, "latest_evaluation_evaluation_repetitions.csv"),
    latestTransactions: path.join(evaluationsDir, "latest_evaluation_evaluation_transactions.csv"),
    latestOperations: path.join(evaluationsDir, "latest_evaluation_evaluation_operations.csv"),
    latestAdversarialScenarios: path.join(evaluationsDir, "latest_evaluation_evaluation_adversarial_scenarios.csv")
  };

  await writeCsv(csvPaths.repetitions, repetitionRows, repetitionColumns);
  await writeCsv(csvPaths.latestRepetitions, repetitionRows, repetitionColumns);
  await writeCsv(csvPaths.transactions, transactionRows, transactionColumns);
  await writeCsv(csvPaths.latestTransactions, transactionRows, transactionColumns);
  await writeCsv(csvPaths.operations, operationRows, operationColumns);
  await writeCsv(csvPaths.latestOperations, operationRows, operationColumns);
  await writeCsv(csvPaths.adversarialScenarios, adversarialScenarioRows, adversarialScenarioColumns);
  await writeCsv(csvPaths.latestAdversarialScenarios, adversarialScenarioRows, adversarialScenarioColumns);

  // Build full report
  const report = {
    evaluationId,
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    status: "passed",
    focus: "Evaluation evaluation pipeline for FHE off-chain execution, PoD auditing, FHEVM dispute finality and slashing.",
    config,
    runDir,
    artifacts: {
      runDir,
      attestationPayload: path.join(runDir, "attestation_payload.json"),
      microTraceBundle: path.join(runDir, "micro_trace_bundle.json"),
      latestHardhatDisputeResult: path.join(runDir, "hardhat_dispute_result.json"),
      hardhatRepetitionResults: repetitionArtifacts,
      csv: csvPaths
    },
    fheOperations: summarizeFheOperations(microTraceBundle, hardhatResults),
    transactions: allTransactions,
    decisionProcess: summarizeDecisionProcess(hardhatResults),
    adversarialScenarios: adversarialScenarioRows,
    resultHash: attestationPayload.result_hash_sha256,
    aggregate: {
      repetitions: hardhatResults.length,
      transactionCount: allTransactions.length,
      totalGasUsed: sumWei(allTransactions.map((t) => t.gasUsed)).toString(),
      totalTransactionCostWei: sumWei(allTransactions.map((t) => t.transactionCostWei)).toString(),
      allDishonestOperatorsSlashed: hardhatResults.every((r) => r.dishonestNode?.decision === 2),
      allHonestOperatorsAccepted: hardhatResults.every((r) => r.honestNode?.decision === 1),
      csvRows: {
        repetitions: repetitionRows.length,
        transactions: transactionRows.length,
        operations: operationRows.length,
        adversarialScenarios: adversarialScenarioRows.length
      }
    }
  };

  // Write JSON reports
  const evaluationPath = path.join(evaluationsDir, `${evaluationId}.json`);
  const latestPath = path.join(evaluationsDir, "latest_evaluation_evaluation.json");
  await writeJson(evaluationPath, report);
  await writeJson(latestPath, report);

  return {
    evaluationId,
    evaluationPath,
    latestPath,
    csvPaths,
    aggregate: report.aggregate
  };
}
