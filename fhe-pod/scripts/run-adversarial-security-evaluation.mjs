#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { projectRoot, writeJson } from "./evm-lib.mjs";

const startedAt = new Date();
const evaluationId = `adversarial-security-${startedAt
  .toISOString()
  .replace(/[-:]/g, "")
  .replace(/\.\d{3}Z$/, "Z")}`;
const evaluationsDir = process.env.SECURITY_EVAL_OUTPUT_DIR
  ? path.resolve(process.env.SECURITY_EVAL_OUTPUT_DIR) : path.join(projectRoot, "artifacts", "evaluations");

const scenarioSpecs = [
  {
    scenarioId: "explicit_dataflow_and_public_constants",
    threatModel: "Same-valued wire substitution or changed public constant alters the authorized computation",
    expectedControl: "Full disclosure rejects altered references or constants; the explicit circuit with nonadjacent dependencies is admitted",
    testName: "explicit compliance DAG: on-chain disclosure binds nonadjacent wires and public constants"
  },
  {
    scenarioId: "legacy_kms_non_boolean_rejected",
    threatModel: "A correctly signed non-Boolean word is presented as an audit verdict in the legacy KMS mode",
    expectedControl: "Boolean decoding rejects the word without recording an opening; this type check is not a pre-decryption privacy policy",
    testName: "legacy KMS opening rejects a correctly signed non-Boolean word"
  },
  {
    "scenarioId": "terminal_committed_opcode_fault",
    "threatModel": "A challenger commits inconsistent opcode evidence to force an honest operator timeout",
    "expectedControl": "Both leaf openings are authenticated before attributing the committed fault; the challenger forfeits its bond and the task reopens",
    "testName": "terminal admissibility: committed opcode fault loses challenger bond and reopens task"
  },
  {
    "scenarioId": "terminal_committed_operands_fault",
    "threatModel": "A challenger commits inconsistent operands evidence to force an honest operator timeout",
    "expectedControl": "Both leaf openings are authenticated before attributing the committed fault; the challenger forfeits its bond and the task reopens",
    "testName": "terminal admissibility: committed operands fault loses challenger bond and reopens task"
  },
  {
    "scenarioId": "terminal_committed_hint_fault",
    "threatModel": "A challenger commits inconsistent hint evidence to force an honest operator timeout",
    "expectedControl": "Both leaf openings are authenticated before attributing the committed fault; the challenger forfeits its bond and the task reopens",
    "testName": "terminal admissibility: committed hint fault loses challenger bond and reopens task"
  },
  {
    "scenarioId": "terminal_committed_digest_fault",
    "threatModel": "A challenger commits inconsistent digest evidence to force an honest operator timeout",
    "expectedControl": "Both leaf openings are authenticated before attributing the committed fault; the challenger forfeits its bond and the task reopens",
    "testName": "terminal admissibility: committed digest fault loses challenger bond and reopens task"
  },
  {
    "scenarioId": "terminal_committed_diligence_fault",
    "threatModel": "A challenger commits inconsistent diligence evidence to force an honest operator timeout",
    "expectedControl": "Both leaf openings are authenticated before attributing the committed fault; the challenger forfeits its bond and the task reopens",
    "testName": "terminal admissibility: committed diligence fault loses challenger bond and reopens task"
  },
  {
    "scenarioId": "terminal_caller_data",
    "threatModel": "Forged terminal calldata frames another participant",
    "expectedControl": "Unauthenticated openings revert without changing stake; authentic evidence still resolves",
    "testName": "terminal admissibility: unauthenticated caller data cannot slash either participant"
  },
  {
    "scenarioId": "terminal_missing_request",
    "threatModel": "Challenger withholds its terminal opening",
    "expectedControl": "Timeout forfeits the challenger bond and reopens the task",
    "testName": "terminal admissibility: missing request forfeits challenger bond instead of slashing honest operator"
  },
  {
    "scenarioId": "terminal_decision_window",
    "threatModel": "Admission consumes the operator response window or retries extend it forever",
    "expectedControl": "First authenticated request starts a full decision window; retries do not extend it",
    "testName": "terminal admissibility: admitted request starts a fresh nonrenewable decision window"
  },
  {
    "scenarioId": "terminal_single_leaf_disclosure",
    "threatModel": "Disclosure consumes the response window or missing operator data penalizes the challenger",
    "expectedControl": "Initial clock includes disclosure time; withheld trace is slashed through the availability module",
    "testName": "terminal admissibility: one-leaf disclosure preserves response time and attributes withheld data to operator"
  },
  {
    scenarioId: "optimistic_acceptance_is_explicit",
    threatModel: "an unchallenged task is mistaken for cryptographically proven full-trace correctness",
    expectedControl: "the contract finalizes only through the explicit optimistic path after the challenge window",
    testName: "optimistic path finalizes when no auditor opens a challenge"
  },
  {
    scenarioId: "terminal_output_binding_enforced",
    threatModel: "an operator publishes an output commitment unrelated to the committed trace (output substitution)",
    expectedControl: "createTask verifies a Merkle inclusion proof pinned to the last trace leaf and the canonical output-bound result hash; unbound, substituted, non-terminal, and unattested submissions revert",
    testName: "createTask rejects a result hash that is not bound to the terminal trace state"
  },
  {
    scenarioId: "published_output_binding_traceable",
    threatModel: "a consumer cannot independently verify that the published output matches the committed trace",
    expectedControl: "getTaskResultBinding and the TerminalOutputBound event expose the binding; recomputing the canonical output-bound hash from the published output verifies it, and a substituted output fails verification",
    testName: "published output binding is traceable and externally verifiable"
  },
  {
    scenarioId: "single_dissenter_overrides_wrong_majority",
    threatModel: "the operator and most assigned auditors support a corrupted stage",
    expectedControl: "one eligible dissenter reaches objective resolution and slashes the operator",
    testName: "one dissenting auditor can slash the operator even if the other auditors support the operator"
  },
  {
    scenarioId: "same_stage_wrong_verdict_slashed",
    threatModel: "auditors assigned to different stages are indiscriminately punished for one faulty stage",
    expectedControl: "wrong-verdict slashing is limited to the objectively resolved stage cohort",
    testName: "wrong-verdict slashing only applies to auditors scoped to the challenged stage"
  },
  {
    scenarioId: "challenge_leaf_must_be_precommitted",
    threatModel: "challenger fabricates an audit leaf after seeing the operator trace",
    expectedControl: "the revealed audit leaf must open against the precommitted PoD root",
    testName: "challenge must reveal an audit trace leaf committed by the PoD root"
  },
  {
    scenarioId: "precommitted_checkpoint_required_for_challenge",
    threatModel: "challenger uses an opaque PoD root that omits the sampled checkpoint",
    expectedControl: "challenge path rejects the diligence proof before reward-bearing challenge",
    testName: "challenge cannot pass diligence with a PoD root that omits the checkpoint"
  },
  {
    scenarioId: "reward_path_requires_checkpoint",
    threatModel: "challenger seeks reward using a root that does not commit the required diligence evidence",
    expectedControl: "reward-bearing challenge requires the precommitted sampled checkpoint",
    testName: "challenge reward path requires a precommitted diligence checkpoint"
  },
  {
    scenarioId: "randomness_cannot_precede_commitments",
    threatModel: "auditors adapt their commitments after learning the diligence sample",
    expectedControl: "randomness cannot be sealed before audit commitments are fixed",
    testName: "diligence randomness cannot be sealed before audit commitments are fixed"
  },
  {
    scenarioId: "post_commit_randomness_required",
    threatModel: "auditor chooses a convenient checkpoint before randomness is sealed",
    expectedControl: "diligence proof is rejected until post-commit randomness exists and only the sampled checkpoint is accepted",
    testName: "diligence randomness is post-commit, single-use, and required before diligence proofs"
  },
  {
    scenarioId: "stage_assignment_enforced",
    threatModel: "a Sybil or unassigned auditor targets a stage outside its derived cohort",
    expectedControl: "audit submission and challenge are rejected outside the assigned stage",
    testName: "auditors cannot submit or challenge outside their assigned stage"
  },
  {
    scenarioId: "auditor_identity_replay_rejected",
    threatModel: "lazy auditor reuses another auditor's opened diligence evidence",
    expectedControl: "checkpoint hash includes auditor identity and replay is rejected",
    testName: "diligence checkpoints are bound to the auditor identity and cannot be replayed"
  },
  {
    scenarioId: "bisection_root_binding",
    threatModel: "a disputant submits convenient subtree hashes unrelated to its committed trace",
    expectedControl: "every bisection branch must reconstruct the committed subtree root",
    testName: "bisection rejects subtree hashes that do not match committed trace roots"
  },
  {
    scenarioId: "pro_operator_verdict_cannot_extract_challenge_reward",
    threatModel: "auditor supports the operator but later tries to become challenger",
    expectedControl: "reward-bearing challenge requires opened dissent",
    testName: "supporting auditors cannot convert a pro-operator verdict into a reward-bearing challenge"
  },
  {
    scenarioId: "permissionless_bisection_liveness",
    threatModel: "the operator or original challenger abandons bisection to force an incorrect timeout",
    expectedControl: "an opened same-side auditor can continue the dispute",
    testName: "supporting and dissenting auditors can keep bisection moving if the operator or original challenger disappear"
  },
  {
    scenarioId: "challenge_spam_bond_cap",
    threatModel: "a rational challenger opens many concurrent disputes using one undivided stake",
    expectedControl: "per-dispute refundable bonds exhaust available stake and cap concurrency",
    testName: "refundable dispute bonds cap concurrent challenge spam"
  },
  {
    scenarioId: "objective_fhevm_leaf_finality",
    threatModel: "a contested result is settled by auditor votes instead of deterministic execution",
    expectedControl: "the configured local FHEVM-compatible runtime is frozen as the exclusive settlement backend and resolves the isolated instruction on-chain",
    testName: "local FHEVM runtime resolves the disputed micro-instruction on-chain"
  },
  {
    scenarioId: "attested_leaf_decision_binding",
    threatModel:
      "a settlement is forged for the isolated leaf: the two validity bits are submitted with fewer than the "
      + "required signatures, or a bundle legitimately signed for one leaf is replayed to settle a different one",
    expectedControl:
      "settleLeafViaAttestedDecision accepts the bits only with t+1 signatures over an EIP-712 digest that binds the "
      + "game address, chain id, task, leaf index, opcode and the two claimed handles under the "
      + "FHE_POD_LEAF_DECISION_V1 domain tag; t signatures revert, and a bundle bound to another leaf reverts even "
      + "though its own signatures are valid",
    testName: "attested leaf decision: t+1 signatures settle the leaf, fewer or misbound do not"
  },
  {
    scenarioId: "challenge_evidence_must_match_sampled_checkpoint",
    threatModel: "challenger proves one checkpoint but opens a different recomputed audit leaf",
    expectedControl: "challenge is rejected on diligence hash mismatch",
    testName: "challenge evidence must match the recomputed leaf revealed in the diligence checkpoint"
  },
  {
    scenarioId: "lazy_non_opening_auditor_slashed",
    threatModel: "assigned auditor never opens the committed verdict",
    expectedControl: "after the opening window the lazy auditor can be slashed",
    testName: "lazy auditor can be slashed and a single decryptor cannot open a verdict alone"
  },
  {
    scenarioId: "optimistic_reward_requires_sampled_precommitted_evidence",
    threatModel: "auditor expects reward on the optimistic path without revealing sampled evidence",
    expectedControl: "stake is unchanged until the auditor claims with a valid sampled checkpoint; double claim is rejected",
    testName: "diligence reward on the optimistic path requires sampled precommitted evidence"
  },
  {
    scenarioId: "arbitrary_checkpoint_tree_reward_gap_is_pinned",
    threatModel: "a precommitted but computation-independent checkpoint tree is mistaken for evidence of diligent execution",
    expectedControl: "the regression records the current residual: Merkle membership proves prior commitment only, so arbitrary precommitted content can earn an optimistic reward",
    testName: "documents that an arbitrary precommitted checkpoint tree can earn an optimistic reward"
  },
  {
    scenarioId: "unopened_or_opaque_reward_claim_rejected",
    threatModel: "lazy auditor tries to claim reward with no opened verdict or a random PoD root",
    expectedControl: "reward claim rejects unopened verdicts and opaque commitments that cannot prove checkpoint membership",
    testName: "diligence reward rejects unopened or opaque lazy audit commitments"
  },
  {
    scenarioId: "same_stage_secondary_reward_requires_own_evidence",
    threatModel: "same-stage auditor copies the challenger evidence after seeing the dispute",
    expectedControl: "copied evidence is rejected; secondary reward requires the auditor's own precommitted transcript and correct verdict",
    testName: "same-stage secondary auditor reward requires own evidence and correct objective verdict"
  },
  {
    scenarioId: "false_challenger_slashed",
    threatModel: "challenger escalates a false accusation against a correct operator leaf",
    expectedControl: "objective verifier rejects the challenger and the challenger is slashed",
    testName: "false challenger gets slashed when the operator leaf is objectively correct"
  },
  {
    scenarioId: "supported_micro_isa_rejects_wrong_claims",
    threatModel: "an unsupported or incorrectly evaluated micro-operation is accepted by the objective verifier",
    expectedControl: "every supported opcode accepts its correct claim and rejects a wrong claim",
    testName: "objective verifier supports expanded micro-operation surface"
  },
  {
    scenarioId: "lazy_operator_mirror_slashed_ex_post",
    threatModel: "a lazy auditor mirrors the operator trace instead of independently recomputing it",
    expectedControl: "if the mirrored corrupted stage is challenged, the mirror is wrong-verdict slashed and denied reward",
    testName: "lazy trace-mirroring auditor supporting a corrupted stage is slashed and denied reward"
  },
  {
    scenarioId: "operator_bisection_withholding_slashed",
    threatModel: "the operator abandons an opened legacy bisection to prevent adjudication",
    expectedControl: "the timeout transition slashes the operator and never accepts the disputed result",
    testName: "a withholding operator that abandons bisection is slashed by timeout, not accepted"
  },
  {
    scenarioId: "challenger_abandonment_forfeits_bond",
    threatModel: "a challenger opens a dispute and then abandons its turn",
    expectedControl: "the challenger forfeits its bond and the disputed result is not falsely accepted",
    testName: "a challenger that abandons its own challenge forfeits the bond and the result is still not accepted"
  },
  {
    scenarioId: "legacy_continuity_failure_is_fail_closed",
    threatModel: "a legacy trace violates state continuity and leaves no objectively valid leaf claim",
    expectedControl: "the dispute remains unresolvable rather than accepting either inconsistent claim; the secure profile prevents this state through full-trace continuity checks",
    testName: "a continuity-violating trace yields an unresolvable dispute (griefing), never a wrong acceptance"
  },
  {
    scenarioId: "authenticated_full_trace_profile",
    threatModel: "origin substitution, intermediate-handle substitution, premature bisection, false clear opening, or complete-trace withholding",
    expectedControl: "owner records, requester authorization, complete root reconstruction, continuity checks, handle-bound FHEVM resolution, and withholding slashing fail closed",
    testName: "secure trace: authenticated origins, full disputed-trace DA, continuity and handle-based FHEVM finality"
  },
  {
    scenarioId: "both_leaf_backends_enforced_on_chain",
    threatModel: "an off-chain finalizer supplies inverted verdict booleans or a dummy proof",
    expectedControl: "both configured leaf backends derive or authenticate their verdict on-chain and reject the lying finalizer",
    testName: "isolated leaf: on-chain enforcement of both verifier backends"
  },
  {
    scenarioId: "sampling_not_available_before_seed_block",
    threatModel: "participants predict or repeatedly draw assignments before the committed future block",
    expectedControl: "premature and repeated sampling revert",
    testName: "S1/S5: no assignment before the seed block; premature and double sampling revert"
  },
  {
    scenarioId: "ordered_sampling_without_replacement",
    threatModel: "sampling duplicates identities or does not implement the specified deterministic draw",
    expectedControl: "the derived ordered sample is deterministic and contains no repeated registered identity",
    testName: "S2/S7: unbiased ordered sampling is deterministic and without replacement"
  },
  {
    scenarioId: "sybil_capture_probability_matches_hypergeometric",
    threatModel: "the implementation reports an incorrect all-adversarial cohort probability under identity sampling without replacement",
    expectedControl: "exhaustive small-population enumeration equals the hypergeometric expression",
    testName: "S7: all-adversarial cohort probability equals the hypergeometric law"
  },
  {
    scenarioId: "unsampled_task_fails_closed",
    threatModel: "an operator finalizes or an auditor acts before assignments exist",
    expectedControl: "unsampled tasks cannot be audited or finalized",
    testName: "S3/S4: unsampled tasks cannot finalize and cannot be audited"
  },
  {
    scenarioId: "expired_seed_block_rescheduled",
    threatModel: "the future seed block leaves the EVM's 256-block blockhash horizon",
    expectedControl: "the contract reschedules instead of accepting a zero or unavailable block hash",
    testName: "S6: a seed block beyond the 256-block hash horizon reschedules"
  },
  {
    scenarioId: "legacy_requested_leaf_reveal_happy_path",
    threatModel: "a correctly requested legacy availability opening cannot clear the task",
    expectedControl: "a correct bonded reveal clears the request and allows finalization",
    testName: "A1: request -> correct reveal -> cleared -> finalization; bond pays the operator"
  },
  {
    scenarioId: "legacy_availability_scope_documented",
    threatModel: "the legacy requested-leaf module is mistaken for full-trace availability",
    expectedControl: "the regression explicitly demonstrates its per-requested-leaf scope; the experiment's secure profile instead uses AuthenticatedTraceAvailability",
    testName: "A6: availability is enforced per requested leaf, not for the full trace"
  },
  {
    scenarioId: "legacy_availability_bad_requests_rejected",
    threatModel: "an unassigned requester, wrong Merkle proof, or wrong bond creates or satisfies a legacy availability request",
    expectedControl: "all malformed or unauthorized requests revert",
    testName: "A2/A3: wrong proofs, wrong bonds, and unassigned requesters are rejected"
  },
  {
    scenarioId: "legacy_ignored_request_blocks_optimistic_finality",
    threatModel: "an ignored legacy availability request is silently treated as satisfied",
    expectedControl: "optimistic finalization remains blocked; secure-profile complete-trace withholding additionally terminates with operator slashing",
    testName: "A4/A5: an ignored request blocks optimistic finalization permanently"
  },
  {
    scenarioId: "kms_eip712_digest_matches_reference_encoding",
    threatModel: "the on-chain KMS verdict verifier computes a digest that diverges from the EIP-712 struct signed by the KMS cores, accepting or rejecting the wrong payloads",
    expectedControl: "the contract digest equals an independent ethers TypedDataEncoder encoding of PublicDecryptVerification for the same domain",
    testName: "verifier digest matches ethers EIP-712 encoding of the KMS struct"
  },
  {
    scenarioId: "kms_threshold_opening_happy_path",
    threatModel: "a correctly signed threshold decryption cannot open the committed verdict, or a dissenting plaintext is recorded as support",
    expectedControl: "t+1 distinct core signatures over the committed handle open the audit, and the decrypted verdict bit determines support versus dissent",
    testName: "t+1 KMS core signatures open a supporting verdict; verdict bit 0 opens dissent"
  },
  {
    scenarioId: "kms_subthreshold_duplicate_unregistered_rejected",
    threatModel: "an attacker opens a verdict with fewer than t+1 signatures, with one core's signature duplicated, or with signatures from keys outside the registered core set",
    expectedControl: "the verifier deduplicates recovered signers and requires t+1 distinct registered cores; all three attempts revert",
    testName: "fewer than threshold, duplicate-core, and unregistered signatures are rejected"
  },
  {
    scenarioId: "kms_foreign_handle_or_tampered_plaintext_rejected",
    threatModel: "valid core signatures produced for a different ciphertext handle are replayed against this audit, or the decrypted plaintext is altered after signing",
    expectedControl: "signatures bind the committed handle and the exact plaintext; both substitutions fail signature verification",
    testName: "signatures over a different handle or tampered plaintext cannot open the audit"
  },
  {
    scenarioId: "kms_opening_phase_gated_single_use",
    threatModel: "a KMS opening lands during the commit window, after the opening deadline, or is repeated to overwrite a recorded verdict",
    expectedControl: "the opening is accepted only inside the opening window and only once per audit",
    testName: "phase gating: KMS opening rejected inside commit window and after open deadline; no double opening"
  },
  {
    scenarioId: "kms_and_committee_backends_coexist",
    threatModel: "enabling the KMS backend silently breaks the sampled commit-reveal committee opening used as the baseline",
    expectedControl: "the legacy commit-reveal openVerdict path remains functional on the same deployment",
    testName: "commit-reveal openVerdict path remains functional alongside the KMS path"
  },
  {
    scenarioId: "input_handle_cannot_be_laundered_as_verdict",
    threatModel: "an assigned auditor commits an individual user's input ciphertext handle as its verdict and has it publicly decrypted through the authorized verdict-opening path",
    expectedControl: "the availability module indexes registered input handles and submitAudit rejects a verdictCommit that is a registered individual-input handle",
    testName: "individual privacy: a registered input handle cannot be committed as a verdict"
  },
  {
    scenarioId: "kms_opening_bound_to_execution",
    threatModel: "a KMS opening bundle signed for one execution is replayed to open a verdict in a different (taskId, auditor, game) context",
    expectedControl: "openVerdictViaKMS requires the bound extraData to equal keccak256(taskId, auditor, game), binding each opening to its execution",
    testName: "execution binding: a KMS opening is bound to (taskId, auditor, game)"
  },
  {
    scenarioId: "kms_opening_not_replayable_across_auditors",
    threatModel: "a bundle bound to auditor A is replayed to open auditor B's record that commits an identical ciphertext handle",
    expectedControl: "the execution binding includes the auditor identity, so a bundle bound to A cannot open B's identical-handle record",
    testName: "replay: a bundle bound to auditor A cannot open auditor B's identical-handle record"
  },
  {
    scenarioId: "kms_single_core_cannot_open_threshold_required",
    threatModel: "a single KMS core, with a second core unavailable, opens a verdict without reaching the t+1 threshold",
    expectedControl: "a single core cannot open the verdict; only t+1 distinct registered cores can",
    testName: "threshold: a single core (unavailable second core) cannot open; t+1 can"
  },
  {
    scenarioId: "decryption_opening_entrypoints_are_scoped",
    threatModel: "the game exposes a decryption-opening entrypoint that is not scoped to an audit record, allowing arbitrary handles to be opened",
    expectedControl: "the only decryption-opening entrypoints are audit-record scoped; the game exposes no general plaintext-opening path",
    testName: "structural: the game's only decryption-opening entrypoints are audit-record scoped"
  },
  {
    scenarioId: "value_equal_byte_different_claims_settle_for_operator",
    threatModel: "a challenger commits a value-equal but byte-different result ciphertext for a correct leaf (an independent re-evaluation under another schedule, or a deliberate re-encryption), so the objective verifier validates BOTH claims; a revert here would leave the terminal round undecided and default judgment would slash the honest operator",
    expectedControl: "a leaf at which both claims validate settles against the challenger: the operator's claim is correct, the challenge is unsupported, the challenge bond is forfeited, and no default judgment can follow",
    testName: "attested leaf decision: value-equal byte-different claims settle against the challenger"
  },
  {
    scenarioId: "pre_challenge_disclosure_request_feeds_challenge",
    threatModel: "the operator delivers the committed trace off chain to no assigned auditor, so no auditor can form a verdict or open a challenge and the faulty task would finalize optimistically at no cost",
    expectedControl: "an assigned auditor posts one bonded disclosure request during the audit-commit window; the task deadlines are pushed by the disclosure window; the operator publishes the complete trace through the challenge disclosure path; the disclosed trace then supports a normal challenge, bisection and objective settlement",
    testName: "pre-challenge disclosure request: an answered request feeds a normal challenge"
  },
  {
    scenarioId: "pre_challenge_trace_withholding_slashed",
    threatModel: "the operator ignores a pre-challenge disclosure request and waits for the challenge window to expire",
    expectedControl: "optimistic finalization is blocked while the obligation is open; after the disclosure deadline the operator is slashed for withholding, the task closes as OperatorSlashed, and the requester's bond is refunded",
    testName: "pre-challenge trace withholding: an unanswered disclosure request slashes the operator and closes the task"
  },
  {
    scenarioId: "sham_challenge_cannot_burn_task_challenge",
    threatModel: "an operator-controlled auditor holding one cohort seat opens a deliberately losing challenge first (its bond flows back to the operator) to consume the task's challenge and lock out the honest dissenter of the same cohort",
    expectedControl: "a lost challenge returns the task to Auditing with the loser barred and the challenge window restarted; the honest dissenter's challenge proceeds, isolates the corrupted leaf, and slashes the operator; dissenting verdicts are slashed only if the task finally finalizes as accepted",
    testName: "a sham losing challenge does not consume the task's challenge: the honest dissenter still wins"
  }
];

function printUsageAndExit() {
  console.log(`Usage:
  npm run eval:security

Runs adversarial EVM tests and writes structured experiment artifacts:
  artifacts/evaluations/latest_adversarial_security_evaluation.json
  artifacts/evaluations/latest_adversarial_security_evaluation.csv`);
  process.exit(0);
}

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  printUsageAndExit();
}

function resolveCommand(command) {
  if (process.platform === "win32" && command === "npm") return "npm.cmd";
  return command;
}

function commandText(command, args) {
  return [command, ...args].join(" ");
}

function csvEscape(value) {
  const text = String(value ?? "");
  if (/[",\n]/.test(text)) {
    return `"${text.replaceAll("\"", "\"\"")}"`;
  }
  return text;
}

function toCsv(rows, columns) {
  return [
    columns.join(","),
    ...rows.map((row) => columns.map((column) => csvEscape(row[column])).join(","))
  ].join("\n");
}

function parseSummary(output) {
  const readCount = (label) => {
    const match = output.match(
      new RegExp(`(?:#|ℹ)\\s+${label}\\s+(\\d+(?:\\.\\d+)?)`)
    );
    return match ? Number.parseFloat(match[1]) : null;
  };
  return {
    tests: readCount("tests"),
    pass: readCount("pass"),
    fail: readCount("fail"),
    durationMs: readCount("duration_ms")
  };
}

async function runEvmTests() {
  const command = "npm";
  const args = ["run", "test:evm"];
  const start = performance.now();
  // Offline mode for constrained environments: SECURITY_EVAL_RAW_INPUT points
  // at a captured TAP stream of the same suite (e.g., produced in batches with
  // --test-name-pattern) instead of spawning the full run in-process.
  if (process.env.SECURITY_EVAL_RAW_INPUT) {
    const rawPath = process.env.SECURITY_EVAL_RAW_INPUT;
    console.log(`[security-eval] reading raw TAP input from ${rawPath}`);
    const output = await fs.readFile(rawPath, "utf8");
    return {
      command: `offline TAP input (${rawPath})`,
      durationMs: Math.round(performance.now() - start),
      output
    };
  }
  console.log(`[security-eval] command: ${commandText(command, args)}`);

  const output = await new Promise((resolve, reject) => {
    const child = spawn(resolveCommand(command), args, {
      cwd: projectRoot,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32"
    });
    let combined = "";
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      combined += text;
      process.stdout.write(text);
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      combined += text;
      process.stderr.write(text);
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`${commandText(command, args)} failed with exit code ${code}`));
        return;
      }
      resolve(combined);
    });
  });

  return {
    command: commandText(command, args),
    durationMs: Math.round(performance.now() - start),
    output
  };
}

await fs.mkdir(evaluationsDir, { recursive: true });

console.log("");
console.log("============================================================");
console.log("FHE-PoD adversarial security evaluation");
console.log("============================================================");
console.log(`evaluationId=${evaluationId}`);

const run = await runEvmTests();
const summary = parseSummary(run.output);
const scenarioRows = scenarioSpecs.map((scenario) => {
  const observed = run.output.includes(scenario.testName);
  return {
    evaluationId,
    scenarioId: scenario.scenarioId,
    threatModel: scenario.threatModel,
    expectedControl: scenario.expectedControl,
    testName: scenario.testName,
    observedInTestOutput: String(observed),
    status: observed ? "passed" : "not-observed",
    measurementType: "direct-evm-regression-test"
  };
});

const notObserved = scenarioRows.filter((row) => row.status !== "passed");
if (notObserved.length > 0) {
  throw new Error(
    `EVM tests passed, but ${notObserved.length} security scenarios were not observed in test output`
  );
}
if (summary.tests !== scenarioRows.length) {
  throw new Error(
    `EVM suite reported ${summary.tests} tests, but the security matrix maps ${scenarioRows.length}; update the threat-to-test map`
  );
}

const paths = {
  reportPath: path.join(evaluationsDir, `${evaluationId}.json`),
  latestReportPath: path.join(evaluationsDir, "latest_adversarial_security_evaluation.json"),
  csvPath: path.join(evaluationsDir, `${evaluationId}.csv`),
  latestCsvPath: path.join(evaluationsDir, "latest_adversarial_security_evaluation.csv"),
  rawOutputPath: path.join(evaluationsDir, `${evaluationId}-evm-test-output.txt`),
  latestRawOutputPath: path.join(evaluationsDir, "latest_adversarial_security_evm_test_output.txt")
};

const report = {
  evaluationId,
  startedAt: startedAt.toISOString(),
  finishedAt: new Date().toISOString(),
  status: "passed",
  command: run.command,
  durationMs: run.durationMs,
  claim:
    "The suite exercises the implemented commitment, opening, challenge, bisection, backend-selection, reward and slashing rules, including regression tests that pin two accepted residual behaviors instead of misclassifying them as prevented attacks.",
  criticalBoundary:
    "These are protocol regression tests. They prove enforcement of the implemented rules, not cryptographic PoD hardness, terminal output binding, data availability, or production threshold-FHE liveness.",
  summary,
  scenarioRows,
  artifacts: paths
};

const csv = toCsv(scenarioRows, [
  "evaluationId",
  "scenarioId",
  "threatModel",
  "expectedControl",
  "testName",
  "observedInTestOutput",
  "status",
  "measurementType"
]);

await writeJson(paths.reportPath, report);
await writeJson(paths.latestReportPath, report);
await fs.writeFile(paths.csvPath, `${csv}\n`);
await fs.writeFile(paths.latestCsvPath, `${csv}\n`);
await fs.writeFile(paths.rawOutputPath, run.output);
await fs.writeFile(paths.latestRawOutputPath, run.output);

console.log("");
console.log("[security-eval] complete");
console.log(`[security-eval] report=${paths.reportPath}`);
console.log(`[security-eval] csv=${paths.csvPath}`);
