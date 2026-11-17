/**
 * The five steps of the linear workflow, as the implementation enumerates them.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The measurement scripts announced their own internal stages ("[3/4] On-chain
 * gas..."), which are units of *tooling*, not units of the *protocol*. A reader
 * watching the console could not tell which part of Section "Workflow for
 * Computation and Verification" was executing, nor map a failure to the step of
 * the experiment it belongs to.
 *
 * The labels below are transcribed verbatim from the numbered list in
 * `\subsubsection{Linear Operations}` (`\label{sec:workflow-linear}`). Keep them
 * in sync with the implementation: if a step is renamed there, rename it here, and
 * the Rust, JavaScript and shell stages all follow, because they all print from
 * this table.
 *
 * The `does` lines are the concrete operations the step performs, in the order
 * the implementation describes them, so the console shows the cryptographic work
 * (key generation, encryption, commitment, signing, pairing verification,
 * accumulator fold, balanced reduction, decryption) and not only a stage number.
 */
"use strict";

const WORKFLOW_STEPS = Object.freeze({
  W1: Object.freeze({
    id: "W1",
    title: "Setup and task assignment",
    does: [
      "deploy with the dataset/epoch tag tau, the authorized operation (SUM|SUB),",
      "the input count N and the enrolled owner address of every index;",
      "the administrator assigns one task identifier to one operator"
    ]
  }),
  W2: Object.freeze({
    id: "W2",
    title: "Data contribution and admission",
    does: [
      "per owner: produce the QoE record m_i, ENCRYPT it as a leveled LWE vector",
      "c_i under the shared FHE key, self-register pk_i from the enrolled address,",
      "COMMIT P(c_i) and SIGN sigma_i = sk_i * H_G1(ctx_i);",
      "on-chain: verify the two-pairing admission check e(sigma_i,G2)=e(M_i,pk_i),",
      "consume index i, and fold w_i*P(c_i) into the accumulator P_agg"
    ]
  }),
  W3: Object.freeze({
    id: "W3",
    title: "Execution and output construction (off-chain)",
    does: [
      "the operator forms the UNREDUCED output vector A = sum_i w_i*phi(c_i) over",
      "ciphertexts only, never decrypting, then serializes it canonically and",
      "computes the output digest d_out and the commitment P(A)"
    ]
  }),
  W4: Object.freeze({
    id: "W4",
    title: "On-chain verification and replay protection",
    does: [
      "the operator submits (taskId, d_out, P(A)); the contract runs canonical",
      "point checks, requires all N records admitted, accepts only if",
      "P(A) = P_agg, then consumes the one-shot task and records the pair"
    ]
  }),
  W5: Object.freeze({
    id: "W5",
    title: "Consumer verification and decryption",
    does: [
      "the consumer recomputes d_out and P(A) from the DELIVERED vector and",
      "compares both against the on-chain record; only then does it derive",
      "C_out = rho(A) by balanced reduction and DECRYPT"
    ]
  })
});

const RULE = "-".repeat(74);

/**
 * Prints the workflow-step banner.
 *
 * @param {string} id      one of W1..W5
 * @param {string} [note]  what this particular script does within the step
 */
function step(id, note) {
  const s = WORKFLOW_STEPS[id];
  if (!s) throw new Error(`unknown workflow step: ${id}`);
  console.log("");
  console.log(RULE);
  console.log(`  ${s.id}  ${s.title}   [sec:workflow-linear, step ${s.id.slice(1)}]`);
  for (const line of s.does) console.log(`      ${line}`);
  if (note) console.log(`      >> ${note}`);
  console.log(RULE);
}

/** Prints the whole five-step map, for the top of a run. */
function printMap(header) {
  console.log("");
  console.log(RULE);
  console.log(`  ${header ?? "Linear workflow (sec:workflow-linear)"}`);
  console.log(RULE);
  for (const s of Object.values(WORKFLOW_STEPS)) {
    console.log(`  ${s.id}  ${s.title}`);
  }
  console.log(RULE);
}

module.exports = { WORKFLOW_STEPS, step, printMap };
