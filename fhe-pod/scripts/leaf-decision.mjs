#!/usr/bin/env node
/**
 * The leaf decision of a dispute, decided homomorphically.
 *
 * WHY THIS MODULE EXISTS.
 *
 * A ciphertext handle is `keccak256(safe_serialize(ciphertext))`. Two
 * evaluations of the SAME operation, on the SAME operand ciphertexts, under the
 * SAME server key, do not have to produce the same bytes: tfhe-rs 1.4.0
 * evaluates in parallel, and the schedule a process happens to take is visible
 * in the result ciphertext. Measured on this repository (see
 * `scripts/leaf-decision-stability.test.mjs`), independent processes replaying
 * one workload reproduce the committed handles most of the time and sometimes
 * do not, with every replay decrypting to the correct value.
 *
 * A handle therefore identifies ONE EXECUTION of an operation, not the
 * operation. Settling a leaf by comparing handles
 *
 *     operatorValid := (operatorHandle == referenceHandle)      // WRONG
 *
 * can slash an honest operator who executed correctly under a different
 * schedule. That is a soundness bug in the settlement rule, not a nuisance.
 *
 * The decision this module makes instead is the one a coprocessor makes:
 *
 *     recomputed  := eval(opcode, lhsCiphertext, rhsCiphertext)   // homomorphic
 *     valid       := decrypt(valid_operands AND FHE.eq(recomputed, claimedCiphertext))
 *
 * Value equality under encryption is insensitive to scheduling; byte
 * equality is not. Only the combined validity BIT is decrypted -- never an operand,
 * never the recomputed result, never a claim -- and that bit is what t+1
 * participants sign for `settleLeafViaAttestedDecision`.
 *
 * WHAT IS MODELED. A production bridge would compute the checked relation on
 * authenticated ciphertexts, authorize the two derived predicates before
 * threshold decryption, and bind their outcomes to a leaf certificate. A raw
 * KMS decryption response does not establish that relation. Here the
 * recomputation and the single decryption run in a local process holding the
 * evaluation key pair (`ct-inspect leaf-decision`), and the t+1 signatures are
 * produced by deterministic local identities. The primitive that decides the
 * leaf is the checked relation, with one decrypted bit per claim. This local
 * routine does not implement the distributed bridge or a release policy.
 */
import fs from "node:fs";
import { keccak256 } from "ethers";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PUBLIC_SCALAR_RHS_OPCODES } from "./micro-isa.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const podRoot = path.resolve(scriptDir, "..");

const targetDir = process.env.CARGO_TARGET_DIR
  ? path.resolve(podRoot, process.env.CARGO_TARGET_DIR) : path.join(podRoot, "target");
export const ctInspectPath = path.join(targetDir, "release", "ct-inspect");
export const fheExecutorPath = path.join(targetDir, "release", "fhe-executor");

/** Opcodes whose right operand is a public scalar of the program, never encrypted. */
const RHS_IS_PUBLIC_SCALAR = new Set(PUBLIC_SCALAR_RHS_OPCODES);
/** Opcodes that ignore the right operand entirely. */
const UNARY = new Set(["CAST_U8"]);

export function ensureCtInspect() {
  return ensureBinary("ct-inspect", ctInspectPath);
}

export function ensureFheExecutor() {
  return ensureBinary("fhe-executor", fheExecutorPath);
}

function ensureBinary(name, binaryPath) {
  const build = spawnSync(
    "cargo",
    ["build", "--release", "--bin", name],
    { cwd: podRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  if (build.status !== 0 || !fs.existsSync(binaryPath)) {
    throw new Error(
      `${name} is required for encrypted execution and could not be built: ` +
        `${build.stderr ?? ""}`.trim()
    );
  }
  return binaryPath;
}

/**
 * Environment of the SINGLE-THREAD evaluation profile (one rayon thread).
 *
 * This profile is a MEASUREMENT knob, not a soundness device. On 2026-09-02 the
 * repository measured (seed-probe, leaf-decision-stability.test.mjs) that a
 * correct evaluation of one leaf does not serialize identically across
 * processes with tfhe-rs 1.4.0 on aarch64/macOS, and that neither one rayon
 * thread nor a deterministic ShortintEngine seed changes that: the same small
 * set of result handles recurs with 1 and with 8 threads, and the divergent
 * serializations differ inside the LWE body of the non-trivial block. The
 * protocol therefore never uses result bytes for validity: each decision is
 * valid_operands AND FHE.eq(recomputed, claimed), with only the combined bit
 * decrypted. An admissible value-equal but byte-different claim is VALID. This function only lets the stability
 * test price and report the single-thread profile.
 */
export function canonicalEvaluationEnv(base = process.env) {
  return { ...base, RAYON_NUM_THREADS: "1" };
}

function runCtInspect(args, { timeoutMs = 60 * 60 * 1000, env = undefined } = {}) {
  ensureCtInspect();
  const startedAt = Date.now();
  const result = spawnSync(ctInspectPath, args, {
    cwd: podRoot,
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 512 * 1024 * 1024,
    env: env ?? process.env
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `ct-inspect ${args[0]} exited ${result.status}: ${String(result.stderr).slice(-2000)}`
    );
  }
  try {
    const parsed = JSON.parse(result.stdout);
    // Wall-clock of the whole child process; used to price the canonical
    // profile against the parallel one.
    if (parsed && typeof parsed === "object") parsed.elapsedMs = Date.now() - startedAt;
    return parsed;
  } catch (error) {
    throw new Error(
      `ct-inspect ${args[0]} did not print JSON (${error.message}): ${String(result.stdout).slice(0, 500)}`
    );
  }
}

/**
 * Where the ciphertext of one operand of `leafIndex` lives.
 *
 * Mirrors the executor's dataflow: an operand is either a freshly encrypted
 * authenticated input, the previous leaf's stored result, or a public constant
 * of the program (which is never encrypted at all).
 */
export function operandCiphertextPath(ciphertextDir, manifestKey, leafRecord, side) {
  const source = side === "lhs" ? leafRecord.lhsSource : leafRecord.rhsSource;
  const dir = path.join(ciphertextDir, manifestKey);
  if (source === "AUTHENTICATED_INPUT") {
    return path.join(dir, `input-${leafRecord.index}-${side}.ct`);
  }
  if (source === "PREVIOUS_OUTPUT") {
    const index = leafRecord[`${side}Ref`]?.index ?? leafRecord.index - 1;
    if (!Number.isSafeInteger(index) || index < 0 || index >= leafRecord.index) {
      throw new Error(`invalid prior-output reference at leaf ${leafRecord.index}`);
    }
    return path.join(dir, `result-${index}.ct`);
  }
  return null; // PUBLIC_CONSTANT: a scalar of the program, not a ciphertext
}

export function resultCiphertextPath(ciphertextDir, manifestKey, leafIndex) {
  return path.join(ciphertextDir, manifestKey, `result-${leafIndex}.ct`);
}

/**
 * Decide one isolated leaf.
 *
 * @param {object}   args
 * @param {string}   args.ciphertextDir  directory the executor wrote
 * @param {object}   args.manifest       the ciphertext manifest
 * @param {string}   args.referenceKey   manifest key whose OPERANDS are the ones
 *                                       the task committed on chain (the honest
 *                                       variant: the program the requester
 *                                       authorised, which no operator can change)
 * @param {number}   args.leafIndex
 * @param {number}   args.rhsScalar      public scalar for DIV/MOD/SHR leaves
 * @param {Array<{label: string, ciphertextPath: string, expectedHandle?: string}>} args.claims
 * @returns {{opcode: string, recomputedHandle: string, decisions: object[], byLabel: Record<string, boolean>}}
 */
export function decideLeaf({
  ciphertextDir,
  manifest,
  referenceKey,
  leafIndex,
  claims,
  rhsScalar = 0,
  // Both bits are VALUE equality: FHE.eq(recomputed, claim), bit decrypted.
  // Result bytes are never a validity condition, because a correct evaluation
  // is not byte-reproducible across processes on this library (see
  // canonicalEvaluationEnv). A leaf where both claims validate is a correct
  // leaf the challenger disputed, and settles against the challenger.
  // Detection and localization are outside this function: the implementation
  // scopes them by the assumption that a coprocessor derives result handles
  // from the operation and the operand handles (FHEVM model), under which an
  // honest challenger's recomputation agrees with the operator's trace on
  // every correct leaf and hash bisection isolates the first faulty one. The
  // local executor does not satisfy that assumption, so the evaluated
  // disputes start from a known corrupted leaf (run-hardhat-dispute-demo.mjs
  // splices the honest trace with one replaced result). `canonical` only
  // selects the single-thread profile for the recomputation;
  // `requireCanonicalBytesFor` is kept for experiments and is empty in the
  // protocol.
  canonical = false,
  requireCanonicalBytesFor = []
}) {
  const entry = manifest.workloads?.find((w) => w.workloadId === referenceKey);
  if (!entry) throw new Error(`ciphertext manifest has no entry for ${referenceKey}`);
  const leafRecord = entry.leaves?.find((l) => l.index === leafIndex);
  if (!leafRecord) {
    throw new Error(`ciphertext manifest entry ${referenceKey} has no leaf ${leafIndex}`);
  }

  const lhsPath = operandCiphertextPath(ciphertextDir, referenceKey, leafRecord, "lhs");
  const lhsConstant = leafRecord.lhsRef?.kind === "constant" ? leafRecord.lhsRef.value : null;
  if (!lhsPath && lhsConstant === null) throw new Error(`leaf ${leafIndex} has no left operand`);
  const scalarRhs = RHS_IS_PUBLIC_SCALAR.has(leafRecord.opcode) || UNARY.has(leafRecord.opcode);
  const rhsPath = scalarRhs
    ? null
    : operandCiphertextPath(ciphertextDir, referenceKey, leafRecord, "rhs");

  const args = [
    "leaf-decision",
    "--server-key",
    path.join(ciphertextDir, "keys", "server-key.bin"),
    "--client-key",
    path.join(ciphertextDir, "keys", "client-key.bin"),
    "--opcode",
    leafRecord.opcode
  ];
  if (lhsPath) args.push("--lhs", lhsPath);
  else args.push("--lhs-scalar", String(lhsConstant));
  if (rhsPath) args.push("--rhs", rhsPath);
  else args.push("--rhs-scalar", String(leafRecord.rhsRef?.kind === "constant" ? leafRecord.rhsRef.value : rhsScalar));
  for (const claim of claims) args.push("--claim", `${claim.label}=${claim.ciphertextPath}`);

  // A ciphertext directory written before the executor persisted results has
  // the inputs but none of the `result-<i>.ct` files this adjudication reads.
  // Say so, instead of failing with a bare ENOENT from the Rust side.
  for (const file of [lhsPath, rhsPath, ...claims.map((claim) => claim.ciphertextPath)]) {
    if (file && !fs.existsSync(file)) {
      throw new Error(
        `${file} is missing. A disputed leaf is adjudicated by recomputing it over the operand ` +
          "ciphertexts and comparing each claim with FHE.eq, which needs the stored result " +
          "ciphertexts. A cache written by an executor that only kept handles has none: re-run " +
          "`npm run fhe:execute` to regenerate it."
      );
    }
  }

  // Reject mismatched files BEFORE computing or releasing any predicate bit.
  // This is a local manifest check, not distributed authorization of a circuit.
  for (const [file, expected, label] of [
    [lhsPath, leafRecord.lhsHandle, "lhs"], [rhsPath, leafRecord.rhsHandle, "rhs"],
    ...claims.map(claim => [claim.ciphertextPath, claim.expectedHandle, claim.label])
  ]) {
    if (file && expected && keccak256(fs.readFileSync(file)).toLowerCase() !== expected.toLowerCase()) {
      throw new Error(`ciphertext handle mismatch for ${label}; no decision released`);
    }
  }
  if (manifest.keyDigest && keccak256(fs.readFileSync(path.join(ciphertextDir, "keys", "server-key.bin"))) !== manifest.keyDigest) {
    throw new Error("server key mismatch; no decision released");
  }
  const out = runCtInspect(args, { env: canonical ? canonicalEvaluationEnv() : undefined });

  // Bind ciphertext to handle: the file we adjudicated must be the very
  // ciphertext whose digest the party published on chain. Without this check
  // the decision would be about some ciphertext, not about the claim.
  for (const claim of claims) {
    if (!claim.expectedHandle) continue;
    const decided = out.decisions.find((d) => d.label === claim.label);
    if (!decided) throw new Error(`ct-inspect returned no decision for ${claim.label}`);
    if (String(decided.claimedHandle).toLowerCase() !== String(claim.expectedHandle).toLowerCase()) {
      throw new Error(
        `claim ciphertext for ${claim.label} hashes to ${decided.claimedHandle}, but the handle ` +
          `committed on chain is ${claim.expectedHandle}: the adjudicated ciphertext is not the claim`
      );
    }
  }

  const byLabel = {};
  const valueEqualByLabel = {};
  const canonicalBytesByLabel = {};
  for (const decision of out.decisions) {
    valueEqualByLabel[decision.label] = decision.valid;
    canonicalBytesByLabel[decision.label] = Boolean(decision.claimBytesEqualRecomputed);
    byLabel[decision.label] =
      decision.valid &&
      (!canonical || !requireCanonicalBytesFor.includes(decision.label) || canonicalBytesByLabel[decision.label]);
  }
  return {
    opcode: leafRecord.opcode,
    canonical,
    valueEqualByLabel,
    canonicalBytesByLabel,
    recomputedHandle: out.recomputedHandle,
    lhsHandle: out.lhsHandle,
    rhsHandle: out.rhsHandle,
    recomputeMs: out.recomputeMs,
    decisions: out.decisions,
    byLabel
  };
}

/**
 * Replay a whole workload in THIS process, and for every leaf decide -- by
 * `FHE.eq` against the committed result ciphertext -- whether the replay agrees
 * with what was committed. Used by the stability test and by check C4.
 */
export function replayWithDecisions({
  ciphertextDir,
  tracesPath,
  workloadId,
  limitLeaves = null,
  decide = true,
  canonical = false,
  timeoutMs = 60 * 60 * 1000
}) {
  const args = [
    "replay",
    "--server-key",
    path.join(ciphertextDir, "keys", "server-key.bin"),
    "--client-key",
    path.join(ciphertextDir, "keys", "client-key.bin"),
    "--decrypt",
    "--ct-dir",
    ciphertextDir,
    "--traces",
    tracesPath,
    "--workload",
    workloadId
  ];
  if (decide) args.push("--decide");
  if (limitLeaves !== null) args.push("--limit-leaves", String(limitLeaves));
  return runCtInspect(args, {
    timeoutMs,
    env: canonical ? canonicalEvaluationEnv() : undefined
  });
}

/**
 * Saturate `count` cores until the returned handle is stopped.
 *
 * Scheduling divergence is what breaks handle reproducibility, so a test that
 * claims decision stability has to look for it where it is most likely to
 * appear: with the machine contended, so that the thread pool evaluating a leaf
 * interleaves differently from run to run.
 */
export function startCpuLoad(count) {
  const workers = [];
  for (let i = 0; i < count; i += 1) {
    const child = spawn(
      process.execPath,
      ["-e", "let x = 0; for (;;) { x = (x + 1) % 4294967296; }"],
      { stdio: "ignore", detached: false }
    );
    workers.push(child);
  }
  return {
    count: workers.length,
    stop() {
      for (const worker of workers) {
        try {
          worker.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }
    }
  };
}
