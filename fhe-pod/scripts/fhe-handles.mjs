#!/usr/bin/env node
/**
 * Ciphertext handles produced by the TFHE executor.
 *
 * The dispute game registers, for every trace operand, a 32-byte ciphertext
 * handle. Those handles used to be derived from the clear value
 * (`ciphertextHandleForClear`), which made the on-chain "ciphertext" the
 * plaintext. `crates/tfhe-pod-demo/src/bin/fhe-executor.rs` now executes every
 * leaf of every evaluated workload over real FheUint64 ciphertexts and writes
 * artifacts/fhe/ciphertext-manifest.json, in which
 *
 *   handle = keccak256(safe_serialize(ciphertext))
 *
 * for each authenticated input and for each leaf result. This module exposes
 * those handles to the JavaScript evaluation.
 *
 * Set VCFHE_REQUIRE_FHE_HANDLES=1 (evaluation runs do) to turn a missing or
 * incomplete manifest into a hard failure instead of a fallback.
 *
 * Both traces the dispute demo commits are covered. The exporter emits the
 * corrupted trace as a separate manifest entry keyed `<workloadId>#corrupted`
 * (see scripts/export-traces-for-fhe.mjs), so the executor keeps its flat,
 * workloadId-keyed model and this module maps (workloadId, variant) onto it.
 */
import fs from "node:fs";
import { explicitTraceReferences } from "./trace-references.mjs";
import { COMPLIANCE_CIRCUIT_VERSION } from "./compliance-circuit.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const podRoot = path.resolve(scriptDir, "..");

/**
 * The pod directory, exported so a run record can report the manifest it read
 * as a repo-relative path instead of one that is specific to the machine that
 * produced it.
 */
export const podRootPath = podRoot;
/**
 * Manifest location. `VCFHE_CIPHERTEXT_MANIFEST` overrides it so that a run
 * outside the evaluation's evaluated set, such as the ANATEL RQUAL demonstration,
 * can supply its own ciphertexts without overwriting the manifest the evaluation's
 * measurements were produced with. Unset, the path is the evaluated one and
 * nothing changes.
 */
export const ciphertextManifestPath = process.env.VCFHE_CIPHERTEXT_MANIFEST
  ? path.resolve(podRoot, process.env.VCFHE_CIPHERTEXT_MANIFEST)
  : path.join(podRoot, "artifacts", "fhe", "ciphertext-manifest.json");

/**
 * Where the ciphertexts themselves live. The executor writes them next to the
 * manifest, in `<manifest dir>/ciphertexts`, and `VCFHE_CIPHERTEXT_DIR`
 * overrides that the same way the manifest path is overridden.
 *
 * Settling a disputed leaf needs the CIPHERTEXTS, not only their digests: the
 * decision is `FHE.eq(recomputed, claimed)` evaluated homomorphically (see
 * scripts/leaf-decision.mjs), because ciphertext bytes are not reproducible
 * across evaluation schedules and the equality bit is.
 */
export const ciphertextDirPath = process.env.VCFHE_CIPHERTEXT_DIR
  ? path.resolve(podRoot, process.env.VCFHE_CIPHERTEXT_DIR)
  : path.join(path.dirname(ciphertextManifestPath), "ciphertexts");

export const requireFheHandles = process.env.VCFHE_REQUIRE_FHE_HANDLES === "1";

let cached;

export function loadCiphertextManifest() {
  if (cached !== undefined) return cached;
  try {
    cached = JSON.parse(fs.readFileSync(ciphertextManifestPath, "utf8"));
  } catch (error) {
    if (requireFheHandles) {
      throw new Error(
        `VCFHE_REQUIRE_FHE_HANDLES=1 but ${ciphertextManifestPath} is unreadable (${error.message}). `
        + "Run: node scripts/export-traces-for-fhe.mjs && npm run fhe:execute"
      );
    }
    cached = null;
  }
  return cached;
}

export const fheTraceVariants = Object.freeze(["honest", "corrupted"]);

/**
 * Manifest key of a (workload, variant) pair. Must stay in step with
 * `manifestWorkloadKey` in scripts/export-traces-for-fhe.mjs.
 */
export function manifestWorkloadKey(workloadId, variant = "honest") {
  if (!fheTraceVariants.includes(variant)) {
    throw new Error(`unknown trace variant ${variant}; expected one of ${fheTraceVariants.join("|")}`);
  }
  return variant === "corrupted" ? `${workloadId}#corrupted` : workloadId;
}

/**
 * Handles for one variant of one workload, or null when the manifest does not
 * cover it.
 *
 * Shape: { workloadId, manifestKey, variant, keyDigest, tfheVersion,
 *          leafResultHandles: string[], leafClaims: string[],
 *          inputHandle(leafIndex, side) -> string|null,
 *          isPublicConstant(leafIndex, side) -> boolean }
 */
export function fheHandlesForWorkload(workloadId, expectedLeafCount, variant = "honest") {
  const manifest = loadCiphertextManifest();
  if (!manifest) return null;
  const manifestKey = manifestWorkloadKey(workloadId, variant);
  const entry = manifest.workloads?.find((w) => w.workloadId === manifestKey);
  if (!entry) {
    if (requireFheHandles) {
      throw new Error(
        `VCFHE_REQUIRE_FHE_HANDLES=1 but the ciphertext manifest has no entry for ${manifestKey} `
        + `(${variant} variant of ${workloadId}). Run: node scripts/export-traces-for-fhe.mjs `
        + "&& npm run fhe:execute"
      );
    }
    return null;
  }
  if (Number.isInteger(expectedLeafCount) && entry.leaves.length !== expectedLeafCount) {
    throw new Error(
      `ciphertext manifest for ${manifestKey} covers ${entry.leaves.length} leaves, `
      + `but the lowered trace has ${expectedLeafCount}. Re-export the traces and re-run the executor.`
    );
  }
  const failed = entry.leaves.filter((leaf) => leaf.ok === false);
  if (failed.length > 0) {
    throw new Error(
      `the TFHE executor reported ${failed.length} leaf mismatch(es) for ${manifestKey} `
      + `(first at index ${failed[0].index}); the encrypted execution disagrees with the lowering.`
    );
  }
  const inputs = new Map();
  const inputValues = new Map();
  for (const record of entry.inputs ?? []) {
    inputs.set(`${record.leafIndex}:${record.side}`, record.handle);
    inputValues.set(`${record.leafIndex}:${record.side}`, record.clear);
  }
  // Operands the encrypted execution treats as public scalars (a divisor, a
  // shift amount, the ignored rhs of a unary opcode) are never encrypted, so
  // the manifest holds no ciphertext for them. The dispute plan still registers
  // them as trace inputs, and `buildAuthenticatedTracePlan` needs to tell
  // "public constant, nothing to encrypt" apart from "manifest is incomplete".
  const publicConstants = new Set();
  for (const leaf of entry.leaves) {
    if (leaf.lhsSource === "PUBLIC_CONSTANT") publicConstants.add(`${leaf.index}:lhs`);
    if (leaf.rhsSource === "PUBLIC_CONSTANT") publicConstants.add(`${leaf.index}:rhs`);
  }
  return {
    workloadId,
    manifestKey,
    variant,
    keyDigest: manifest.keyDigest,
    tfheVersion: manifest.tfheVersion,
    determinismVerified: manifest.determinismVerified === true,
    fheMs: entry.fheMs,
    leafResultHandles: entry.leaves.map((leaf) => leaf.resultHandle),
    leafClaims: entry.leaves.map((leaf) => String(leaf.claimed)),
    circuitVersion: entry.circuitVersion,
    leafRecords: entry.leaves,
    inputHandle(leafIndex, side) {
      return inputs.get(`${leafIndex}:${side}`) ?? null;
    },
    inputClear(leafIndex, side) {
      return inputValues.get(`${leafIndex}:${side}`) ?? null;
    },
    isPublicConstant(leafIndex, side) {
      return publicConstants.has(`${leafIndex}:${side}`);
    }
  };
}

/**
 * Fails loudly when the manifest entry was produced from a different trace than
 * the one about to be committed -- the case that matters is an evaluation run
 * with `--manipulated-leaf-index` while the exporter used the per-workload
 * default, which would register handles for a corruption that is not the one
 * on-chain.
 */
export function assertHandlesMatchTrace(handles, leaves, label) {
  if (!handles) return;
  if (handles.leafClaims.length !== leaves.length) {
    throw new Error(
      `${label}: ciphertext manifest covers ${handles.leafClaims.length} leaves, trace has ${leaves.length}`
    );
  }
  if (handles.variant !== "corrupted" && explicitTraceReferences(leaves)) {
    if (handles.circuitVersion !== COMPLIANCE_CIRCUIT_VERSION) throw new Error(`${label}: stale circuit manifest; regenerate ciphertexts`);
    for (const [i, leaf] of leaves.entries()) {
      const actual = handles.leafRecords?.[i];
      if (actual?.opcode !== leaf.opcode_name || JSON.stringify(actual.lhsRef) !== JSON.stringify(leaf.lhsRef)
        || JSON.stringify(actual.rhsRef) !== JSON.stringify(leaf.rhsRef)) throw new Error(`${label}: circuit reference mismatch at leaf ${i}`);
      for (const side of ["lhs", "rhs"]) {
        if (leaf[`${side}Ref`].kind === "input" && (handles.inputClear?.(i, side) == null
          || BigInt(handles.inputClear(i, side)) !== BigInt(leaf[side]))) {
          throw new Error(`${label}: stale owner input at leaf ${i} ${side}; regenerate ciphertexts`);
        }
      }
    }
  }
  for (let index = 0; index < leaves.length; index += 1) {
    if (BigInt(handles.leafClaims[index]) !== BigInt(leaves[index].claimed)) {
      throw new Error(
        `${label}: leaf ${index} claims ${leaves[index].claimed} on-chain but the ciphertext manifest `
        + `(${handles.manifestKey}) executed ${handles.leafClaims[index]}. Re-run `
        + "scripts/export-traces-for-fhe.mjs and npm run fhe:execute with the same manipulated leaf index."
      );
    }
  }
}
