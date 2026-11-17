#!/usr/bin/env node
/**
 * Export every evaluated workload's lowered micro-trace so that the TFHE
 * executor can run it over real ciphertexts.
 *
 * The evaluation used to lower a workload to integers in JavaScript and derive
 * each on-chain ciphertext handle from the clear value, which meant the
 * "ciphertext handles" registered on-chain were the plaintext. This exporter is
 * the first half of the replacement: it emits the exact leaf sequence the
 * evaluation will commit, and `cargo run --bin fhe-executor` encrypts the
 * operands, executes every leaf under TFHE, and returns one handle per input
 * and per leaf result. `scripts/fhe-handles.mjs` then feeds those handles to
 * `buildAuthenticatedTracePlan`.
 *
 * Two variants are exported per workload, because the evaluation commits two
 * traces on-chain:
 *
 *   variant "honest"    workloadId = <id>              the lowered trace itself;
 *   variant "corrupted" workloadId = <id>#corrupted    the same trace with the
 *                       leaf `defaultManipulatedLeafIndex` re-claimed by the
 *                       dishonest operator (`deriveDishonestLeaves`, shared with
 *                       scripts/run-hardhat-dispute-demo.mjs).
 *
 * The `#corrupted` suffix is a *manifest key*, not a new workload: it keeps the
 * executor's `workloadId`-keyed model unchanged, and scripts/fhe-handles.mjs
 * maps (workloadId, variant) back to it.
 *
 * The manipulated leaf cannot be handed to the executor verbatim: its claim is
 * false by construction, so executing the original opcode would decrypt to the
 * honest result and be reported as a mismatch. The dishonest operator does not
 * publish the honest ciphertext either -- it publishes a ciphertext of the value
 * it claims. The corrupted variant therefore rewrites that one leaf into the
 * homomorphic operation that actually produces the fraudulent value
 * (`ADD(honest result, delta)`), so the exported trace is an executable, honest
 * description of a dishonest computation.
 *
 * Output: artifacts/fhe/traces.json
 *
 * Usage (from VC-FHE/fhe-pod):
 *   node scripts/export-traces-for-fhe.mjs [--workloads all|<id>,<id>]
 *                                          [--manipulated-leaf-index <n>]
 *                                          [--out <path>]
 *                                          [--only-anatel-demo]
 *                                          [--only-anatel-simplified]
 *                                          [--only-arithmetic-demo]
 *
 * `--only-anatel-demo` exports the ANATEL RQUAL demonstration workload INSTEAD
 * of the evaluated ones, `--only-anatel-simplified` exports its teaching
 * variant from VC-FHE/Anatel/anatel-rqual-simplificado/, and `--only-arithmetic-demo`
 * exports the five-leaf arithmetic example from VC-FHE/examples/exemplo-aritmetico/.
 * All three are opt-in and write
 * wherever `--out` points, so the default invocation, and therefore
 * artifacts/fhe/traces.json and every number of the evaluation, is byte-identical
 * with or without these flags existing.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  OPCODES,
  allApplicationWorkloadSpecs,
  deriveDishonestLeaves,
  lowerWorkloadSpec
} from "./application-lowering.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const podRoot = path.resolve(scriptDir, "..");
const defaultOutPath = path.join(podRoot, "artifacts", "fhe", "traces.json");

function argValue(name, fallback) {
  const eq = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (eq) return eq.split("=").slice(1).join("=");
  const idx = process.argv.indexOf(`--${name}`);
  return idx >= 0 && process.argv[idx + 1] ? process.argv[idx + 1] : fallback;
}

const selector = argValue("workloads", "all");
// Mirrors `--manipulated-leaf-index` of run-application-layer-evaluation.mjs:
// when the evaluation overrides the per-workload default, the corrupted variant
// exported here has to be corrupted at the same leaf, or the dishonest task
// would register handles for a different corruption than the one it commits.
const manipulatedLeafOverride = (() => {
  const raw = argValue("manipulated-leaf-index", null);
  if (raw === null) return null;
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`--manipulated-leaf-index must be an integer >= 0; received ${raw}`);
  }
  return value;
})();
const wanted = selector === "all"
  ? null
  : new Set(selector.split(",").map((s) => s.trim()).filter(Boolean));

const outPath = path.resolve(podRoot, argValue("out", defaultOutPath));
const outDir = path.dirname(outPath);

// The demonstration workload is not part of allApplicationWorkloadSpecs() and
// must never enter the evaluated set. It is lowered by its own module and is
// exported only when the caller asks for it explicitly.
const onlyAnatelDemo = process.argv.includes("--only-anatel-demo");
const onlyAnatelSimplified = process.argv.includes("--only-anatel-simplified");
const onlyArithmeticDemo = process.argv.includes("--only-arithmetic-demo");
const demoSelectors = [
  onlyAnatelDemo && "--only-anatel-demo",
  onlyAnatelSimplified && "--only-anatel-simplified",
  onlyArithmeticDemo && "--only-arithmetic-demo"
].filter(Boolean);
if (demoSelectors.length > 1) {
  console.error(`${demoSelectors.join(", ")} select different traces; pass one`);
  process.exit(1);
}
const onlyDemoWorkload = demoSelectors.length === 1;

const specs = onlyDemoWorkload
  ? []
  : allApplicationWorkloadSpecs().filter((spec) => wanted === null || wanted.has(spec.id));
if (!onlyDemoWorkload && specs.length === 0) {
  console.error(`no workload matches --workloads ${selector}`);
  process.exit(1);
}

/**
 * Operand provenance, computed exactly as buildAuthenticatedTracePlan computes
 * it, so the executor encrypts an operand only when the trace treats it as an
 * authenticated input and reuses the previous leaf's result ciphertext
 * otherwise. Recomputing it here rather than importing it keeps the exporter
 * free of the ethers dependency; scripts/fhe-handles.mjs asserts the two agree.
 */
function operandSources(leaves) {
  return leaves.map((leaf, index) => {
    const previous = index > 0 ? leaves[index - 1] : null;
    const lhsFromPrevious = previous !== null && BigInt(leaf.lhs) === BigInt(previous.claimed);
    const rhsFromPrevious = previous !== null && BigInt(leaf.rhs) === BigInt(previous.claimed);
    return { lhsFromPrevious, rhsFromPrevious };
  });
}

/** Manifest key of a variant. `fheHandlesForWorkload` must agree with this. */
function manifestWorkloadKey(workloadId, variant) {
  return variant === "corrupted" ? `${workloadId}#corrupted` : workloadId;
}

/**
 * The executable form of the corrupted trace.
 *
 * `deriveDishonestLeaves` states the fraud in the clear: leaf `index` claims a
 * value the original operation does not produce. To obtain the ciphertext the
 * dishonest operator publishes for that leaf, the exported leaf is rewritten
 * into the operation that does produce the fraudulent value, namely the honest
 * result shifted by the claim delta. The delta is READ from the shared
 * derivation rather than assumed, so a change to the fault model propagates
 * here without a second edit.
 *
 * Every other leaf is exported verbatim; only the operand-provenance flags are
 * recomputed, because the corrupted claim breaks the value chain into the
 * following leaf (which is exactly the discrepancy the dispute bisects).
 */
function corruptedExecutionLeaves(honestLeaves, manipulatedLeafIndex) {
  const dishonest = deriveDishonestLeaves(honestLeaves, manipulatedLeafIndex);
  const honestLeaf = honestLeaves[manipulatedLeafIndex];
  const honestClaim = BigInt(honestLeaf.claimed);
  const dishonestClaim = BigInt(dishonest[manipulatedLeafIndex].claimed);
  const delta = dishonestClaim - honestClaim;
  if (delta === 0n) {
    throw new Error(
      `corrupted variant of leaf ${manipulatedLeafIndex} claims the honest value; nothing is manipulated`
    );
  }
  const opcodeName = delta > 0n ? "ADD" : "SUB";
  const magnitude = delta > 0n ? delta : -delta;
  const leaves = [...dishonest];
  leaves[manipulatedLeafIndex] = {
    ...dishonest[manipulatedLeafIndex],
    opcode: OPCODES[opcodeName],
    opcode_name: opcodeName,
    lhs: honestClaim.toString(),
    rhs: magnitude.toString(),
    claimed: dishonestClaim.toString(),
    operands: null,
    tamperedFrom: {
      opcode: honestLeaf.opcode_name ?? honestLeaf.opcode,
      lhs: String(honestLeaf.lhs),
      rhs: String(honestLeaf.rhs),
      claimed: String(honestLeaf.claimed)
    }
  };
  return leaves;
}

function serializeVariant({ spec, lowered, leaves, variant, manipulatedLeafIndex }) {
  const sources = operandSources(leaves);
  return {
    workloadId: manifestWorkloadKey(spec.id, variant),
    baseWorkloadId: spec.id,
    variant,
    manipulatedLeafIndex,
    circuitVersion: variant === "honest" ? lowered.program?.version ?? null : null,
    evidenceRole: variant === "honest" ? "honest-execution" : "known-fault-ciphertext-fixture",
    title: variant === "corrupted"
      ? `${spec.title} [corrupted leaf ${manipulatedLeafIndex}]`
      : spec.title,
    leafCount: leaves.length,
    opcodeHistogram: variant === "honest"
      ? (lowered.lowering?.opcodeHistogram ?? null)
      : null,
    leaves: leaves.map((leaf, index) => ({
      index,
      opcode: leaf.opcode_name ?? leaf.opcode,
      opcodeId: typeof leaf.opcode === "number" ? leaf.opcode : null,
      lhs: String(leaf.lhs),
      rhs: String(leaf.rhs),
      claimed: String(leaf.claimed),
      operands: leaf.operands ? leaf.operands.map(String) : null,
      ...(variant === "honest" && leaf.lhsRef ? { lhsRef: leaf.lhsRef, rhsRef: leaf.rhsRef } : {}),
      lhsFromPrevious: variant === "honest" && leaf.lhsRef ? false : sources[index].lhsFromPrevious,
      rhsFromPrevious: variant === "honest" && leaf.rhsRef ? false : sources[index].rhsFromPrevious,
      ...(leaf.tamperedFrom ? { tampered: true, tamperedFrom: leaf.tamperedFrom } : {})
    }))
  };
}

const workloads = [];
let totalLeaves = 0;

// (spec, lowered) pairs. The evaluated workloads are lowered by
// lowerWorkloadSpec; the demonstration workload arrives already lowered from
// its own module, which registers nothing in operationRegistry.
const loweredPairs = [];
if (onlyAnatelDemo) {
  // The demonstration lives outside the pod, in VC-FHE/Anatel/anatel-rqual/. The
  // import is dynamic and inside this branch, so the default invocation never
  // touches it.
  const { anatelRqualInputs } = await import("../../Anatel/anatel-rqual/anatel-rqual-fixtures.mjs");
  const { lowerAnatelRqual } = await import("../../Anatel/anatel-rqual/anatel-rqual-lowering.mjs");
  const lowered = lowerAnatelRqual(anatelRqualInputs());
  loweredPairs.push([{ id: lowered.id }, lowered]);
} else if (onlyAnatelSimplified) {
  // Same arrangement for the teaching variant in
  // VC-FHE/Anatel/anatel-rqual-simplificado/: its own lowering module, its own
  // workload id, nothing registered in operationRegistry.
  const { lowerSimplifiedRqual } = await import(
    "../../Anatel/anatel-rqual-simplificado/anatel-rqual-simplified-lowering.mjs"
  );
  const lowered = lowerSimplifiedRqual();
  loweredPairs.push([{ id: lowered.id }, lowered]);
} else if (onlyArithmeticDemo) {
  // Same arrangement for the minimal arithmetic teaching example in
  // VC-FHE/examples/exemplo-aritmetico/: its own lowering module, its own workload id,
  // nothing registered in operationRegistry. Five leaves padded to eight.
  const { lowerArithmeticDemo } = await import(
    "../../examples/exemplo-aritmetico/arithmetic-demo-lowering.mjs"
  );
  const lowered = lowerArithmeticDemo();
  loweredPairs.push([{ id: lowered.id }, lowered]);
} else {
  for (const spec of specs) loweredPairs.push([spec, lowerWorkloadSpec(spec)]);
}

for (const [spec, lowered] of loweredPairs) {
  const leaves = Array.isArray(lowered.witnesses)
    ? lowered.witnesses
    : (lowered.witnesses?.leaves ?? lowered.leaves ?? spec.leaves);
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error(`workload ${spec.id} lowered to no leaves`);
  }
  const manipulatedLeafIndex = manipulatedLeafOverride ?? lowered.defaultManipulatedLeafIndex;
  if (!Number.isInteger(manipulatedLeafIndex) || manipulatedLeafIndex >= leaves.length) {
    throw new Error(
      `workload ${spec.id}: manipulated leaf ${manipulatedLeafIndex} is outside its ${leaves.length} leaves`
    );
  }
  const variants = [
    { variant: "honest", leaves },
    { variant: "corrupted", leaves: corruptedExecutionLeaves(leaves, manipulatedLeafIndex) }
  ];
  for (const { variant, leaves: variantLeaves } of variants) {
    totalLeaves += variantLeaves.length;
    workloads.push(serializeVariant({
      spec,
      lowered,
      leaves: variantLeaves,
      variant,
      manipulatedLeafIndex
    }));
  }
}

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outPath, `${JSON.stringify({
  generator: "scripts/export-traces-for-fhe.mjs",
  engineVersion: "application-lowering-v3-explicit-compliance",
  variants: ["honest", "corrupted"],
  workloadCount: workloads.length,
  baseWorkloadCount: loweredPairs.length,
  totalLeaves,
  workloads
}, null, 2)}\n`);
const baseCount = loweredPairs.length;
console.log(
  `wrote ${path.relative(podRoot, outPath)}: ${baseCount} workloads `
  + `x ${workloads.length / baseCount} variants = ${workloads.length} entries, ${totalLeaves} leaves`
);
for (const w of workloads) {
  console.log(
    `  ${w.workloadId.padEnd(44)} ${String(w.leafCount).padStart(4)} leaves  `
    + `variant=${w.variant} manipulatedLeaf=${w.manipulatedLeafIndex}`
  );
}
