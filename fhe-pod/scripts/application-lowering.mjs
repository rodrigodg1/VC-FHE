import { qoeMosWorkloadSpecs } from "./qoe-mos-fixtures.mjs";
import { qoeTreeWorkloadSpecs } from "./qoe-tree-fixtures.mjs";
import { regulatoryWorkloadSpecs } from "./regulatory-fixtures.mjs";
import { stav360WorkloadSpecs } from "./stav360-fixtures.mjs";
import { webrtcWorkloadSpecs } from "./webrtc-fixtures.mjs";

import { compileComplianceCircuit, evaluateCircuitReference } from "./compliance-circuit.mjs";

export const LOWERING_ENGINE_VERSION = "application-lowering-v3-explicit-compliance";

// The micro-ISA is declared once, in scripts/micro-isa.mjs, and mirrors the
// Solidity constants of FhevmObjectiveMicroVerifier. Re-exported here so the
// existing importers of `OPCODES` keep working.
//
// v1 of this file declared its own 14-entry table that omitted ADD_CHAIN (15),
// which made the "15-operation micro-ISA" of the implementation true for the
// adjudicable surface but false for the compilable one. The table is now
// shared, and `lowerWorkloadSpec` additionally checks every emitted leaf
// against the reference relation (see `assertTraceSemantics`).
export {
  OPCODES,
  OPCODE_NAMES,
  MAX_COMPOUND_OPS,
  MICRO_ISA_SIZE,
  evaluateLeaf,
  checkWitness,
  assertTraceSemantics
} from "./micro-isa.mjs";

import {
  OPCODES,
  MICRO_ISA_SIZE,
  assertTraceSemantics,
  checkWitness
} from "./micro-isa.mjs";

const SUPPORTED_OPCODE_NAMES = new Set(Object.keys(OPCODES));

function parseInteger(value, label, { min = 0 } = {}) {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${label} must be an integer >= ${min}; received ${value}`);
  }
  return value;
}

function parseIntegerArray(values, label, options = {}) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(`${label} must be a non-empty integer array`);
  }
  return values.map((value, index) => parseInteger(value, `${label}[${index}]`, options));
}

/**
 * Builds one lowered trace leaf and verifies it against the adjudicated
 * relation before returning it.
 *
 * The `checkWitness` call is the important part: `claimed` used to be accepted
 * verbatim, so a lowering rule could emit an arithmetically wrong leaf and the
 * evaluation would still report the honest task as "accepted" -- the optimistic
 * path re-executes no leaf, so nothing on-chain would have contradicted it.
 * Now a lowering bug fails loudly, at the leaf that caused it.
 */
export function leaf(leafIndex, opcodeName, lhs, rhs, claimed, note) {
  if (!SUPPORTED_OPCODE_NAMES.has(opcodeName)) {
    throw new Error(`Unsupported opcode: ${opcodeName}`);
  }
  const witness = {
    leaf_index: leafIndex,
    opcode: OPCODES[opcodeName],
    opcode_name: opcodeName,
    lhs: parseInteger(lhs, `${opcodeName}.lhs`),
    rhs: parseInteger(rhs, `${opcodeName}.rhs`),
    claimed: parseInteger(claimed, `${opcodeName}.claimed`),
    note
  };
  const verdict = checkWitness(witness);
  if (!verdict.ok) {
    throw new Error(
      `lowering emitted a leaf the objective verifier would reject: ` +
        `leaf ${leafIndex} ${opcodeName}(${witness.lhs}, ${witness.rhs}) -> ${verdict.reason}`
    );
  }
  return witness;
}

function assertPowerOfTwo(n, workloadId) {
  if (n <= 0 || (n & (n - 1)) !== 0) {
    throw new Error(`Workload ${workloadId} produced ${n} leaves; leaf count must be a power of two`);
  }
}

function nextPowerOfTwo(n) {
  let p = 1;
  while (p < n) {
    p <<= 1;
  }
  return p;
}

function padWitnessesToPowerOfTwo(witnesses) {
  const padded = [...witnesses];
  const target = nextPowerOfTwo(padded.length);
  while (padded.length < target) {
    padded.push(leaf(padded.length, "ADD", 0, 0, 0, "padding no-op"));
  }
  return padded;
}

export function opcodeCounts(witnesses) {
  const counts = new Map();
  for (const w of witnesses) {
    counts.set(w.opcode_name, (counts.get(w.opcode_name) ?? 0) + 1);
  }
  return Object.fromEntries([...counts.entries()].sort((a, b) => a[0].localeCompare(b[0])));
}

/**
 * Canonical fault injection of the evaluation: the dishonest operator replays
 * the whole honest trace and overstates the result of exactly one leaf by
 * DISHONEST_CLAIM_DELTA.
 *
 * It is declared here, once, because two places have to agree on it exactly:
 * `scripts/run-hardhat-dispute-demo.mjs` commits the corrupted trace on-chain,
 * and `scripts/export-traces-for-fhe.mjs` exports the same corrupted trace so
 * the TFHE executor can produce the ciphertext handles that the corrupted task
 * registers. If the two ever drifted, the dishonest task would commit
 * ciphertext handles for a trace it never executed.
 */
export const DISHONEST_CLAIM_DELTA = 1;

/** The value the dishonest operator claims for the manipulated leaf. */
export function dishonestLeafClaim(honestLeaf) {
  return Number(honestLeaf.claimed) + DISHONEST_CLAIM_DELTA;
}

/**
 * The corrupted trace: the honest leaves with leaf `manipulatedLeafIndex`
 * re-claimed. Every other leaf, including the operands of the leaf that follows
 * the manipulated one, is left untouched, which is what makes the corruption
 * detectable at exactly one leaf by bisection.
 */
export function deriveDishonestLeaves(honestLeaves, manipulatedLeafIndex) {
  if (!Array.isArray(honestLeaves) || honestLeaves.length === 0) {
    throw new Error("deriveDishonestLeaves requires a non-empty honest trace");
  }
  if (
    !Number.isInteger(manipulatedLeafIndex) ||
    manipulatedLeafIndex < 0 ||
    manipulatedLeafIndex >= honestLeaves.length
  ) {
    throw new Error(
      `manipulated leaf ${manipulatedLeafIndex} is outside the ${honestLeaves.length}-leaf trace`
    );
  }
  const leaves = [...honestLeaves];
  leaves[manipulatedLeafIndex] = {
    ...honestLeaves[manipulatedLeafIndex],
    claimed: dishonestLeafClaim(honestLeaves[manipulatedLeafIndex])
  };
  return leaves;
}

function lowerQuantizedLinearClassifier(operation) {
  const x = parseIntegerArray(operation.features, "features");
  const w = parseIntegerArray(operation.weights, "weights");
  if (x.length !== w.length || x.length !== 2) {
    throw new Error("quantized_linear_classifier currently expects exactly two features and two weights");
  }
  const bias = parseInteger(operation.bias, "bias");
  const scaleShift = parseInteger(operation.scaleShift, "scaleShift");
  const threshold = parseInteger(operation.threshold, "threshold");
  const expectedClass = parseInteger(operation.expectedClass, "expectedClass", { min: 0 });

  const p0 = x[0] * w[0];
  const p1 = x[1] * w[1];
  const sum = p0 + p1;
  const biased = sum + bias;
  const score = biased >> scaleShift;
  const gt = score > threshold ? 1 : 0;
  const classOk = gt === expectedClass ? 1 : 0;
  const accepted = gt & classOk;

  return {
    model: { x, w, bias, scaleShift, threshold, expectedClass, score },
    witnesses: [
      leaf(0, "MUL", x[0], w[0], p0, "x0*w0"),
      leaf(1, "MUL", x[1], w[1], p1, "x1*w1"),
      leaf(2, "ADD", p0, p1, sum, "sum products"),
      leaf(3, "ADD", sum, bias, biased, "add bias"),
      leaf(4, "SHR", biased, scaleShift, score, "fixed-point rescale"),
      leaf(5, "GT", score, threshold, gt, "threshold predicate"),
      leaf(6, "EQ", gt, expectedClass, classOk, "class consistency"),
      leaf(7, "BITAND", gt, classOk, accepted, "final acceptance bit")
    ]
  };
}

function buildSumTree(values, startIndex, notePrefix) {
  let witnesses = [];
  let idx = startIndex;
  let layer = [...values];
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const lhs = layer[i];
      const rhs = layer[i + 1];
      const claimed = lhs + rhs;
      witnesses.push(
        leaf(idx++, "ADD", lhs, rhs, claimed, `${notePrefix} partial sum`)
      );
      next.push(claimed);
    }
    layer = next;
  }
  return { sum: layer[0], witnesses, nextIndex: idx };
}

function lowerMeanVariance(operation) {
  const values = parseIntegerArray(operation.values, "values");
  if (values.length < 2) {
    throw new Error("mean_variance expects at least two values");
  }
  const divisor = parseInteger(operation.divisor ?? values.length, "divisor", { min: 1 });
  const varianceThreshold = parseInteger(operation.varianceThreshold, "varianceThreshold");
  const meanThreshold = parseInteger(operation.meanThreshold, "meanThreshold");

  let leafIndex = 0;
  const witnesses = [];

  const padded = [...values];
  const sumTarget = nextPowerOfTwo(padded.length);
  while (padded.length < sumTarget) {
    padded.push(0);
  }

  const sumTree = buildSumTree(padded, leafIndex, "rating");
  witnesses.push(...sumTree.witnesses);
  leafIndex = sumTree.nextIndex;

  const sum = values.reduce((a, b) => a + b, 0);
  const mean = Math.floor(sum / divisor);

  witnesses.push(leaf(leafIndex++, "DIV", sum, divisor, mean, "integer MOS / mean"));

  const squares = values.map((v) => v * v);
  for (let i = 0; i < values.length; i += 1) {
    witnesses.push(
      leaf(leafIndex++, "MUL", values[i], values[i], squares[i], `rating${i}^2`)
    );
  }

  const paddedSquares = [...squares];
  while (paddedSquares.length < sumTarget) {
    paddedSquares.push(0);
  }
  const ssTree = buildSumTree(paddedSquares, leafIndex, "square");
  witnesses.push(...ssTree.witnesses);
  leafIndex = ssTree.nextIndex;

  const ss = squares.reduce((a, b) => a + b, 0);
  const ex2 = Math.floor(ss / divisor);
  const meanSq = mean * mean;
  const variance = ex2 - meanSq;
  const meanOk = mean > meanThreshold ? 1 : 0;
  const varianceOk = variance > varianceThreshold ? 1 : 0;
  const accepted = varianceOk & meanOk;

  witnesses.push(leaf(leafIndex++, "DIV", ss, divisor, ex2, "E[x^2]"));
  witnesses.push(leaf(leafIndex++, "MUL", mean, mean, meanSq, "E[x]^2"));
  witnesses.push(leaf(leafIndex++, "SUB", ex2, meanSq, variance, "variance"));
  witnesses.push(
    leaf(leafIndex++, "GT", variance, varianceThreshold, varianceOk, "variance threshold")
  );
  witnesses.push(leaf(leafIndex++, "GT", mean, meanThreshold, meanOk, "mean threshold"));
  witnesses.push(
    leaf(leafIndex++, "BITAND", varianceOk, meanOk, accepted, "aggregate acceptance")
  );

  return {
    model: {
      values,
      mean,
      variance,
      formula: "E[x^2] - E[x]^2",
      meanThreshold,
      varianceThreshold,
      metadata: operation.metadata ?? null
    },
    witnesses
  };
}

function lowerPoorRatingSla(operation) {
  const values = parseIntegerArray(operation.values, "values");
  const poorThreshold = parseInteger(operation.poorThreshold ?? 2, "poorThreshold");
  const slaThreshold = parseInteger(operation.slaThreshold, "slaThreshold");
  const compareBelow = poorThreshold + 1;

  let leafIndex = 0;
  const witnesses = [];
  const poorBits = values.map((v) => (v <= poorThreshold ? 1 : 0));

  for (let i = 0; i < values.length; i += 1) {
    witnesses.push(
      leaf(
        leafIndex++,
        "LT",
        values[i],
        compareBelow,
        poorBits[i],
        `rating${i} <= ${poorThreshold}`
      )
    );
  }

  const padded = [...poorBits];
  const target = nextPowerOfTwo(padded.length);
  while (padded.length < target) {
    padded.push(0);
  }
  const countTree = buildSumTree(padded, leafIndex, "poor count");
  witnesses.push(...countTree.witnesses);
  leafIndex = countTree.nextIndex;

  const poorCount = poorBits.reduce((a, b) => a + b, 0);
  const slaBreached = poorCount > slaThreshold ? 1 : 0;

  witnesses.push(
    leaf(leafIndex++, "GT", poorCount, slaThreshold, slaBreached, "SLA breach flag")
  );

  return {
    model: {
      values,
      poorThreshold,
      poorCount,
      slaThreshold,
      slaBreached,
      metadata: operation.metadata ?? null
    },
    witnesses
  };
}

function lowerQoeDegradationAlarm(operation) {
  const throughputKbps = parseInteger(operation.throughputKbps, "throughputKbps", { min: 1 });
  const bitrateKbps = parseInteger(operation.bitrateKbps, "bitrateKbps", { min: 1 });
  const headroomPercent = parseInteger(operation.headroomPercent, "headroomPercent", { min: 1 });
  const observedMosMilli =
    operation.observedMosMilli === undefined
      ? null
      : parseInteger(operation.observedMosMilli, "observedMosMilli");
  const observedPoor =
    operation.observedPoor === undefined
      ? null
      : parseInteger(operation.observedPoor, "observedPoor");

  const capacityScore = throughputKbps * 100;
  const requiredScore = bitrateKbps * headroomPercent;
  const predictedPoor = capacityScore < requiredScore ? 1 : 0;
  const alarm = predictedPoor & 1;

  return {
    model: {
      throughputKbps,
      bitrateKbps,
      headroomPercent,
      capacityScore,
      requiredScore,
      predictedPoor,
      alarm,
      observedMosMilli,
      observedPoor,
      metadata: operation.metadata ?? null
    },
    witnesses: [
      leaf(0, "MUL", throughputKbps, 100, capacityScore, "throughput headroom score"),
      leaf(1, "MUL", bitrateKbps, headroomPercent, requiredScore, "required bitrate score"),
      leaf(2, "LT", capacityScore, requiredScore, predictedPoor, "MOS degradation predicate"),
      leaf(3, "BITAND", predictedPoor, 1, alarm, "poor-QoE alarm flag")
    ]
  };
}

function lowerQuantizedDecisionTree(operation) {
  const throughputKbps = parseInteger(operation.throughputKbps, "throughputKbps", { min: 1 });
  const bitrateKbps = parseInteger(operation.bitrateKbps, "bitrateKbps", { min: 1 });
  const rootBitrateThresholdKbps = parseInteger(
    operation.rootBitrateThresholdKbps,
    "rootBitrateThresholdKbps",
    { min: 1 }
  );
  const lowTputThresholdKbps = parseInteger(
    operation.lowTputThresholdKbps,
    "lowTputThresholdKbps"
  );
  const highTputThresholdKbps = parseInteger(
    operation.highTputThresholdKbps,
    "highTputThresholdKbps"
  );
  const observedMosMilli =
    operation.observedMosMilli === undefined
      ? null
      : parseInteger(operation.observedMosMilli, "observedMosMilli");
  const observedPoor =
    operation.observedPoor === undefined
      ? null
      : parseInteger(operation.observedPoor, "observedPoor");

  // Oblivious depth-2 tree evaluation: both branch predicates are computed
  // and masked by the root split, so the trace is straight-line and free of
  // data-dependent control flow.
  const hi = bitrateKbps > rootBitrateThresholdKbps ? 1 : 0;
  const lo = hi ^ 1;
  const poorLow = throughputKbps < lowTputThresholdKbps ? 1 : 0;
  const poorHigh = throughputKbps < highTputThresholdKbps ? 1 : 0;
  const contribLow = lo & poorLow;
  const contribHigh = hi & poorHigh;
  const predictedPoor = contribLow | contribHigh;
  const alarm = predictedPoor & 1;

  return {
    model: {
      throughputKbps,
      bitrateKbps,
      rootBitrateThresholdKbps,
      lowTputThresholdKbps,
      highTputThresholdKbps,
      branch: hi ? "high" : "low",
      predictedPoor,
      alarm,
      observedMosMilli,
      observedPoor,
      metadata: operation.metadata ?? null
    },
    witnesses: [
      leaf(0, "GT", bitrateKbps, rootBitrateThresholdKbps, hi, "root split: high-demand branch"),
      leaf(1, "BITXOR", hi, 1, lo, "root split: low-demand branch"),
      leaf(2, "LT", throughputKbps, lowTputThresholdKbps, poorLow, "low branch predicate"),
      leaf(3, "LT", throughputKbps, highTputThresholdKbps, poorHigh, "high branch predicate"),
      leaf(4, "BITAND", lo, poorLow, contribLow, "low branch contribution"),
      leaf(5, "BITAND", hi, poorHigh, contribHigh, "high branch contribution"),
      leaf(6, "BITOR", contribLow, contribHigh, predictedPoor, "tree prediction bit"),
      leaf(7, "BITAND", predictedPoor, 1, alarm, "poor-QoE alarm flag")
    ]
  };
}

// The public circuit fixes record identity and every dependency before values
// are supplied. Equal private values must never alias two distinct wires.
function lowerComplianceMonitor(operation, regional) {
  const valuesMilli = parseIntegerArray(operation.valuesMilli, "valuesMilli");
  const cells = regional ? parseIntegerArray(operation.cells, "cells") : [];
  if (regional && cells.length !== valuesMilli.length) throw new Error("one cell per MOS value required");
  const program = compileComplianceCircuit({ recordCount: valuesMilli.length, regional,
    poorThresholdMilli: operation.poorThresholdMilli, targetPermille: operation.targetPermille,
    targetCell: operation.targetCell ?? 0 });
  const inputValues = [...valuesMilli, ...cells];
  const reference = evaluateCircuitReference(program, inputValues);
  const resolve = ref => ref.kind === "constant" ? Number(ref.value)
    : ref.kind === "input" ? inputValues[ref.index] : Number(reference.outputs[ref.index]);
  const witnesses = program.instructions.map(instruction => ({
    ...leaf(instruction.index, instruction.opcode, resolve(instruction.lhs), resolve(instruction.rhs),
      Number(reference.outputs[instruction.index]), instruction.index >= program.unpaddedLength
        ? "carry terminal result through padding" : "explicit compliance circuit"),
    lhsRef: instruction.lhs, rhsRef: instruction.rhs
  }));
  const selected = valuesMilli.filter((_, i) => !regional || cells[i] === operation.targetCell);
  const goodCount = selected.filter(value => value > operation.poorThresholdMilli).length;
  const compliant = Number(reference.value);
  return { program, witnesses, model: {
    valuesMilli, poorThresholdMilli: operation.poorThresholdMilli,
    targetPermille: operation.targetPermille, compliant, violation: 1 - compliant,
    ...(regional ? { cells, targetCell: operation.targetCell, inRegionCount: selected.length,
      goodInRegionCount: goodCount,
      regionGoodPermille: selected.length ? Math.floor(goodCount * 1000 / selected.length) : null }
      : { goodCount, goodPermille: Math.floor(goodCount * 1000 / selected.length) }),
    indicator: regional
      ? "regional compliance <=> inRegionCount > 0 AND goodInRegionCount * 1000 >= inRegionCount * targetPermille"
      : "compliance <=> goodCount * 1000 >= n * targetPermille",
    metadata: operation.metadata ?? null
  }};
}
function lowerRegulatoryComplianceMonitor(operation) { return lowerComplianceMonitor(operation, false); }
function lowerRegionalComplianceMonitor(operation) { return lowerComplianceMonitor(operation, true); }

function lowerHistogramCount(operation) {
  const values = parseIntegerArray(operation.values, "values");
  if (values.length !== 8) {
    throw new Error("histogram_count currently expects exactly eight values");
  }
  const target = parseInteger(operation.target, "target");
  const threshold = parseInteger(operation.threshold, "threshold");
  const eq = values.map((v) => (v === target ? 1 : 0));
  const p0 = eq[0] + eq[1];
  const p1 = eq[2] + eq[3];
  const p2 = eq[4] + eq[5];
  const p3 = eq[6] + eq[7];
  const h0 = p0 + p1;
  const h1 = p2 + p3;
  const count = h0 + h1;
  const enough = count > threshold ? 1 : 0;

  return {
    model: { values, target, count, threshold },
    witnesses: [
      ...values.map((v, i) => leaf(i, "EQ", v, target, eq[i], `value${i} == target`)),
      leaf(8, "ADD", eq[0], eq[1], p0, "count pair 0"),
      leaf(9, "ADD", eq[2], eq[3], p1, "count pair 1"),
      leaf(10, "ADD", eq[4], eq[5], p2, "count pair 2"),
      leaf(11, "ADD", eq[6], eq[7], p3, "count pair 3"),
      leaf(12, "ADD", p0, p1, h0, "half count 0"),
      leaf(13, "ADD", p2, p3, h1, "half count 1"),
      leaf(14, "ADD", h0, h1, count, "target bin count"),
      leaf(15, "GT", count, threshold, enough, "count threshold")
    ]
  };
}

function lowerDecisionRule(operation) {
  const age = parseInteger(operation.age, "age");
  const income = parseInteger(operation.income, "income");
  const debt = parseInteger(operation.debt, "debt");
  const ageThreshold = parseInteger(operation.ageThreshold, "ageThreshold");
  const incomeThreshold = parseInteger(operation.incomeThreshold, "incomeThreshold");
  const debtThreshold = parseInteger(operation.debtThreshold, "debtThreshold");
  const expected = parseInteger(operation.expected, "expected");

  const ageOk = age > ageThreshold ? 1 : 0;
  const incomeOk = income > incomeThreshold ? 1 : 0;
  const debtOk = debt < debtThreshold ? 1 : 0;
  const strong = ageOk & incomeOk;
  const approved = strong & debtOk;
  const ok = approved === expected ? 1 : 0;
  const manualReview = approved ^ 1;
  const finalFlag = ok | manualReview;

  return {
    model: { age, income, debt, approved, thresholds: { ageThreshold, incomeThreshold, debtThreshold } },
    witnesses: [
      leaf(0, "GT", age, ageThreshold, ageOk, "age threshold"),
      leaf(1, "GT", income, incomeThreshold, incomeOk, "income threshold"),
      leaf(2, "LT", debt, debtThreshold, debtOk, "debt threshold"),
      leaf(3, "BITAND", ageOk, incomeOk, strong, "left branch"),
      leaf(4, "BITAND", strong, debtOk, approved, "approved leaf"),
      leaf(5, "EQ", approved, expected, ok, "expected class check"),
      leaf(6, "BITXOR", approved, 1, manualReview, "manual review flag"),
      leaf(7, "BITOR", ok, manualReview, finalFlag, "final policy flag")
    ]
  };
}

function lowerBucketizedFeatureScore(operation) {
  const userId = parseInteger(operation.userId, "userId");
  const bins = parseInteger(operation.bins, "bins", { min: 1 });
  const targetBucket = parseInteger(operation.targetBucket, "targetBucket");
  const income = parseInteger(operation.income, "income");
  const divisor = parseInteger(operation.divisor, "divisor", { min: 1 });
  const incomeThreshold = parseInteger(operation.incomeThreshold, "incomeThreshold");

  const bucket = userId % bins;
  const bucketU8 = bucket & 0xff;
  const bucketOk = bucketU8 === targetBucket ? 1 : 0;
  const incomeBucket = Math.floor(income / divisor);
  const incomeOk = incomeBucket > incomeThreshold ? 1 : 0;
  const eligible = bucketOk & incomeOk;
  const riskFlag = eligible ^ 0;
  const finalFlag = riskFlag | 0;

  return {
    model: { userId, bins, targetBucket, income, divisor, bucket, incomeBucket },
    witnesses: [
      leaf(0, "MOD", userId, bins, bucket, "bucket = userId mod bins"),
      leaf(1, "CAST_U8", bucket, 0, bucketU8, "bucket cast"),
      leaf(2, "EQ", bucketU8, targetBucket, bucketOk, "target bucket"),
      leaf(3, "DIV", income, divisor, incomeBucket, "income bucket"),
      leaf(4, "GT", incomeBucket, incomeThreshold, incomeOk, "income threshold"),
      leaf(5, "BITAND", bucketOk, incomeOk, eligible, "eligibility"),
      leaf(6, "BITXOR", eligible, 0, riskFlag, "risk flag"),
      leaf(7, "BITOR", riskFlag, 0, finalFlag, "final flag")
    ]
  };
}

/**
 * Attention monitor over an encrypted per-frame gaze-deviation stream.
 *
 * Each owner encodes its own gaze deviation magnitude per frame as an
 * unsigned milliradian value; the trace never receives a signed gaze vector.
 * The trace compares every frame against a public deviation threshold, counts
 * the off-centre frames homomorphically, and opens a single alarm bit. The
 * per-frame biometric values are never part of the released output.
 */
function lowerGazeAttentionMonitor(operation) {
  const deviationsMilli = parseIntegerArray(operation.deviationsMilli, "deviationsMilli");
  if (deviationsMilli.length < 2) {
    throw new Error("gaze_attention_monitor expects at least two frames");
  }
  const thresholdMilli = parseInteger(operation.offCenterThresholdMilli, "offCenterThresholdMilli", {
    min: 1
  });
  const targetPermille = parseInteger(operation.attentionTargetPermille, "attentionTargetPermille", {
    min: 1
  });
  if (targetPermille > 1000) {
    throw new Error("attentionTargetPermille must be <= 1000");
  }
  const n = deviationsMilli.length;

  let leafIndex = 0;
  const witnesses = [];
  const offBits = deviationsMilli.map((d) => (d > thresholdMilli ? 1 : 0));

  for (let i = 0; i < n; i += 1) {
    witnesses.push(
      leaf(
        leafIndex++,
        "GT",
        deviationsMilli[i],
        thresholdMilli,
        offBits[i],
        `frame${i} gaze deviation off centre`
      )
    );
  }

  const padded = [...offBits];
  const target = nextPowerOfTwo(padded.length);
  while (padded.length < target) {
    padded.push(0);
  }
  const countTree = buildSumTree(padded, leafIndex, "off-centre count");
  witnesses.push(...countTree.witnesses);
  leafIndex = countTree.nextIndex;

  const offCount = offBits.reduce((a, b) => a + b, 0);
  const scaledOff = offCount * 1000;
  const requiredScore = n * targetPermille;
  const alarm = scaledOff > requiredScore ? 1 : 0;

  witnesses.push(leaf(leafIndex++, "MUL", offCount, 1000, scaledOff, "off-centre permille scale"));
  witnesses.push(leaf(leafIndex++, "MUL", n, targetPermille, requiredScore, "attention target score"));
  witnesses.push(leaf(leafIndex++, "GT", scaledOff, requiredScore, alarm, "attention alarm bit"));

  return {
    model: {
      frames: n,
      offCenterThresholdMilli: thresholdMilli,
      attentionTargetPermille: targetPermille,
      offCenterCount: offCount,
      offCenterPermille: Math.floor(scaledOff / n),
      alarm,
      indicator: "alarm <=> offCenterCount * 1000 > frames * attentionTargetPermille",
      metadata: operation.metadata ?? null
    },
    witnesses
  };
}

/**
 * Quantized linear classifier over d encrypted features with public signed
 * weights. Signed arithmetic is avoided by accumulating the positively and
 * the negatively weighted products separately and deciding with one
 * comparison, so every leaf stays inside the unsigned micro-ISA.
 *
 * The two-feature `quantized_linear_classifier` above is left untouched; this
 * handler is additive and is used by workloads that need d != 2 or signed
 * weights.
 */
function lowerLinearClassifierNd(operation) {
  const features = parseIntegerArray(operation.features, "features");
  const weights = operation.weights;
  if (!Array.isArray(weights) || weights.length !== features.length) {
    throw new Error("linear_classifier_nd expects one integer weight per feature");
  }
  weights.forEach((w, i) => {
    if (!Number.isInteger(w)) {
      throw new Error(`weights[${i}] must be an integer; received ${w}`);
    }
  });
  const bias = operation.bias ?? 0;
  if (!Number.isInteger(bias)) {
    throw new Error(`bias must be an integer; received ${bias}`);
  }
  const expectedClass = parseInteger(operation.expectedClass, "expectedClass", { min: 0 });
  if (expectedClass > 1) {
    throw new Error("expectedClass must be 0 or 1");
  }

  let leafIndex = 0;
  const witnesses = [];
  const positives = [];
  const negatives = [];

  for (let i = 0; i < features.length; i += 1) {
    const magnitude = Math.abs(weights[i]);
    if (magnitude === 0) {
      continue;
    }
    const product = features[i] * magnitude;
    witnesses.push(
      leaf(leafIndex++, "MUL", features[i], magnitude, product, `feature${i} weighted product`)
    );
    (weights[i] > 0 ? positives : negatives).push(product);
  }
  if (positives.length === 0 && negatives.length === 0) {
    throw new Error("linear_classifier_nd requires at least one nonzero weight");
  }

  /** Sum one bucket; an empty bucket contributes the public constant 0. */
  const accumulate = (bucket, label) => {
    if (bucket.length === 0) {
      return 0;
    }
    if (bucket.length === 1) {
      return bucket[0];
    }
    const padded = [...bucket];
    const target = nextPowerOfTwo(padded.length);
    while (padded.length < target) {
      padded.push(0);
    }
    const tree = buildSumTree(padded, leafIndex, label);
    witnesses.push(...tree.witnesses);
    leafIndex = tree.nextIndex;
    return tree.sum;
  };

  let positiveTotal = accumulate(positives, "positive score");
  let negativeTotal = accumulate(negatives, "negative score");

  if (bias > 0) {
    const withBias = positiveTotal + bias;
    witnesses.push(leaf(leafIndex++, "ADD", positiveTotal, bias, withBias, "positive bias"));
    positiveTotal = withBias;
  } else if (bias < 0) {
    const magnitude = -bias;
    if (negatives.length === 0) {
      negativeTotal = magnitude;
    } else {
      const withBias = negativeTotal + magnitude;
      witnesses.push(leaf(leafIndex++, "ADD", negativeTotal, magnitude, withBias, "negative bias"));
      negativeTotal = withBias;
    }
  }

  const predicted = positiveTotal > negativeTotal ? 1 : 0;
  const classOk = predicted === expectedClass ? 1 : 0;
  const accepted = predicted & classOk;

  witnesses.push(
    leaf(leafIndex++, "GT", positiveTotal, negativeTotal, predicted, "classifier decision")
  );
  witnesses.push(leaf(leafIndex++, "EQ", predicted, expectedClass, classOk, "class consistency"));
  witnesses.push(leaf(leafIndex++, "BITAND", predicted, classOk, accepted, "final acceptance bit"));

  return {
    model: {
      features,
      weights,
      bias,
      scaleShift: operation.scaleShift ?? null,
      positiveTotal,
      negativeTotal,
      predicted,
      expectedClass,
      accepted,
      decision: "predicted <=> sum of positively weighted products > sum of negatively weighted products",
      metadata: operation.metadata ?? null
    },
    witnesses
  };
}

export const operationRegistry = Object.freeze({
  quantized_linear_classifier: lowerQuantizedLinearClassifier,
  linear_classifier_nd: lowerLinearClassifierNd,
  gaze_attention_monitor: lowerGazeAttentionMonitor,
  mean_variance: lowerMeanVariance,
  histogram_count: lowerHistogramCount,
  poor_rating_sla: lowerPoorRatingSla,
  qoe_degradation_alarm: lowerQoeDegradationAlarm,
  quantized_decision_tree: lowerQuantizedDecisionTree,
  // The five operation types below remain supported and unit-tested; no
  // evaluated workload instantiates them (see applicationWorkloadSpecs).
  regulatory_compliance_monitor: lowerRegulatoryComplianceMonitor,
  regional_compliance_monitor: lowerRegionalComplianceMonitor,
  decision_rule: lowerDecisionRule,
  bucketized_feature_score: lowerBucketizedFeatureScore
});

// Every evaluated workload is a real-data task declared in the implementation's
// dataset/workload table. The synthetic probes that used to sit here were
// removed: three duplicated the opcode set of a real workload, and the other
// two were tasks the implementation never declares. Coverage of the supported
// opcodes that no QoE indicator emits (SHR, MOD, CAST_U8, MIN, ADD_CHAIN) is
// established by scripts/micro-isa.test.mjs against the contract constants,
// not by an application workload over invented values.
export const applicationWorkloadSpecs = Object.freeze([]);

export function lowerWorkloadSpec(spec) {
  if (!spec || typeof spec !== "object") {
    throw new Error("workload spec must be an object");
  }
  if (!spec.operation || typeof spec.operation !== "object") {
    throw new Error(`${spec.id ?? "workload"} is missing an operation spec`);
  }
  const lowerer = operationRegistry[spec.operation.type];
  if (!lowerer) {
    throw new Error(`Unsupported operation type: ${spec.operation.type}`);
  }

  const lowered = lowerer(spec.operation);
  const unpaddedLeafCount = lowered.program?.unpaddedLength ?? lowered.witnesses.length;
  const witnesses = padWitnessesToPowerOfTwo(lowered.witnesses);
  assertPowerOfTwo(witnesses.length, spec.id);

  // Whole-trace invariant: every committed leaf must satisfy the same relation
  // the on-chain leaf verifier enforces, leaf indices must be dense and
  // ordered, and no opcode may fall outside the adjudicated micro-ISA. This is
  // the only place a semantically wrong honest trace can be caught, because the
  // optimistic path verifies no leaf on-chain.
  const semantics = assertTraceSemantics(witnesses, spec.id ?? "workload");

  return {
    id: spec.id,
    domain: spec.domain,
    title: spec.title,
    applicability: spec.applicability,
    limitation: spec.limitation,
    defaultManipulatedLeafIndex: spec.defaultManipulatedLeafIndex,
    model: lowered.model,
    ...(lowered.program ? { program: lowered.program } : {}),
    witnesses,
    lowering: {
      engineVersion: LOWERING_ENGINE_VERSION,
      operationType: spec.operation.type,
      operationSpec: spec.operation,
      unpaddedLeafCount,
      paddedLeafCount: witnesses.length,
      // Provenance for downstream analysis: which ISA the trace was checked
      // against, and how many leaves of each opcode it contains.
      microIsaSize: MICRO_ISA_SIZE,
      microIsaVerified: true,
      opcodeHistogram: semantics.opcodeHistogram,
      semantics: {
        integerDomain: "uint64",
        arithmetic: "deterministic unsigned integer arithmetic",
        division: "floor division with nonzero divisor",
        rangeGuards:
          "ADD/MUL overflow, SUB underflow, DIV/MOD by zero, SHR >= 64 bits and ADD_CHAIN length outside 1..8 are rejected",
        unsupported: "floating point, approximate CKKS tolerance semantics, stochastic training, and unsupported nonlinear functions"
      },
      warnings: lowered.loweringWarnings ?? []
    }
  };
}

export function syntheticApplicationWorkloadSpecs() {
  return applicationWorkloadSpecs;
}

export function allApplicationWorkloadSpecs() {
  return [
    ...applicationWorkloadSpecs,
    ...stav360WorkloadSpecs(),
    ...qoeMosWorkloadSpecs(),
    ...qoeTreeWorkloadSpecs(),
    ...regulatoryWorkloadSpecs(),
    ...webrtcWorkloadSpecs()
  ];
}

export function defaultApplicationWorkloads() {
  return allApplicationWorkloadSpecs().map(lowerWorkloadSpec);
}
