/**
 * Lowering of the ANATEL RQUAL regulatory-seal expression to the micro-ISA.
 *
 * DEMONSTRATION ONLY. This module deliberately does NOT register an operation
 * type in `operationRegistry`, and the workload it produces is deliberately NOT
 * a member of `allApplicationWorkloadSpecs()`. The eleven evaluated workloads
 * of the implementation and every artifact they produce are untouched by it. It
 * exists to show one thing: a formula written in a government regulation can be
 * translated into the adjudicated micro-ISA trace and settled on-chain.
 *
 * THE EXPRESSION (structure only; see anatel-rqual-params.json)
 * ------------------------------------------------------------
 *   technical measurements  -> IQS
 *   user survey responses   -> IQP = ISG
 *   user complaints         -> IR = 1000 * A_P / B_P
 *   S = F(IQS) + F(IQP) + F(IR)   ->   quality seal
 *
 * Res. 717/2019 Art. 7 defines IQS (VI), IQP (VII) and IR (V) and Art. 11
 * assigns seals A to E. The regulation does NOT publish F(.) or its numeric
 * band edges (Anexo I / Res. Interna 444/2025, not consulted), so every
 * threshold used below is a declared deployment parameter. This is not a
 * reproduction of ANATEL's official numbers.
 *
 * ARITHMETIC
 * ----------
 * Everything is unsigned 64-bit integer arithmetic over the 15-operation
 * micro-ISA of `micro-isa.mjs`. Fractions are carried in permille so that no
 * leaf needs a rational. Every `claimed` below is produced by `evaluateLeaf`,
 * the reference implementation of the on-chain validity predicate, and is
 * asserted against the value the emitting code expected: the trace therefore
 * cannot drift from the semantics the objective verifier enforces, and it
 * cannot silently drift from the reference values this demonstration narrates.
 */
// The micro-ISA and the leaf emitter are the pod's, not this demonstration's:
// the whole point is that a regulatory formula lowers to the SAME 15-operation
// instruction set the evaluated workloads use.
import { leaf, opcodeCounts } from "../../fhe-pod/scripts/application-lowering.mjs";
import {
  assertTraceSemantics,
  evaluateLeaf,
  PUBLIC_SCALAR_RHS_OPCODES
} from "../../fhe-pod/scripts/micro-isa.mjs";
import { anatelRqualInputs } from "./anatel-rqual-fixtures.mjs";

/** Mirrors LOWERING_ENGINE_VERSION of application-lowering.mjs. */
export const ANATEL_RQUAL_ENGINE_VERSION = "application-lowering-v2";

/** The operation type of this demonstration. Not in `operationRegistry`. */
export const ANATEL_RQUAL_OPERATION_TYPE = "anatel_rqual_seal";

/** The workload id. Not in `allApplicationWorkloadSpecs()`. */
export const ANATEL_RQUAL_WORKLOAD_ID = "anatel_rqual_seal_demo";

/** Permille scale: fractions are carried as parts per thousand. */
const PERMILLE = 1000;

/** Micro-ISA size, mirrored from micro-isa.mjs via the trace assertion. */
const MICRO_ISA_SIZE = 15;

function nextPowerOfTwo(n) {
  let p = 1;
  while (p < n) {
    p <<= 1;
  }
  return p;
}

/**
 * Emits one leaf and returns its result.
 *
 * The claimed value is NEVER supplied by the caller. It is computed by
 * `evaluateLeaf`, the reference implementation of
 * `FhevmObjectiveMicroVerifier._verifyClaim`, and cross-checked against the
 * value the caller expected. A lowering bug is therefore a build failure at the
 * leaf that caused it, and the narrated reference values below cannot disagree
 * with the committed trace.
 */
function emit(state, opcodeName, lhs, rhs, expected, note) {
  const verdict = evaluateLeaf(opcodeName, lhs, rhs);
  if (!verdict.valid) {
    throw new Error(
      `anatel-rqual: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) is rejected by the micro-ISA: ${verdict.reason}`
    );
  }
  const claimed = Number(verdict.value);
  if (!Number.isSafeInteger(claimed)) {
    throw new Error(
      `anatel-rqual: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) yields ${verdict.value}, outside the safe integer range`
    );
  }
  if (expected !== undefined && claimed !== expected) {
    throw new Error(
      `anatel-rqual: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) yields ${claimed}, ` +
        `but the reference computation expected ${expected}`
    );
  }
  const index = state.witnesses.length;
  state.witnesses.push(leaf(index, opcodeName, lhs, rhs, claimed, note));
  return { index, value: claimed };
}

/**
 * Left-associative chain of ADD leaves over `values`.
 *
 * A chain, not a balanced tree: the regulation's indicators are counts and
 * totals, and a chain keeps the accumulator explicit at every leaf, so a
 * bisection lands on the exact partial total a challenger disputes.
 */
function addChainOf(state, values, notePrefix) {
  if (values.length === 0) {
    throw new Error("anatel-rqual: cannot fold an empty chain");
  }
  let accumulator = values[0];
  let last = null;
  for (let i = 1; i < values.length; i += 1) {
    last = emit(state, "ADD", accumulator, values[i], accumulator + values[i], `${notePrefix} ${i}`);
    accumulator = last.value;
  }
  if (last === null) {
    throw new Error("anatel-rqual: a chain over a single value emits no leaf");
  }
  return last;
}

/**
 * F(x): the number of declared band edges that x exceeds, in 0..4.
 *
 * Four GT leaves plus a chain of ADD leaves. Monotone non-decreasing in x by
 * construction, because the edges are asserted ascending when the parameter
 * file is loaded.
 */
function bandOf(state, x, edges, label) {
  const bits = edges.map(
    (edge, i) => emit(state, "GT", x, edge, x > edge ? 1 : 0, `F(${label}): ${label} above band edge ${i} (${edge} permille)`).value
  );
  const band = addChainOf(state, bits, `F(${label}): band accumulation step`);
  return band;
}

/**
 * Lowers the RQUAL expression to a micro-ISA trace.
 *
 * @param {object} [inputs] result of `anatelRqualInputs()`; loaded if omitted
 * @returns {object} the same top-level shape `lowerWorkloadSpec` produces
 */
export function lowerAnatelRqual(inputs = anatelRqualInputs()) {
  const { iqsValuesMilli, iqpRatings, complaintsAp, accessBaseBp, params, provenance } = inputs;

  const {
    iqsPoorThresholdMilli,
    iqsSessionCount,
    iqpScaleMax,
    iqpPanelSize,
    bandEdgesPermille,
    sealCutoffs,
    sealLabels
  } = params;

  if (iqsValuesMilli.length !== iqsSessionCount) {
    throw new Error(
      `anatel-rqual: iqsSessionCount=${iqsSessionCount} but the panel holds ${iqsValuesMilli.length} measurements`
    );
  }
  if (iqpRatings.length !== iqpPanelSize) {
    throw new Error(
      `anatel-rqual: iqpPanelSize=${iqpPanelSize} but the panel holds ${iqpRatings.length} ratings`
    );
  }

  const state = { witnesses: [] };

  // ---------------------------------------------------------------- stage 1
  // IQS (Art. 7 VI), technical measurements.
  // Share of measured sessions whose milli-MOS exceeds the declared poor
  // threshold, expressed in permille. Only the per-session comparison bits are
  // ever summed; no individual measurement reaches the released output.
  const goodBits = iqsValuesMilli.map((value, i) =>
    emit(
      state,
      "GT",
      value,
      iqsPoorThresholdMilli,
      value > iqsPoorThresholdMilli ? 1 : 0,
      `IQS: session${i} milli-MOS above the poor threshold`
    ).value
  );
  const goodCountLeaf = addChainOf(state, goodBits, "IQS: good-session count step");
  const iqsScaledLeaf = emit(
    state,
    "MUL",
    goodCountLeaf.value,
    PERMILLE,
    goodCountLeaf.value * PERMILLE,
    "IQS: scale the good-session count to permille"
  );
  const iqsLeaf = emit(
    state,
    "DIV",
    iqsScaledLeaf.value,
    iqsSessionCount,
    Math.floor(iqsScaledLeaf.value / iqsSessionCount),
    "IQS: permille of sessions meeting the technical threshold (public scalar divisor)"
  );

  // ---------------------------------------------------------------- stage 2
  // IQP = ISG (Art. 7 VII), user survey responses.
  // Panel mean on the ACR scale, expressed as permille of the scale ceiling.
  // The panel total is the only aggregate that leaves the survey stage; no
  // subject's individual score is released.
  const ratingSumLeaf = addChainOf(state, iqpRatings, "IQP: opinion-score accumulation step");
  const iqpScaledLeaf = emit(
    state,
    "MUL",
    ratingSumLeaf.value,
    PERMILLE,
    ratingSumLeaf.value * PERMILLE,
    "IQP: scale the panel total to milli-units before dividing"
  );
  const iqpMeanMilliLeaf = emit(
    state,
    "DIV",
    iqpScaledLeaf.value,
    iqpPanelSize,
    Math.floor(iqpScaledLeaf.value / iqpPanelSize),
    "IQP: milli-ACR panel mean (public scalar divisor = panel size)"
  );
  const iqpLeaf = emit(
    state,
    "DIV",
    iqpMeanMilliLeaf.value,
    iqpScaleMax,
    Math.floor(iqpMeanMilliLeaf.value / iqpScaleMax),
    "IQP: permille of the ACR ceiling (public scalar divisor = scale maximum)"
  );

  // ---------------------------------------------------------------- stage 3
  // IR (Art. 7 V), user complaints: IR = 1000 * A_P / B_P.
  // A_P is the encrypted, authenticated input of this stage; B_P is a public
  // scalar divisor. IR rises with complaints, so it is inverted to a score
  // where higher is better, and the inversion is guarded: MIN clamps IR to the
  // permille ceiling BEFORE the subtraction, because a SUB that would underflow
  // is rejected outright by the objective verifier and would abort the trace
  // rather than produce a floor of zero.
  const irScaledLeaf = emit(
    state,
    "MUL",
    complaintsAp,
    PERMILLE,
    complaintsAp * PERMILLE,
    "IR: scale the complaint count A_P by 1000"
  );
  const irLeaf = emit(
    state,
    "DIV",
    irScaledLeaf.value,
    accessBaseBp,
    Math.floor(irScaledLeaf.value / accessBaseBp),
    "IR: 1000 * A_P / B_P, with the access base B_P as a public scalar divisor"
  );
  const irGuardedLeaf = emit(
    state,
    "MIN",
    irLeaf.value,
    PERMILLE,
    Math.min(irLeaf.value, PERMILLE),
    "IR: clamp to the permille ceiling so the inversion below cannot underflow"
  );
  const irScoreLeaf = emit(
    state,
    "SUB",
    PERMILLE,
    irGuardedLeaf.value,
    PERMILLE - irGuardedLeaf.value,
    "IR: invert to a score in permille where higher is better"
  );

  // ---------------------------------------------------------------- stage 4
  // F(.) applied to each indicator. Deployment parameters, not ANATEL values.
  const bandIqsLeaf = bandOf(state, iqsLeaf.value, bandEdgesPermille, "IQS");
  const bandIqpLeaf = bandOf(state, iqpLeaf.value, bandEdgesPermille, "IQP");
  const bandIrLeaf = bandOf(state, irScoreLeaf.value, bandEdgesPermille, "IR");

  // ---------------------------------------------------------------- stage 5
  // S = F(IQS) + F(IQP) + F(IR), then the seal index.
  const sPartialLeaf = emit(
    state,
    "ADD",
    bandIqsLeaf.value,
    bandIqpLeaf.value,
    bandIqsLeaf.value + bandIqpLeaf.value,
    "S: F(IQS) + F(IQP)"
  );
  const sLeaf = emit(
    state,
    "ADD",
    sPartialLeaf.value,
    bandIrLeaf.value,
    sPartialLeaf.value + bandIrLeaf.value,
    "S: + F(IR), the composite regulatory score in 0..12"
  );
  const sealBits = sealCutoffs.map(
    (cutoff, i) =>
      emit(
        state,
        "GT",
        sLeaf.value,
        cutoff,
        sLeaf.value > cutoff ? 1 : 0,
        `seal: S above cut-off ${i} (${cutoff})`
      ).value
  );
  const sealLeaf = addChainOf(state, sealBits, "seal: band accumulation step");

  // The released value is the seal index and nothing else. It is the FINAL
  // leaf of the unpadded trace, and it is the leaf a conflicted operator has
  // every incentive to inflate, so it is also the leaf this demonstration
  // corrupts by default.
  const releasedLeafIndex = sealLeaf.index;
  if (releasedLeafIndex !== state.witnesses.length - 1) {
    throw new Error(
      `anatel-rqual: the seal index is emitted at leaf ${releasedLeafIndex}, ` +
        `which is not the final leaf ${state.witnesses.length - 1} of the unpadded trace`
    );
  }

  const unpaddedLeafCount = state.witnesses.length;

  // Padding to the next power of two with ADD 0+0 no-ops, exactly as
  // padWitnessesToPowerOfTwo does in application-lowering.mjs: the bisection
  // game halves a power-of-two trace.
  const target = nextPowerOfTwo(unpaddedLeafCount);
  while (state.witnesses.length < target) {
    state.witnesses.push(leaf(state.witnesses.length, "ADD", 0, 0, 0, "padding no-op"));
  }
  const witnesses = state.witnesses;
  if (witnesses.length <= 0 || (witnesses.length & (witnesses.length - 1)) !== 0) {
    throw new Error(
      `anatel-rqual: produced ${witnesses.length} leaves; leaf count must be a power of two`
    );
  }

  // Whole-trace invariant against the same relation the on-chain leaf verifier
  // enforces. The optimistic path re-executes no leaf, so this is the only
  // place a semantically wrong honest trace is caught off-chain.
  const semantics = assertTraceSemantics(witnesses, "anatel-rqual");

  // Independent second pass: re-evaluate every committed leaf and require the
  // claimed value to match. `assertTraceSemantics` already does this; the
  // duplicate is cheap and makes the guarantee local to this file.
  for (const [index, witness] of witnesses.entries()) {
    const verdict = evaluateLeaf(witness.opcode_name, witness.lhs, witness.rhs);
    if (!verdict.valid || Number(verdict.value) !== Number(witness.claimed)) {
      throw new Error(
        `anatel-rqual: leaf ${index} (${witness.opcode_name}) claims ${witness.claimed} ` +
          `but the micro-ISA yields ${verdict.valid ? verdict.value : `invalid (${verdict.reason})`}`
      );
    }
  }

  const sealIndex = sealLeaf.value;
  const sealLabel = Array.isArray(sealLabels) ? (sealLabels[sealIndex] ?? null) : null;

  const model = {
    // The plaintext reference values the demonstration narrates. They are the
    // claimed values of the corresponding leaves, not a parallel computation.
    iqsGoodCount: goodCountLeaf.value,
    iqsPermille: iqsLeaf.value,
    iqpSum: ratingSumLeaf.value,
    iqpMeanMilli: iqpMeanMilliLeaf.value,
    iqpPermille: iqpLeaf.value,
    irPermille: irLeaf.value,
    irScorePermille: irScoreLeaf.value,
    bandIqs: bandIqsLeaf.value,
    bandIqp: bandIqpLeaf.value,
    bandIr: bandIrLeaf.value,
    compositeScoreS: sLeaf.value,
    sealIndex,
    sealLabel,
    // Leaf addresses, so a reader can point at the trace position of each value.
    leafIndex: {
      iqs: iqsLeaf.index,
      iqp: iqpLeaf.index,
      ir: irLeaf.index,
      irScore: irScoreLeaf.index,
      bandIqs: bandIqsLeaf.index,
      bandIqp: bandIqpLeaf.index,
      bandIr: bandIrLeaf.index,
      compositeScoreS: sLeaf.index,
      sealIndex: releasedLeafIndex
    },
    releasedLeafIndex,
    releasedValue: sealIndex,
    // Why this leaf is the one the demonstration corrupts.
    manipulationRationale:
      "The seal index is the only value released to the regulator and to the public. " +
      "A conflicted operator's incentive is to inflate its own seal, so the demonstration " +
      "corrupts exactly that leaf and lets the dispute game settle it.",
    declaredParameters: {
      iqsPoorThresholdMilli,
      iqsSessionCount,
      iqpScaleMax,
      iqpPanelSize,
      complaintsAp,
      accessBaseBp,
      bandEdgesPermille,
      sealCutoffs
    },
    indicator:
      "IQS = 1000 * |{sessions with milliMOS > poorThreshold}| / n; " +
      "IQP = 1000 * mean(ACR) / scaleMax; " +
      "IR = 1000 * A_P / B_P, IRscore = 1000 - min(IR, 1000); " +
      "F(x) = |{edges : x > edge}|; S = F(IQS) + F(IQP) + F(IR); " +
      "sealIndex = |{cutoffs : S > cutoff}|",
    publicScalarOpcodes: PUBLIC_SCALAR_RHS_OPCODES,
    provenance,
    disclaimer: params.disclaimer,
    parameterNotes: params.notes
  };

  const operationSpec = {
    type: ANATEL_RQUAL_OPERATION_TYPE,
    iqsValuesMilli,
    iqsPoorThresholdMilli,
    iqsSessionCount,
    iqpRatings,
    iqpPanelSize,
    iqpScaleMax,
    complaintsAp,
    accessBaseBp,
    bandEdgesPermille,
    sealCutoffs,
    metadata: {
      demonstrationOnly: true,
      registeredInOperationRegistry: false,
      partOfEvaluatedWorkloadSet: false,
      structureSource: params.structureSource,
      expression: params.expression,
      disclaimer: params.disclaimer,
      provenance
    }
  };

  return {
    id: ANATEL_RQUAL_WORKLOAD_ID,
    domain: "QoE / regulatory quality assessment (demonstration)",
    title:
      "ANATEL RQUAL regulatory quality seal over encrypted technical, survey and complaint indicators (demonstration)",
    applicability:
      "Shows that a composite quality indicator written in a government regulation - IQS from technical " +
      "measurements, IQP from user survey responses, IR from user complaints, combined as " +
      "S = F(IQS) + F(IQP) + F(IR) into a quality seal - can be lowered to the adjudicated micro-ISA and " +
      "settled by the existing dispute game, so a regulator can verify the published seal without seeing " +
      "any per-session measurement or any subject's opinion score.",
    limitation:
      "DEMONSTRATION ONLY, and not part of the evaluated workload set. Only the STRUCTURE of the expression " +
      "was verified against the regulation (Res. 717/2019 Art. 7 defines IQS, IQP and IR; Art. 11 assigns " +
      "seals A to E). The regulation does NOT publish the F(.) mapping or any numeric band edge - those live " +
      "in Anexo I / Res. Interna 444/2025, which was not consulted - so every weight, threshold, band edge and " +
      "seal cut-off used here is a declared deployment parameter chosen in the range of such reference values, " +
      "NOT a value prescribed by ANATEL, and the released seal is NOT an official RQUAL result. The IQS and IQP " +
      "panels are real measured data (16 drive-test milli-MOS values and 20 subjects' ACR scores), but the two " +
      "IR scalars A_P and B_P are illustrative period constants, not measured. Integer floor division loses " +
      "sub-permille precision at every quotient. The default manipulated leaf is leaf " +
      `${releasedLeafIndex}, the ADD that produces the seal index: it is the only value the trace releases, and ` +
      "inflating its own seal is exactly the misreport a conflicted operator has an incentive to publish, so " +
      "that is the leaf the challenge, bisection and objective leaf resolution settle.",
    defaultManipulatedLeafIndex: releasedLeafIndex,
    model,
    witnesses,
    lowering: {
      engineVersion: ANATEL_RQUAL_ENGINE_VERSION,
      operationType: ANATEL_RQUAL_OPERATION_TYPE,
      operationSpec,
      unpaddedLeafCount,
      paddedLeafCount: witnesses.length,
      microIsaSize: MICRO_ISA_SIZE,
      microIsaVerified: true,
      opcodeHistogram: semantics.opcodeHistogram,
      semantics: {
        integerDomain: "uint64",
        arithmetic: "deterministic unsigned integer arithmetic",
        division: "floor division with nonzero divisor",
        rangeGuards:
          "ADD/MUL overflow, SUB underflow, DIV/MOD by zero, SHR >= 64 bits and ADD_CHAIN length outside 1..8 are rejected",
        unsupported:
          "floating point, approximate CKKS tolerance semantics, stochastic training, and unsupported nonlinear functions"
      },
      warnings: [
        "demonstration-only workload: not registered in operationRegistry and not a member of allApplicationWorkloadSpecs()",
        "all thresholds, band edges and seal cut-offs are declared deployment parameters, not ANATEL-prescribed values",
        "the IR scalars A_P and B_P are illustrative period constants, not measured quantities"
      ]
    }
  };
}

/** Convenience: the opcode histogram of a lowered trace, in the shared format. */
export function anatelRqualOpcodeCounts(witnesses) {
  return opcodeCounts(witnesses);
}

export default lowerAnatelRqual;
