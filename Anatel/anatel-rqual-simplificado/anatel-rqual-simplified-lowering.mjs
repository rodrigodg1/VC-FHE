/**
 * Lowers the ANATEL RQUAL expression to the adjudicated micro-ISA, in the
 * SMALLEST trace that still carries the whole structure.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * ../anatel-rqual/ lowers the same expression over real measurement panels and
 * produces 89 useful leaves padded to 128, of which 87 are additions of an
 * accumulation chain. That trace is right for showing that the architecture
 * handles a real workload and wrong for showing how a formula becomes opcodes:
 * the interesting structure is buried under the panel reduction.
 *
 * This variant supplies IQS and IQP as pre-aggregated encrypted indicators and
 * uses three band edges instead of four. The result is 28 useful leaves padded
 * to 32, every one of which fits on a single screen, while still exercising six
 * of the fifteen operations, the public-scalar division rule, the underflow
 * guard, and the same dispute pipeline against the same contracts.
 *
 * WHAT IS IDENTICAL TO THE FULL DEMONSTRATION
 * -------------------------------------------
 * The expression, the micro-ISA, the leaf emitter, the whole-trace semantic
 * assertion, the power-of-two padding, the released value, the choice of the
 * corrupted leaf, and every downstream stage: encryption with tfhe-rs,
 * provenance registration, task authorization, the optimistic path, disclosure,
 * bisection, objective leaf resolution and settlement.
 *
 * WHAT IS DELIBERATELY DIFFERENT, AND MUST BE SAID WHEN BOTH ARE SHOWN
 * --------------------------------------------------------------------
 * 1. IQS and IQP are declared scalars here, not aggregates of a measured panel.
 *    Nothing in this variant is measured data.
 * 2. F(.) has three band edges here and four there, so the same indicator lands
 *    on a different band and the two runs release different seals. That is
 *    expected, not a discrepancy.
 *
 * As in the full demonstration, no leaf's claimed value is written by hand:
 * every one is produced by `evaluateLeaf`, the reference implementation of the
 * on-chain validity predicate, and asserted against the value the emitting code
 * expected.
 */
import { leaf, opcodeCounts } from "../../fhe-pod/scripts/application-lowering.mjs";
import {
  assertTraceSemantics,
  evaluateLeaf,
  PUBLIC_SCALAR_RHS_OPCODES
} from "../../fhe-pod/scripts/micro-isa.mjs";
import { simplifiedRqualInputs } from "./anatel-rqual-simplified-fixtures.mjs";

/** Mirrors LOWERING_ENGINE_VERSION of application-lowering.mjs. */
export const SIMPLIFIED_ENGINE_VERSION = "application-lowering-v2";

/** The operation type of this demonstration. Not in `operationRegistry`. */
export const SIMPLIFIED_OPERATION_TYPE = "anatel_rqual_seal_simplified";

/** The workload id. Not in `allApplicationWorkloadSpecs()`. */
export const SIMPLIFIED_WORKLOAD_ID = "anatel_rqual_seal_simplified_demo";

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
 * `evaluateLeaf` and cross-checked against the value the caller expected, so a
 * lowering bug is a build failure at the leaf that caused it.
 */
function emit(state, opcodeName, lhs, rhs, expected, note) {
  const verdict = evaluateLeaf(opcodeName, lhs, rhs);
  if (!verdict.valid) {
    throw new Error(
      `anatel-rqual-simplified: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) is rejected by the micro-ISA: ${verdict.reason}`
    );
  }
  const claimed = Number(verdict.value);
  if (!Number.isSafeInteger(claimed)) {
    throw new Error(
      `anatel-rqual-simplified: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) yields ${verdict.value}, outside the safe integer range`
    );
  }
  if (expected !== undefined && claimed !== expected) {
    throw new Error(
      `anatel-rqual-simplified: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) yields ${claimed}, ` +
        `but the reference computation expected ${expected}`
    );
  }
  const index = state.witnesses.length;
  state.witnesses.push(leaf(index, opcodeName, lhs, rhs, claimed, note));
  return { index, value: claimed };
}

/** Left-associative chain of ADD leaves over `values`: n values cost n-1 leaves. */
function addChainOf(state, values, notePrefix) {
  if (values.length === 0) {
    throw new Error("anatel-rqual-simplified: cannot fold an empty chain");
  }
  let accumulator = values[0];
  let last = null;
  for (let i = 1; i < values.length; i += 1) {
    last = emit(state, "ADD", accumulator, values[i], accumulator + values[i], `${notePrefix} ${i}`);
    accumulator = last.value;
  }
  if (last === null) {
    throw new Error("anatel-rqual-simplified: a chain over a single value emits no leaf");
  }
  return last;
}

/**
 * F(x): the number of declared band edges that x exceeds.
 *
 * One GT per edge plus a chain of ADD leaves to count them, so k edges cost
 * k + (k - 1) leaves. Monotone non-decreasing in x by construction, because the
 * edges are asserted ascending when the parameter file is loaded.
 */
function bandOf(state, x, edges, label) {
  const bits = edges.map(
    (edge, i) => emit(state, "GT", x, edge, x > edge ? 1 : 0, `F(${label}): ${label} above band edge ${i} (${edge} permille)`).value
  );
  return addChainOf(state, bits, `F(${label}): band accumulation step`);
}

/**
 * Lowers the simplified RQUAL expression to a micro-ISA trace.
 *
 * @param {object} [inputs] result of `simplifiedRqualInputs()`; loaded if omitted
 * @returns {object} the same top-level shape `lowerWorkloadSpec` produces
 */
export function lowerSimplifiedRqual(inputs = simplifiedRqualInputs()) {
  const { iqsPermille, iqpPermille, complaintsAp, accessBaseBp, params, provenance } = inputs;
  const { bandEdgesPermille, sealCutoffs, sealLabels } = params;

  const state = { witnesses: [] };

  // ---------------------------------------------------------------- stage 1
  // IR (Art. 7 V), user complaints: IR = 1000 * A_P / B_P.
  //
  // This stage is kept in full, and it is deliberately FIRST, because it is the
  // only place in this short trace where the two rules of the instruction set
  // are visible: A_P is the encrypted input and B_P is a PUBLIC scalar divisor,
  // because DIV does not accept an encrypted right-hand operand; and the MIN
  // clamps IR to the permille ceiling BEFORE the subtraction, because a SUB that
  // would underflow is rejected outright by the objective verifier and would
  // abort the trace rather than saturate at zero.
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

  // ---------------------------------------------------------------- stage 2
  // F(.) applied to each indicator. IQS and IQP enter here directly: in this
  // variant they ARE the encrypted inputs, with no aggregation stage above them.
  const bandIqsLeaf = bandOf(state, iqsPermille, bandEdgesPermille, "IQS");
  const bandIqpLeaf = bandOf(state, iqpPermille, bandEdgesPermille, "IQP");
  const bandIrLeaf = bandOf(state, irScoreLeaf.value, bandEdgesPermille, "IR");

  // ---------------------------------------------------------------- stage 3
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
    `S: + F(IR), the composite regulatory score in 0..${3 * bandEdgesPermille.length}`
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

  // The released value is the seal index and nothing else. It is the FINAL leaf
  // of the unpadded trace, and it is the leaf a conflicted operator has every
  // incentive to inflate, so it is also the leaf this demonstration corrupts.
  const releasedLeafIndex = sealLeaf.index;
  if (releasedLeafIndex !== state.witnesses.length - 1) {
    throw new Error(
      `anatel-rqual-simplified: the seal index is emitted at leaf ${releasedLeafIndex}, ` +
        `which is not the final leaf ${state.witnesses.length - 1} of the unpadded trace`
    );
  }

  const unpaddedLeafCount = state.witnesses.length;

  // Padding to the next power of two with ADD 0+0 no-ops, exactly as
  // padWitnessesToPowerOfTwo does: the bisection game halves a power-of-two trace.
  const target = nextPowerOfTwo(unpaddedLeafCount);
  while (state.witnesses.length < target) {
    state.witnesses.push(leaf(state.witnesses.length, "ADD", 0, 0, 0, "padding no-op"));
  }
  const witnesses = state.witnesses;
  if (witnesses.length <= 0 || (witnesses.length & (witnesses.length - 1)) !== 0) {
    throw new Error(
      `anatel-rqual-simplified: produced ${witnesses.length} leaves; leaf count must be a power of two`
    );
  }

  // Whole-trace invariant against the same relation the on-chain leaf verifier
  // enforces. The optimistic path re-executes no leaf, so this is the only place
  // a semantically wrong honest trace is caught off-chain.
  const semantics = assertTraceSemantics(witnesses, "anatel-rqual-simplified");

  // Independent second pass, cheap, and it makes the guarantee local to this file.
  for (const [index, witness] of witnesses.entries()) {
    const verdict = evaluateLeaf(witness.opcode_name, witness.lhs, witness.rhs);
    if (!verdict.valid || Number(verdict.value) !== Number(witness.claimed)) {
      throw new Error(
        `anatel-rqual-simplified: leaf ${index} (${witness.opcode_name}) claims ${witness.claimed} ` +
          `but the micro-ISA yields ${verdict.valid ? verdict.value : `invalid (${verdict.reason})`}`
      );
    }
  }

  const sealIndex = sealLeaf.value;
  const sealLabel = Array.isArray(sealLabels) ? (sealLabels[sealIndex] ?? null) : null;

  const model = {
    // The plaintext reference values the demonstration narrates. They are the
    // claimed values of the corresponding leaves, not a parallel computation.
    iqsPermille,
    iqpPermille,
    irPermille: irLeaf.value,
    irScorePermille: irScoreLeaf.value,
    bandIqs: bandIqsLeaf.value,
    bandIqp: bandIqpLeaf.value,
    bandIr: bandIrLeaf.value,
    compositeScoreS: sLeaf.value,
    compositeScoreMax: 3 * bandEdgesPermille.length,
    sealIndex,
    sealLabel,
    leafIndex: {
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
    manipulationRationale:
      "The seal index is the only value released to the regulator and to the public. " +
      "A conflicted operator's incentive is to inflate its own seal, so the demonstration " +
      "corrupts exactly that leaf and lets the dispute game settle it.",
    declaredParameters: {
      iqsPermille,
      iqpPermille,
      complaintsAp,
      accessBaseBp,
      bandEdgesPermille,
      sealCutoffs
    },
    indicator:
      "IQS and IQP are supplied as pre-aggregated encrypted indicators in permille; " +
      "IR = 1000 * A_P / B_P, IRscore = 1000 - min(IR, 1000); " +
      "F(x) = |{edges : x > edge}|; S = F(IQS) + F(IQP) + F(IR); " +
      "sealIndex = |{cutoffs : S > cutoff}|",
    publicScalarOpcodes: PUBLIC_SCALAR_RHS_OPCODES,
    provenance,
    disclaimer: params.disclaimer,
    relationToFullDemo: params.relationToFullDemo,
    parameterNotes: params.notes
  };

  const operationSpec = {
    type: SIMPLIFIED_OPERATION_TYPE,
    iqsPermille,
    iqpPermille,
    complaintsAp,
    accessBaseBp,
    bandEdgesPermille,
    sealCutoffs,
    metadata: {
      demonstrationOnly: true,
      teachingVariant: true,
      registeredInOperationRegistry: false,
      partOfEvaluatedWorkloadSet: false,
      structureSource: params.structureSource,
      expression: params.expression,
      disclaimer: params.disclaimer,
      relationToFullDemo: params.relationToFullDemo,
      provenance
    }
  };

  return {
    id: SIMPLIFIED_WORKLOAD_ID,
    domain: "QoE / regulatory quality assessment (teaching demonstration)",
    title:
      "ANATEL RQUAL regulatory quality seal over three encrypted indicators, smallest trace (teaching demonstration)",
    applicability:
      "Shows the same composite quality indicator as ../anatel-rqual/ - S = F(IQS) + F(IQP) + F(IR) - lowered to " +
      "the adjudicated micro-ISA and settled by the existing dispute game, in a trace short enough to read leaf " +
      "by leaf. Intended for explaining how an expression becomes opcodes, not for evidence about scale.",
    limitation:
      "TEACHING DEMONSTRATION, and not part of the evaluated workload set. NOTHING here is measured: unlike " +
      "../anatel-rqual/, whose IQS and IQP come from a 16-session drive-test panel and a 20-subject ACR panel, " +
      "this variant supplies both indicators as declared scalars, and A_P and B_P remain illustrative period " +
      "constants. Only the STRUCTURE of the expression was verified against the regulation (Res. 717/2019 Art. 7 " +
      "defines IQS, IQP and IR; Art. 11 assigns seals A to E); the F(.) mapping and every numeric edge and cut-off " +
      "is a declared deployment parameter, NOT prescribed by ANATEL, and the released seal is NOT an official RQUAL " +
      "result. F(.) uses three band edges here against four in the full demonstration, so the two runs assign " +
      "different bands to the same indicator and release different seals; that difference is deliberate and is not " +
      "a discrepancy between them. Integer floor division loses sub-permille precision at every quotient. The " +
      `default manipulated leaf is leaf ${releasedLeafIndex}, the ADD that produces the seal index: it is the only ` +
      "value the trace releases, and inflating its own seal is exactly the misreport a conflicted operator has an " +
      "incentive to publish, so that is the leaf the challenge, bisection and objective leaf resolution settle.",
    defaultManipulatedLeafIndex: releasedLeafIndex,
    model,
    witnesses,
    lowering: {
      engineVersion: SIMPLIFIED_ENGINE_VERSION,
      operationType: SIMPLIFIED_OPERATION_TYPE,
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
        "teaching demonstration: not registered in operationRegistry and not a member of allApplicationWorkloadSpecs()",
        "no input is measured data; every value is a declared deployment parameter",
        "F(.) uses three band edges here and four in ../anatel-rqual/, so the two demonstrations release different seals"
      ]
    }
  };
}

/** Convenience: the opcode histogram of a lowered trace, in the shared format. */
export function simplifiedRqualOpcodeCounts(witnesses) {
  return opcodeCounts(witnesses);
}
