/**
 * Lowers one arithmetic expression to the adjudicated micro-ISA:
 *
 *     total = x + y * z
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The two ANATEL demonstrations answer "can a real regulatory formula run
 * through this protocol". They are not the right place to answer "what does the
 * protocol actually DO to a computation", because in both of them the mechanism
 * is spread across 28 or 89 leaves and the reader has to hold a regulation in
 * mind at the same time.
 *
 * This example answers only the second question, on the shortest trace that
 * still passes through every stage of the protocol. Standard precedence fixes
 * the order, and the order of the leaves is what the protocol commits to:
 *
 *     leaf 0   MUL   y * z                    both operands encrypted
 *     leaf 1   ADD   x + (y*z)  = total       consumes the previous leaf
 *
 * Two leaves, which is ALREADY a power of two, so this trace needs no padding;
 * one bisection round; two of the fifteen operations. Every operand is a
 * ciphertext, without exception.
 *
 * WHAT IS NOT HERE
 * ----------------
 * Three real parts of the instruction set that this expression deliberately does
 * not reach:
 *
 *   - DIV, and with it the PUBLIC SCALAR rule. Four of the fifteen opcodes
 *     (DIV, MOD, SHR, ADD_CHAIN) take a CLEARTEXT right operand, because the
 *     homomorphic operation is the scalar variant. No leaf here does.
 *   - integer TRUNCATION, which is where an integer trace stops being a neutral
 *     translation of the formula and becomes the definition of what is judged.
 *   - SUB, and its underflow guard: a subtraction that would go below zero is
 *     REJECTED by the objective verifier rather than saturated at zero.
 *
 * ../../Anatel/anatel-rqual-simplificado/ contains all three. Dropping them buys the
 * shortest trace the protocol can run, and costs those three lessons.
 *
 * WHAT IS IDENTICAL TO THE ANATEL DEMONSTRATIONS AND TO THE EVALUATED WORKLOADS
 * ----------------------------------------------------------------------------
 * Everything downstream of this file: the leaf emitter, the whole-trace semantic
 * assertion, the power-of-two padding (a no-op here), encryption with tfhe-rs, provenance
 * registration, task authorization, the optimistic path, disclosure, bisection,
 * the homomorphic leaf decision and settlement. The contracts are the same, the
 * chain is the same, `demo:hardhat` is the same script.
 *
 * As in every other lowering here, no leaf's claimed value is written by hand:
 * every one is produced by `evaluateLeaf`, the reference implementation of the
 * on-chain validity predicate, and asserted against the value the emitting code
 * expected. A lowering bug is a build failure at the leaf that caused it.
 */
import { leaf, opcodeCounts } from "../../fhe-pod/scripts/application-lowering.mjs";
import {
  assertTraceSemantics,
  evaluateLeaf,
  PUBLIC_SCALAR_RHS_OPCODES
} from "../../fhe-pod/scripts/micro-isa.mjs";
import { arithmeticInputs } from "./arithmetic-demo-fixtures.mjs";

/** Mirrors LOWERING_ENGINE_VERSION of application-lowering.mjs. */
export const ARITHMETIC_ENGINE_VERSION = "application-lowering-v2";

/** The operation type of this example. Deliberately not in `operationRegistry`. */
export const ARITHMETIC_OPERATION_TYPE = "arithmetic_teaching_example";

/** The workload id. Deliberately not in `allApplicationWorkloadSpecs()`. */
export const ARITHMETIC_WORKLOAD_ID = "arithmetic_teaching_example_demo";

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
 * Emits one leaf and returns its index and its result.
 *
 * The claimed value is NEVER supplied by the caller. It is computed by
 * `evaluateLeaf` and cross-checked against the value the caller expected, so the
 * trace cannot drift away from the expression it is supposed to implement.
 */
function emit(state, opcodeName, lhs, rhs, expected, note) {
  const verdict = evaluateLeaf(opcodeName, lhs, rhs);
  if (!verdict.valid) {
    throw new Error(
      `arithmetic-demo: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) is rejected by the micro-ISA: ${verdict.reason}`
    );
  }
  const claimed = Number(verdict.value);
  if (!Number.isSafeInteger(claimed)) {
    throw new Error(
      `arithmetic-demo: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) yields ${verdict.value}, outside the safe integer range`
    );
  }
  if (expected !== undefined && claimed !== expected) {
    throw new Error(
      `arithmetic-demo: leaf ${state.witnesses.length} ${opcodeName}(${lhs}, ${rhs}) yields ${claimed}, ` +
        `but the reference computation expected ${expected}`
    );
  }
  const index = state.witnesses.length;
  state.witnesses.push(leaf(index, opcodeName, lhs, rhs, claimed, note));
  return { index, value: claimed };
}

/**
 * Lowers `total = x + y * z` to a micro-ISA trace.
 *
 * @param {object} [inputs] result of `arithmeticInputs()`; loaded if omitted
 * @returns {object} the same top-level shape `lowerWorkloadSpec` produces
 */
export function lowerArithmeticDemo(inputs = arithmeticInputs()) {
  const { x, y, z, params, provenance } = inputs;

  const state = { witnesses: [] };

  // ---------------------------------------------------------------- leaf 0
  // y * z. Standard precedence puts the multiplication first, so it is the first
  // leaf. Both operands are encrypted: MUL accepts a ciphertext on both sides,
  // so nothing forces either of them into the clear.
  const productLeaf = emit(state, "MUL", y, z, y * z, "y * z");

  // ---------------------------------------------------------------- leaf 1
  // x + the product, and the released value. Note that the left operand is the
  // previous leaf's result: that is what makes the trace a CHAIN rather than
  // two unrelated facts, and the contract checks that continuity over ciphertext
  // handles, not over integers. Both operands are ciphertexts here too.
  const totalLeaf = emit(
    state,
    "ADD",
    productLeaf.value,
    x,
    productLeaf.value + x,
    "x + (y * z)  =  total, the ONLY value the trace releases"
  );

  // The released value is the final leaf of the unpadded trace, and it is the
  // one leaf a dishonest operator has any reason to lie about: everything else
  // is an intermediate nobody sees. So it is also the leaf this example corrupts.
  const releasedLeafIndex = totalLeaf.index;
  if (releasedLeafIndex !== state.witnesses.length - 1) {
    throw new Error(
      `arithmetic-demo: the released value is emitted at leaf ${releasedLeafIndex}, ` +
        `which is not the final leaf ${state.witnesses.length - 1} of the unpadded trace`
    );
  }

  const unpaddedLeafCount = state.witnesses.length;

  // Padding to the next power of two with ADD 0+0 no-ops, exactly as
  // padWitnessesToPowerOfTwo does: the bisection game halves the interval each
  // round, and halving is only exact when the leaf count is a power of two.
  //
  // With this expression the loop body never runs: two leaves is already a power
  // of two. The code stays because the RULE is part of the protocol, not of this
  // expression -- a three-leaf trace would be padded to four here. See
  // ../../Anatel/anatel-rqual-simplificado/ (28 -> 32) for a trace where it does fire.
  const target = nextPowerOfTwo(unpaddedLeafCount);
  while (state.witnesses.length < target) {
    state.witnesses.push(leaf(state.witnesses.length, "ADD", 0, 0, 0, "padding no-op"));
  }
  const witnesses = state.witnesses;
  if (witnesses.length <= 0 || (witnesses.length & (witnesses.length - 1)) !== 0) {
    throw new Error(
      `arithmetic-demo: produced ${witnesses.length} leaves; leaf count must be a power of two`
    );
  }

  // Whole-trace invariant against the same relation the on-chain leaf verifier
  // enforces. The optimistic path re-executes no leaf, so this is the only place
  // a semantically wrong honest trace is caught off-chain.
  const semantics = assertTraceSemantics(witnesses, "arithmetic-demo");

  // Independent second pass, cheap, and it makes the guarantee local to this file.
  for (const [index, witness] of witnesses.entries()) {
    const verdict = evaluateLeaf(witness.opcode_name, witness.lhs, witness.rhs);
    if (!verdict.valid || Number(verdict.value) !== Number(witness.claimed)) {
      throw new Error(
        `arithmetic-demo: leaf ${index} (${witness.opcode_name}) claims ${witness.claimed} ` +
          `but the micro-ISA yields ${verdict.valid ? verdict.value : `invalid (${verdict.reason})`}`
      );
    }
  }

  // This expression has no division, so integer arithmetic loses NOTHING here:
  // the trace's total is the exact value of x + y*z over the rationals. A trace
  // with a DIV leaf would need to carry what floor division dropped; this one
  // has nothing to drop, and a field that is always zero would suggest the
  // opposite of what it means.

  const model = {
    // The plaintext reference values the example narrates. They are the claimed
    // values of the corresponding leaves, not a parallel computation.
    product: productLeaf.value,
    total: totalLeaf.value,
    // No division, so no truncation: this total is exact over the rationals too.
    // Stated as a field rather than left implicit, because whether integer
    // arithmetic lost anything is the whole point of the integer-arithmetic
    // discussion, and silence would leave it ambiguous.
    integerArithmeticLosesNothingHere: true,
    leafIndex: {
      product: productLeaf.index,
      total: totalLeaf.index
    },
    releasedLeafIndex,
    releasedValue: totalLeaf.value,
    manipulationRationale:
      "`total` is the only value the trace releases, so it is the only value a dishonest operator " +
      "gains anything by faking. The other leaf is an intermediate nobody sees. The example " +
      "therefore corrupts exactly that leaf and lets the dispute game settle it.",
    declaredParameters: { x, y, z },
    expression: params.expression,
    precedence: params.precedence,
    // The four opcodes that WOULD take a cleartext right operand, none of which
    // this trace uses. Kept so the record states the rule and states that this
    // example does not exercise it, rather than staying silent about both.
    publicScalarOpcodes: PUBLIC_SCALAR_RHS_OPCODES,
    publicScalarInThisTrace: null,
    everyOperandEncrypted: true,
    provenance,
    disclaimer: params.disclaimer,
    whyThisShape: params.whyThisShape,
    whatIsNotHere: params.whatIsNotHere,
    parameterNotes: params.notes
  };

  const operationSpec = {
    type: ARITHMETIC_OPERATION_TYPE,
    x,
    y,
    z,
    metadata: {
      demonstrationOnly: true,
      teachingExample: true,
      registeredInOperationRegistry: false,
      partOfEvaluatedWorkloadSet: false,
      expression: params.expression,
      disclaimer: params.disclaimer,
      provenance
    }
  };

  return {
    id: ARITHMETIC_WORKLOAD_ID,
    domain: "arithmetic teaching example",
    title:
      "total = x + y * z over encrypted operands, settled by the dispute game (teaching example)",
    applicability:
      "Shows the whole protocol on the shortest trace it can run: one arithmetic expression is lowered " +
      "to two micro-instructions, executed over TFHE ciphertexts, committed, challenged, disclosed, " +
      "bisected in one round, decided homomorphically at one leaf and settled on chain. Intended for " +
      "understanding the process, and for nothing else.",
    limitation:
      "TEACHING EXAMPLE, and not part of the evaluated workload set. The three values are arbitrary: " +
      "there is no dataset and no measurement behind any of them, so this run says nothing about " +
      "accuracy and nothing about scale. Two leaves are not evidence about the cost of large traces; " +
      "the eleven evaluated workloads and the two ANATEL demonstrations are where that is answered. " +
      "Three parts of the instruction set are deliberately absent, and each costs a lesson: DIV, and " +
      "with it the PUBLIC SCALAR rule, so every operand here is a ciphertext and the rule is never " +
      "exercised; integer TRUNCATION, which this expression cannot show because it has no division; " +
      "and SUB with its underflow guard. ../../Anatel/anatel-rqual-simplificado/ contains all three. Padding is " +
      "likewise never exercised, because two leaves is already a power of two. " +
      `The default manipulated leaf is leaf ${releasedLeafIndex}, the ADD that produces the released total.`,
    defaultManipulatedLeafIndex: releasedLeafIndex,
    model,
    witnesses,
    lowering: {
      engineVersion: ARITHMETIC_ENGINE_VERSION,
      operationType: ARITHMETIC_OPERATION_TYPE,
      operationSpec,
      unpaddedLeafCount,
      paddedLeafCount: witnesses.length,
      microIsaSize: MICRO_ISA_SIZE,
      microIsaVerified: true,
      opcodeHistogram: semantics.opcodeHistogram,
      semantics: {
        integerDomain: "uint64",
        arithmetic: "deterministic unsigned integer arithmetic",
        division: "floor division with nonzero divisor (supported by the micro-ISA; NOT used by this trace)",
        rangeGuards:
          "ADD/MUL overflow, SUB underflow, DIV/MOD by zero, SHR >= 64 bits and ADD_CHAIN length outside 1..8 are rejected",
        unsupported:
          "floating point, approximate CKKS tolerance semantics, stochastic training, and unsupported nonlinear functions"
      },
      warnings: [
        "teaching example: not registered in operationRegistry and not a member of allApplicationWorkloadSpecs()",
        "the three values are arbitrary; nothing here is measured",
        "two leaves say nothing about the cost of large traces",
        "no public scalar, no truncation and no padding are exercised by this trace; see ../../Anatel/anatel-rqual-simplificado/"
      ]
    }
  };
}

/** Convenience: the opcode histogram of a lowered trace, in the shared format. */
export function arithmeticOpcodeCounts(witnesses) {
  return opcodeCounts(witnesses);
}
