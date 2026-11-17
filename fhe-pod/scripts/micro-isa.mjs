/**
 * Single source of truth for the adjudicated FHE micro-ISA.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The implementation states that the non-linear path adjudicates a fixed set of
 * *15* deterministic, range-safe, unsigned 64-bit micro-operations, and that
 * applications are lowered into traces over exactly that set. Before this
 * module the ISA was declared in three places that could (and did) drift:
 *
 *   1. `contracts/src/FhevmObjectiveMicroVerifier.sol`  -> 15 opcodes (authority)
 *   2. `scripts/application-lowering.mjs`               -> 14 opcodes (ADD_CHAIN missing)
 *   3. `scripts/run-verification-cost-evaluation.mjs`   -> a private 6-opcode map
 *
 * Consequence of (2): no application could ever be lowered to ADD_CHAIN, so the
 * "15-operation micro-ISA" claim held for the *adjudicable* surface but not for
 * the *compilable* one. Consequence of (3): the cost harness could emit an
 * opcode number the lowering engine rejected, with nothing to catch it.
 *
 * Everything now imports from here. `OPCODES` mirrors the Solidity constants
 * one-for-one, and `evaluateLeaf` mirrors the validity predicate of
 * `FhevmObjectiveMicroVerifier._verifyClaim`, including every range guard:
 *
 * On chain that predicate is evaluated HOMOMORPHICALLY over ciphertext handles
 * (no operand is ever opened), and the guards below are enforced there as
 * encrypted predicates ANDed into the validity bit -- except for the guards on
 * the PUBLIC control scalar of SHR/DIV/MOD/ADD_CHAIN, which stay clear because
 * that operand is public by construction (see PUBLIC_SCALAR_RHS_OPCODES). This
 * file is the clear-value reference of the SAME relation, used off-chain so a
 * lowering bug is caught before a trace is committed:
 *
 *   - operands and claimed value must fit in uint64
 *   - ADD / ADD_CHAIN overflow      -> invalid
 *   - MUL overflow                  -> invalid
 *   - SUB underflow                 -> invalid
 *   - DIV / MOD by zero             -> invalid
 *   - SHR by 64 or more bits        -> invalid
 *   - ADD_CHAIN length outside 1..8 -> invalid
 *
 * This gives the evaluation harness an *independent* reference implementation of
 * the relation the contract enforces, so a lowering bug is caught off-chain
 * instead of silently finalising as an "accepted" optimistic task (recall that
 * the optimistic path verifies no leaf at all: only a challenged leaf is
 * re-executed by the selected backend, so a semantically wrong honest trace would otherwise be
 * indistinguishable from a correct one in the evaluation).
 *
 * Keep in sync with: contracts/src/FhevmObjectiveMicroVerifier.sol
 */

/** Opcode numbers, byte-identical to the Solidity `OPCODE_*` constants. */
export const OPCODES = Object.freeze({
  MUL: 1,
  SHR: 2,
  CAST_U8: 3,
  MIN: 4,
  BITAND: 5,
  ADD: 6,
  SUB: 7,
  DIV: 8,
  MOD: 9,
  EQ: 10,
  LT: 11,
  GT: 12,
  BITOR: 13,
  BITXOR: 14,
  ADD_CHAIN: 15
});

/** Reverse map, opcode number -> name. */
export const OPCODE_NAMES = Object.freeze(
  Object.fromEntries(Object.entries(OPCODES).map(([name, code]) => [code, name]))
);

export const SUPPORTED_OPCODE_NAMES = Object.freeze(Object.keys(OPCODES));

/** `MAX_COMPOUND_OPS` in FhevmObjectiveMicroVerifier.sol. */
export const MAX_COMPOUND_OPS = 8n;

/**
 * Opcodes whose second operand is a PUBLIC scalar, not user data. This is the
 * single declaration of the rule; every other component must agree with it.
 *
 * The local executor and adjudicator import one checked Rust relation with
 * these four public controls. ADD_CHAIN means repeated public +1, not an
 * array sum. Unsupported general-evaluator opcodes are rejected.
 */
export const PUBLIC_SCALAR_RHS_OPCODES = Object.freeze(["SHR", "DIV", "MOD", "ADD_CHAIN"]);

const U64_MAX = (1n << 64n) - 1n;

/** Size of the ISA, asserted by the test suite against the Solidity contract. */
export const MICRO_ISA_SIZE = SUPPORTED_OPCODE_NAMES.length;

function toBig(value, label) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new TypeError(`${label} must be an integer; received ${value}`);
    return BigInt(value);
  }
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  throw new TypeError(`${label} must be an integer or integer string; received ${String(value)}`);
}

/**
 * Reference implementation of `FhevmObjectiveMicroVerifier._verifyClaim`.
 *
 * @param {number|string} opcode  opcode number (1..15) or opcode name
 * @param {bigint|number} lhs     left operand, unsigned 64-bit
 * @param {bigint|number} rhs     right operand (public scalar for SHR/DIV/MOD/ADD_CHAIN)
 * @returns {{valid: boolean, value: bigint|null, reason: string|null}}
 *   `valid:false` means the contract's validity bit would be 0 for *any* claimed
 *   value; `value` is the unique claimed value the contract accepts otherwise.
 */
export function evaluateLeaf(opcode, lhs, rhs) {
  const code = typeof opcode === "string" ? OPCODES[opcode] : Number(opcode);
  const name = OPCODE_NAMES[code];
  if (!name) return { valid: false, value: null, reason: `unsupported opcode ${String(opcode)}` };

  const a = toBig(lhs, `${name}.lhs`);
  const b = toBig(rhs, `${name}.rhs`);

  // `_verifyClaim` returns FHE.asEbool(false) when any operand exceeds uint64.
  if (a < 0n || a > U64_MAX) return { valid: false, value: null, reason: "lhs out of uint64 range" };
  if (b < 0n || b > U64_MAX) return { valid: false, value: null, reason: "rhs out of uint64 range" };

  switch (name) {
    case "MUL":
      if (b !== 0n && a > U64_MAX / b) return { valid: false, value: null, reason: "MUL overflow" };
      return { valid: true, value: a * b, reason: null };
    case "SHR":
      if (b >= 64n) return { valid: false, value: null, reason: "SHR shift >= 64" };
      return { valid: true, value: a >> b, reason: null };
    case "CAST_U8":
      return { valid: true, value: a & 0xffn, reason: null };
    case "MIN":
      return { valid: true, value: a < b ? a : b, reason: null };
    case "BITAND":
      return { valid: true, value: a & b, reason: null };
    case "ADD":
      if (a > U64_MAX - b) return { valid: false, value: null, reason: "ADD overflow" };
      return { valid: true, value: a + b, reason: null };
    case "SUB":
      if (a < b) return { valid: false, value: null, reason: "SUB underflow" };
      return { valid: true, value: a - b, reason: null };
    case "DIV":
      if (b === 0n) return { valid: false, value: null, reason: "DIV by zero" };
      return { valid: true, value: a / b, reason: null };
    case "MOD":
      if (b === 0n) return { valid: false, value: null, reason: "MOD by zero" };
      return { valid: true, value: a % b, reason: null };
    case "EQ":
      return { valid: true, value: a === b ? 1n : 0n, reason: null };
    case "LT":
      return { valid: true, value: a < b ? 1n : 0n, reason: null };
    case "GT":
      return { valid: true, value: a > b ? 1n : 0n, reason: null };
    case "BITOR":
      return { valid: true, value: a | b, reason: null };
    case "BITXOR":
      return { valid: true, value: a ^ b, reason: null };
    case "ADD_CHAIN":
      // The contract runs `rhs` encrypted +1 steps, so the chain length is the
      // rhs operand and the result is lhs + rhs.
      if (b === 0n || b > MAX_COMPOUND_OPS) {
        return { valid: false, value: null, reason: `ADD_CHAIN length outside 1..${MAX_COMPOUND_OPS}` };
      }
      if (a > U64_MAX - b) return { valid: false, value: null, reason: "ADD_CHAIN overflow" };
      return { valid: true, value: a + b, reason: null };
    default:
      return { valid: false, value: null, reason: `unhandled opcode ${name}` };
  }
}

/**
 * Checks one lowered witness `{opcode, lhs, rhs, claimed}` against the ISA.
 * @returns {{ok: boolean, expected: bigint|null, reason: string|null}}
 */
export function checkWitness(witness) {
  const opcode = witness.opcode ?? witness.opcode_name;
  const { valid, value, reason } = evaluateLeaf(opcode, witness.lhs, witness.rhs);
  if (!valid) return { ok: false, expected: null, reason };
  const claimed = toBig(witness.claimed, "claimed");
  if (claimed !== value) {
    return { ok: false, expected: value, reason: `claimed ${claimed} but the ISA yields ${value}` };
  }
  return { ok: true, expected: value, reason: null };
}

/**
 * Asserts that an entire honest micro-trace satisfies the adjudicated relation
 * at every leaf. Throws on the first violation with a precise location.
 *
 * Call this on every trace an evaluation commits as *honest*: the optimistic
 * path re-executes no leaf, so this is the only place a lowering bug is caught.
 *
 * @param {Array<object>} witnesses lowered leaves, in trace order
 * @param {string} label            identifier used in the error message
 * @returns {{leafCount: number, opcodeHistogram: Record<string, number>}}
 */
export function assertTraceSemantics(witnesses, label = "trace") {
  if (!Array.isArray(witnesses) || witnesses.length === 0) {
    throw new Error(`${label}: expected a non-empty witness array`);
  }
  const histogram = {};
  for (const [index, witness] of witnesses.entries()) {
    const name = witness.opcode_name ?? OPCODE_NAMES[witness.opcode];
    if (!name || OPCODES[name] === undefined) {
      throw new Error(`${label}: leaf ${index} carries opcode outside the ${MICRO_ISA_SIZE}-operation micro-ISA`);
    }
    if (witness.opcode !== undefined && witness.opcode !== OPCODES[name]) {
      throw new Error(
        `${label}: leaf ${index} opcode number ${witness.opcode} disagrees with name ${name} (${OPCODES[name]})`
      );
    }
    if (witness.leaf_index !== undefined && witness.leaf_index !== index) {
      throw new Error(`${label}: leaf ${index} declares leaf_index ${witness.leaf_index}`);
    }
    const { ok, reason } = checkWitness({ ...witness, opcode: OPCODES[name] });
    if (!ok) throw new Error(`${label}: leaf ${index} (${name}) violates the micro-ISA relation: ${reason}`);
    histogram[name] = (histogram[name] ?? 0) + 1;
  }
  return { leafCount: witnesses.length, opcodeHistogram: histogram };
}

/**
 * Corrupts one leaf so that the on-chain verifier must reject the operator's
 * claim. Used by the adversarial half of every evaluation run: the corrupted
 * value must stay inside uint64 (otherwise the leaf is rejected for the wrong
 * reason, i.e. by the range guard rather than by the arithmetic relation).
 *
 * @returns {object} a copy of `witness` with a wrong but in-range `claimed`
 */
export function corruptWitness(witness) {
  const name = witness.opcode_name ?? OPCODE_NAMES[witness.opcode];
  const { valid, value } = evaluateLeaf(OPCODES[name], witness.lhs, witness.rhs);
  if (!valid) throw new Error(`cannot corrupt a leaf that is already invalid (${name})`);
  const corrupted = value === U64_MAX ? value - 1n : value + 1n;
  return { ...witness, claimed: Number(corrupted) };
}
