/**
 * Regression tests for the micro-ISA reference implementation.
 *
 * Two invariants matter here:
 *
 *   1. The JavaScript opcode table and the Solidity `OPCODE_*` constants of
 *      `contracts/src/FhevmObjectiveMicroVerifier.sol` are identical. This test
 *      parses the contract source rather than trusting a copy, so the drift that
 *      previously left `application-lowering.mjs` with 14 of the 15 opcodes
 *      (ADD_CHAIN missing) is caught mechanically.
 *
 *   2. `evaluateLeaf` reproduces the validity predicate of `_verifyClaim`,
 *      including every range guard the implementation calls "range-safe".
 *
 * Run: node --test scripts/micro-isa.test.mjs
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  OPCODES,
  MICRO_ISA_SIZE,
  MAX_COMPOUND_OPS,
  evaluateLeaf,
  checkWitness,
  assertTraceSemantics
} from "./micro-isa.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const VERIFIER_SOURCE = path.resolve(here, "..", "contracts", "src", "FhevmObjectiveMicroVerifier.sol");
const U64_MAX = (1n << 64n) - 1n;

test("the JS opcode table matches the Solidity constants one-for-one", () => {
  const source = fs.readFileSync(VERIFIER_SOURCE, "utf8");
  const solidity = {};
  const pattern = /uint8\s+public\s+constant\s+OPCODE_([A-Z0-9_]+)\s*=\s*(\d+)\s*;/g;
  for (const match of source.matchAll(pattern)) {
    solidity[match[1]] = Number(match[2]);
  }

  assert.deepEqual(
    solidity,
    OPCODES,
    "scripts/micro-isa.mjs and FhevmObjectiveMicroVerifier.sol declare different opcodes"
  );
  assert.equal(
    MICRO_ISA_SIZE,
    15,
    "the implementation claims a 15-operation micro-ISA; update both the experiment and this test if it changes"
  );

  const maxCompound = /uint64\s+public\s+constant\s+MAX_COMPOUND_OPS\s*=\s*(\d+)\s*;/.exec(source);
  assert.ok(maxCompound, "MAX_COMPOUND_OPS not found in the verifier source");
  assert.equal(BigInt(maxCompound[1]), MAX_COMPOUND_OPS);
});

test("arithmetic opcodes reproduce the contract's expected values", () => {
  const cases = [
    ["MUL", 6n, 7n, 42n],
    ["SHR", 1024n, 3n, 128n],
    ["CAST_U8", 0x1234n, 0n, 0x34n],
    ["MIN", 9n, 4n, 4n],
    ["BITAND", 0b1100n, 0b1010n, 0b1000n],
    ["ADD", 20n, 22n, 42n],
    ["SUB", 50n, 8n, 42n],
    ["DIV", 15n, 4n, 3n],
    ["MOD", 15n, 4n, 3n],
    ["EQ", 5n, 5n, 1n],
    ["EQ", 5n, 6n, 0n],
    ["LT", 4n, 5n, 1n],
    ["GT", 5n, 4n, 1n],
    ["BITOR", 0b1100n, 0b1010n, 0b1110n],
    ["BITXOR", 0b1100n, 0b1010n, 0b0110n],
    ["ADD_CHAIN", 10n, 8n, 18n]
  ];
  for (const [op, lhs, rhs, expected] of cases) {
    const result = evaluateLeaf(op, lhs, rhs);
    assert.equal(result.valid, true, `${op} unexpectedly invalid: ${result.reason}`);
    assert.equal(result.value, expected, `${op}(${lhs}, ${rhs})`);
  }
});

test("every range guard of the implementation is enforced", () => {
  const invalid = [
    ["ADD", U64_MAX, 1n, "ADD overflow"],
    ["ADD_CHAIN", U64_MAX, 1n, "ADD_CHAIN overflow"],
    ["MUL", 1n << 63n, 3n, "MUL overflow"],
    ["SUB", 3n, 4n, "SUB underflow"],
    ["DIV", 10n, 0n, "DIV by zero"],
    ["MOD", 10n, 0n, "MOD by zero"],
    ["SHR", 1n, 64n, "SHR shift >= 64"],
    ["SHR", 1n, 255n, "SHR shift >= 64"],
    ["ADD_CHAIN", 1n, 0n, "chain length 0"],
    ["ADD_CHAIN", 1n, MAX_COMPOUND_OPS + 1n, "chain length above the bound"],
    ["ADD", U64_MAX + 1n, 0n, "lhs outside uint64"],
    ["ADD", 0n, U64_MAX + 1n, "rhs outside uint64"]
  ];
  for (const [op, lhs, rhs, why] of invalid) {
    const result = evaluateLeaf(op, lhs, rhs);
    assert.equal(result.valid, false, `${op}(${lhs}, ${rhs}) should be invalid: ${why}`);
  }
});

test("boundary values that must stay valid are not over-rejected", () => {
  assert.equal(evaluateLeaf("ADD", U64_MAX - 1n, 1n).value, U64_MAX);
  assert.equal(evaluateLeaf("SUB", 5n, 5n).value, 0n);
  assert.equal(evaluateLeaf("SHR", U64_MAX, 63n).value, 1n);
  assert.equal(evaluateLeaf("MUL", U64_MAX, 1n).value, U64_MAX);
  assert.equal(evaluateLeaf("MUL", 0n, U64_MAX).value, 0n);
  assert.equal(evaluateLeaf("ADD_CHAIN", 0n, MAX_COMPOUND_OPS).value, MAX_COMPOUND_OPS);
});

test("checkWitness rejects a claimed value the verifier would reject", () => {
  const honest = { opcode: OPCODES.ADD, lhs: 2, rhs: 3, claimed: 5 };
  assert.equal(checkWitness(honest).ok, true);

  const corrupted = { ...honest, claimed: 6 };
  const verdict = checkWitness(corrupted);
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /claimed 6 but the ISA yields 5/);
});

test("assertTraceSemantics validates ordering, opcodes and arithmetic", () => {
  const trace = [
    { leaf_index: 0, opcode: OPCODES.ADD, opcode_name: "ADD", lhs: 1, rhs: 2, claimed: 3 },
    { leaf_index: 1, opcode: OPCODES.MUL, opcode_name: "MUL", lhs: 3, rhs: 4, claimed: 12 }
  ];
  const summary = assertTraceSemantics(trace, "unit");
  assert.equal(summary.leafCount, 2);
  assert.deepEqual(summary.opcodeHistogram, { ADD: 1, MUL: 1 });

  assert.throws(
    () => assertTraceSemantics([{ ...trace[0], claimed: 4 }], "unit"),
    /violates the micro-ISA relation/
  );
  assert.throws(
    () => assertTraceSemantics([{ ...trace[0], leaf_index: 7 }], "unit"),
    /declares leaf_index 7/
  );
  assert.throws(
    () => assertTraceSemantics([{ ...trace[0], opcode: 99, opcode_name: "NOPE" }], "unit"),
    /outside the 15-operation micro-ISA/
  );
});
