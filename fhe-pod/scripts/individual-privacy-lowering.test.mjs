// Historical clear-witness fixture, not the current handle-only disclosure ABI.
// These tests identify private source values that must stay out of calldata;
// they do not show that the active protocol publishes those values.
import test from "node:test";
import assert from "node:assert/strict";
import { lowerWorkloadSpec } from "./application-lowering.mjs";
import { stav360WorkloadSpecs } from "./stav360-fixtures.mjs";

test("historical clear witness: early leaves contain individual ratings", () => {
  const spec = stav360WorkloadSpecs().find((s) => s.id === "stav360_mos_variance");
  assert.ok(spec, "stav360_mos_variance spec must exist");
  const ratings = spec.operation.values; // e.g. [3, 4, 4, 4]
  const lowered = lowerWorkloadSpec(spec);
  const witnesses = lowered.witnesses;

  // Leaf 0 of the sum tree is ADD(rating0, rating1).
  const leaf0 = witnesses.find((w) => w.leaf_index === 0);
  assert.equal(leaf0.opcode_name, "ADD");
  assert.equal(leaf0.lhs, ratings[0], "leaf 0 lhs is user 0's raw rating");
  assert.equal(leaf0.rhs, ratings[1], "leaf 0 rhs is user 1's raw rating");

  // Publishing this owner-side witness would reveal raw ratings. The current
  // dispute ABI instead publishes handles; its enforcement is tested separately.
  const revealedByLeaf0 = new Set([leaf0.lhs, leaf0.rhs]);
  assert.ok(
    revealedByLeaf0.has(ratings[0]) && revealedByLeaf0.has(ratings[1]),
    "publishing the clear witness would disclose individual user data"
  );

  // The MUL leaves (rating_i^2) each disclose one raw rating twice.
  const squareLeaf = witnesses.find(
    (w) => w.opcode_name === "MUL" && w.lhs === w.rhs && ratings.includes(w.lhs)
  );
  assert.ok(squareLeaf, "a rating^2 leaf discloses an individual rating");

  // Contrast: the DIV (mean) and SUB (variance) leaves operate on AGGREGATES
  // (sum, sum-of-squares), which do not by themselves reveal an individual.
  const meanLeaf = witnesses.find((w) => w.opcode_name === "DIV" && w.note.includes("mean"));
  assert.ok(meanLeaf, "mean leaf exists");
  assert.ok(!ratings.includes(meanLeaf.lhs) || meanLeaf.lhs === ratings.reduce((a, b) => a + b, 0),
    "the mean's dividend is the aggregate sum, not an individual rating");
});
