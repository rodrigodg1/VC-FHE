import test from "node:test";
import assert from "node:assert/strict";
import { lowerWorkloadSpec } from "./application-lowering.mjs";
import { buildAuthenticatedTracePlan } from "./evm-lib.mjs";
import { explicitTraceReferences } from "./trace-references.mjs";

const task = "0x" + "12".repeat(32), owner = "0x" + "34".repeat(20);
const lower = (valuesMilli, cells = null, targetPermille = 750) => lowerWorkloadSpec({
  id: "regression", operation: { type: cells ? "regional_compliance_monitor" : "regulatory_compliance_monitor",
    valuesMilli, cells, targetCell: 7, poorThresholdMilli: 2000, targetPermille }
});

test("active lowering preserves semantics and public wiring over 272 distinct assignments", () => {
  for (const regional of [false, true]) {
    let root;
    for (let mask = 0; mask < (regional ? 256 : 16); mask++) {
      const values = Array.from({ length: 4 }, (_, i) => mask & (1 << i) ? 3000 : 1000);
      const cells = regional ? Array.from({ length: 4 }, (_, i) => mask & (16 << i) ? 7 : 8) : null;
      const selected = values.filter((_, i) => !regional || cells[i] === 7);
      const expected = selected.length > 0 && selected.filter(v => v > 2000).length * 1000 >= selected.length * 750 ? 1 : 0;
      const lowered = lower(values, cells);
      assert.equal(lowered.witnesses.at(-1).claimed, expected);
      assert.equal(lowered.model.compliant, expected);
      const plan = buildAuthenticatedTracePlan(task, lowered.witnesses, owner);
      root ??= plan.programTree.root;
      assert.equal(plan.programTree.root, root);
      assert.equal(plan.inputRecords.length, regional ? 8 : 4);
    }
  }
});

test("equal-valued records remain distinct; sum nodes refer to both intended outputs", () => {
  const lowered = lower(Array(16).fill(3000));
  const plan = buildAuthenticatedTracePlan(task, lowered.witnesses, owner);
  assert.equal(plan.provenanceLeaves[16].lhsSourceIndex, 0);
  assert.equal(plan.provenanceLeaves[16].rhsSourceIndex, 1);
  assert.equal(plan.provenanceLeaves[0].rhsSourceKind, 2);
  assert.equal(plan.provenanceLeaves[31].rhsSourceKind, 2);
  assert.equal(lowered.witnesses.at(-1).claimed, 1);
});

test("malformed references fail and public program changes alter its root", () => {
  const lowered = lower([3000, 3000, 3000]);
  const plan = buildAuthenticatedTracePlan(task, lowered.witnesses, owner);
  for (const mutate of [
    w => { delete w[0].lhsRef; },
    w => { w[0].lhsRef = { kind: "output", index: 0 }; },
    w => { w[0].rhsRef.value = "1999"; },
    w => { w[0].lhsRef.index = 19; }
  ]) {
    const copy = structuredClone(lowered.witnesses); mutate(copy);
    assert.throws(() => explicitTraceReferences(copy));
  }
  const changed = lower([3000, 3000, 3000], null, 900);
  assert.notEqual(buildAuthenticatedTracePlan(task, changed.witnesses, owner).programTree.root, plan.programTree.root);
});
