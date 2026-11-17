#!/usr/bin/env node
// Isolated correctness regression, never a replacement for experiment cost artifacts.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { lowerWorkloadSpec, allApplicationWorkloadSpecs } from "./application-lowering.mjs";
import { buildAuthenticatedTracePlan } from "./evm-lib.mjs";
import { ensureFheExecutor, decideLeaf, replayWithDecisions } from "./leaf-decision.mjs";

const pod = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dir = process.env.VCFHE_DATAFLOW_DIR ?? fs.mkdtempSync(path.join(os.tmpdir(), "tops-dataflow-"));
fs.mkdirSync(dir, { recursive: true });
const canonical = allApplicationWorkloadSpecs().filter(s => ["regulatory_qoe_compliance", "regional_qoe_compliance"].includes(s.id));
const synthetic = [
  { id: "positive-global", type: "regulatory_compliance_monitor" },
  { id: "positive-region", type: "regional_compliance_monitor", cells: [7, 7, 7] },
  { id: "empty-region", type: "regional_compliance_monitor", cells: [8, 8, 8] }
].map(s => ({ id: s.id, operation: { ...s, valuesMilli: [3000, 3000, 3000], targetCell: 7,
  poorThresholdMilli: 2000, targetPermille: 950 } }));
const lowered = [...canonical, ...synthetic].map(lowerWorkloadSpec);
const traces = { workloads: lowered.map(w => ({ workloadId: w.id, circuitVersion: w.program.version,
  leaves: w.witnesses.map((l, index) => ({ index, opcode: l.opcode_name, lhs: String(l.lhs),
    rhs: String(l.rhs), claimed: String(l.claimed), lhsRef: l.lhsRef, rhsRef: l.rhsRef })) })) };
const tracesPath = path.join(dir, "traces.json"), manifestPath = path.join(dir, "ciphertext-manifest.json");
const ciphertextDir = path.join(dir, "ciphertexts");
const verifyExisting = process.argv.includes("--verify-existing");
if (verifyExisting) assert.equal(fs.readFileSync(tracesPath, "utf8"), JSON.stringify(traces), "existing fixture uses another circuit or input set");
else fs.writeFileSync(tracesPath, JSON.stringify(traces));
console.log(`Explicit dataflow regression: ${dir}`);
const executor = ensureFheExecutor();
if (!verifyExisting) {
  const run = spawnSync(executor, ["--traces", tracesPath, "--out", manifestPath, "--ciphertext-dir", ciphertextDir],
    { cwd: pod, stdio: "inherit", timeout: 3600000 });
  assert.equal(run.status, 0, `encrypted executor failed: ${run.error ?? run.status}`);
}
const manifest = JSON.parse(fs.readFileSync(manifestPath));
process.env.VCFHE_CIPHERTEXT_MANIFEST = manifestPath;
const { fheHandlesForWorkload, assertHandlesMatchTrace } = await import("./fhe-handles.mjs?integration");
const task = "0x" + "12".repeat(32), owner = "0x" + "34".repeat(20);
let checked = 0;
const results = [];
for (const w of lowered) {
  const entry = manifest.workloads.find(e => e.workloadId === w.id);
  assert.ok(entry.leaves.every(l => l.ok));
  assert.equal(Number(entry.leaves.at(-1).decrypted), w.model.compliant);
  checked += entry.leaves.length;
  const handles = fheHandlesForWorkload(w.id, w.witnesses.length);
  assertHandlesMatchTrace(handles, w.witnesses, w.id);
  assert.throws(() => assertHandlesMatchTrace({ ...handles, circuitVersion: null }, w.witnesses, "old manifest"));
  const changedInput = structuredClone(w.witnesses);
  const index = changedInput.findIndex(l => l.lhsRef.kind === "input");
  changedInput[index].lhs += 1;
  assert.throws(() => assertHandlesMatchTrace(handles, changedInput, "changed dataset"), /stale owner input/);
  const plan = buildAuthenticatedTracePlan(task, w.witnesses, owner, w.witnesses, handles);
  for (const [i, l] of w.witnesses.entries()) {
    for (const side of ["lhs", "rhs"]) {
      const ref = l[`${side}Ref`], actual = plan.provenanceLeaves[i];
      assert.equal(actual[`${side}Handle`], entry.leaves[i][`${side}Handle`]);
      if (ref.kind === "output") assert.equal(actual[`${side}SourceIndex`], ref.index);
    }
  }
  results.push({ workload: w.id, leaves: entry.leaves.length, output: w.model.compliant,
    inputRecords: plan.inputRecords.length, programRoot: plan.programTree.root });
}
// Nonadjacent outputs, two public operands, and padded result reuse.
const decisions = [];
for (const [key, index] of [["regulatory_qoe_compliance", 33], ["regulatory_qoe_compliance", 32],
  ["regional_qoe_compliance", 80], ["positive-global", 15]]) {
  const entry = manifest.workloads.find(w => w.workloadId === key), leaf = entry.leaves[index];
  const wrong = entry.leaves.find(l => l.decrypted !== leaf.decrypted);
  assert.ok(wrong);
  const claims = [["honest", leaf], ["wrong", wrong]].map(([label, l]) => ({ label,
    ciphertextPath: path.join(ciphertextDir, key, `result-${l.index}.ct`), expectedHandle: l.resultHandle }));
  const verdict = decideLeaf({ ciphertextDir, manifest, referenceKey: key, leafIndex: index, claims });
  assert.deepEqual(verdict.byLabel, { honest: true, wrong: false });
  assert.throws(() => decideLeaf({ ciphertextDir, manifest, referenceKey: key, leafIndex: index,
    claims: [{ ...claims[0], expectedHandle: "0x" + "00".repeat(32) }] }), /no decision released/);
  decisions.push({ key, index, byLabel: verdict.byLabel });
}
const replay = replayWithDecisions({ ciphertextDir, tracesPath, workloadId: "positive-global" });
assert.ok(replay.leaves.every(l => l.decisionBit === true));
const report = { classification: "correctness-regression-not-experiment-performance", passed: true,
  directory: dir, checkedLeaves: checked, results, decisions, independentReplayLeaves: replay.leaves.length,
  independentReplayByteMatches: replay.leaves.filter(l => l.resultHandle === l.committedResultHandle).length,
  scope: "explicit canonical compilation and local checked leaf decisions; no unknown-fault detector or distributed KMS bridge" };
fs.writeFileSync(path.join(dir, "summary.json"), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));
