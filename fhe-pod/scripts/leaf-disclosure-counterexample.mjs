#!/usr/bin/env node
// A successful run reproduces a privacy counterexample; it is NOT a security pass.
// The attacker observes one checked leaf bit, never the client key or witness.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { lowerWorkloadSpec } from "./application-lowering.mjs";
import { ensureFheExecutor, decideLeaf } from "./leaf-decision.mjs";

const pod = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tops-leaf-disclosure-"));
const worlds = [[1000, 3000], [3000, 1000]].map((valuesMilli, bit) =>
  lowerWorkloadSpec({ id: `world-${bit}`, operation: {
    type: "regulatory_compliance_monitor", valuesMilli,
    poorThresholdMilli: 2000, targetPermille: 950
  } }));
// Public input identities, selection, program, dimensions and authorized output
// coincide. The encrypted records differ; IND-CPA is meant to hide this choice.
assert.deepEqual(worlds[0].program, worlds[1].program);
assert.equal(worlds[0].model.compliant, 0);
assert.equal(worlds[1].model.compliant, 0);
assert.equal(worlds[0].witnesses[0].opcode_name, "GT");
assert.equal(worlds[0].witnesses[0].rhs, 2000);
assert.equal(worlds[1].witnesses[0].rhs, 2000);
const traces = { workloads: worlds.map(w => ({ workloadId: w.id,
  circuitVersion: w.program.version, leaves: w.witnesses.map((l, index) => ({
    index, opcode: l.opcode_name, lhs: String(l.lhs), rhs: String(l.rhs),
    claimed: String(l.claimed), lhsRef: l.lhsRef, rhsRef: l.rhsRef
  })) })) };
const tracesPath = path.join(directory, "traces.json");
const manifestPath = path.join(directory, "ciphertext-manifest.json");
const ciphertextDir = path.join(directory, "ciphertexts");
fs.writeFileSync(tracesPath, JSON.stringify(traces));
const run = spawnSync(ensureFheExecutor(), ["--traces", tracesPath,
  "--out", manifestPath, "--ciphertext-dir", ciphertextDir], {
  cwd: pod, stdio: "inherit", timeout: 3600000
});
assert.equal(run.status, 0, `fixture preparation failed: ${run.error ?? run.status}`);
const manifest = JSON.parse(fs.readFileSync(manifestPath));

// This function is the entire attacker's inference; neither records nor keys
// are arguments. It uses only the oracle answer and the public two-world game.
function distinguish(publicValidityBit) { return publicValidityBit ? 0 : 1; }
const observations = [];
for (const [world, w] of worlds.entries()) {
  const entry = manifest.workloads.find(e => e.workloadId === w.id);
  assert.ok(entry.leaves.every(l => l.ok));
  const terminal = entry.leaves.at(-1);
  assert.equal(Number(terminal.decrypted), 0);
  // Reuse the authorized output ciphertext, known to encode zero in BOTH
  // worlds. No attacker encryption, new predicate/threshold, or key is needed.
  // The adjudicator receives the genuine input and the exact claimed handle.
  const answer = decideLeaf({ ciphertextDir, manifest, referenceKey: w.id,
    leafIndex: 0, claims: [{ label: "chosen-zero",
      ciphertextPath: path.join(ciphertextDir, w.id, `result-${terminal.index}.ct`),
      expectedHandle: terminal.resultHandle }] });
  const publicValidityBit = answer.byLabel["chosen-zero"];
  assert.equal(distinguish(publicValidityBit), world);
  observations.push({ world, authorizedOutput: 0, publicValidityBit,
    recoveredWorld: distinguish(publicValidityBit), releasedBits: 1 });
}
const report = {
  classification: "reproduced-privacy-counterexample-not-security-pass",
  reproduced: true, directory, programVersion: worlds[0].program.version,
  checkedFheLeaves: manifest.workloads.reduce((n, w) => n + w.leaves.length, 0),
  observations,
  scope: "active local checked-value adjudicator; synthetic owner fixtures; no end-to-end chain admission or threshold MPC experiment",
  implication: "one admitted chosen-result validity opening can disclose information absent from the authorized aggregate; Boolean type, fixed program, handle binding and a one-bit budget do not suffice",
  excludedClaims: ["full-record reconstruction", "key recovery", "universal impossibility of private verifiable FHE"]
};
const output = process.env.VCFHE_DISCLOSURE_REPORT ?? path.join(directory, "report.json");
fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));
