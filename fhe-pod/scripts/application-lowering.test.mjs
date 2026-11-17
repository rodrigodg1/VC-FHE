import test from "node:test";
import assert from "node:assert/strict";
import {
  allApplicationWorkloadSpecs,
  defaultApplicationWorkloads,
  lowerWorkloadSpec,
  opcodeCounts
} from "./application-lowering.mjs";
import { qoeMosModel, qoeMosWorkloadSpecs } from "./qoe-mos-fixtures.mjs";
import { qoeTreeModel, qoeTreeWorkloadSpecs } from "./qoe-tree-fixtures.mjs";
import { regulatoryPanel, regulatoryWorkloadSpecs } from "./regulatory-fixtures.mjs";
import { stav360Panel, stav360WorkloadSpecs } from "./stav360-fixtures.mjs";
import { loadWebrtcFixtures, webrtcPanel, webrtcWorkloadSpecs } from "./webrtc-fixtures.mjs";


test("STAV360 QoE panels lower to literature-backed models", () => {
  const workloads = defaultApplicationWorkloads();
  const byId = Object.fromEntries(workloads.map((w) => [w.id, w]));
  const p4 = stav360Panel("mos_variance_4");
  const p8 = stav360Panel("mos_variance_8");
  const sla = stav360Panel("poor_rating_sla_8");

  assert.equal(byId.stav360_mos_variance.model.mean, p4.mean);
  assert.equal(byId.stav360_mos_variance.model.variance, p4.variance);
  assert.equal(byId.stav360_mos_variance.lowering.unpaddedLeafCount, 17);
  assert.deepEqual(byId.stav360_mos_variance.witnesses[11], {
    leaf_index: 11,
    opcode: 8,
    opcode_name: "DIV",
    lhs: 57,
    rhs: 4,
    claimed: 14,
    note: "E[x^2]"
  });

  assert.equal(byId.stav360_checkerboard_variance.model.mean, p8.mean);
  assert.equal(byId.stav360_checkerboard_variance.model.variance, p8.variance);
  assert.equal(byId.stav360_checkerboard_variance.lowering.unpaddedLeafCount, 29);
  assert.equal(byId.stav360_checkerboard_variance.witnesses.length, 32);

  assert.equal(byId.stav360_poor_rating_sla.model.poorCount, sla.poorCount);
  assert.equal(byId.stav360_poor_rating_sla.model.slaBreached, 1);
  assert.equal(byId.stav360_poor_rating_sla.lowering.unpaddedLeafCount, 16);
  assert.deepEqual(opcodeCounts(byId.stav360_poor_rating_sla.witnesses), {
    LT: 8,
    ADD: 7,
    GT: 1
  });
});

test("drive-test QoE MOS classifier lowers to a deterministic alarm trace", () => {
  const workloads = defaultApplicationWorkloads();
  const byId = Object.fromEntries(workloads.map((w) => [w.id, w]));
  const fixture = qoeMosModel("bs1_3000kbps_poor_alarm");
  const workload = byId.qoe_mos_degradation_alarm;

  assert.equal(workload.model.throughputKbps, fixture.selectedRow.throughputKbps);
  assert.equal(workload.model.bitrateKbps, fixture.bitrateKbps);
  assert.equal(workload.model.headroomPercent, fixture.headroomPercent);
  assert.equal(workload.model.capacityScore, 192800);
  assert.equal(workload.model.requiredScore, 216000);
  assert.equal(workload.model.predictedPoor, 1);
  assert.equal(workload.model.alarm, 1);
  assert.equal(workload.model.observedPoor, 1);
  assert.equal(workload.lowering.unpaddedLeafCount, 4);
  assert.equal(workload.witnesses.length, 4);
  assert.deepEqual(workload.witnesses[2], {
    leaf_index: 2,
    opcode: 11,
    opcode_name: "LT",
    lhs: 192800,
    rhs: 216000,
    claimed: 1,
    note: "MOS degradation predicate"
  });
  assert.deepEqual(opcodeCounts(workload.witnesses), {
    BITAND: 1,
    LT: 1,
    MUL: 2
  });
});

test("drive-test decision-tree QoE classifier lowers to an oblivious inference trace", () => {
  const workloads = defaultApplicationWorkloads();
  const byId = Object.fromEntries(workloads.map((w) => [w.id, w]));
  const fixture = qoeTreeModel("bs_crossstation_poor_tree");
  const workload = byId.qoe_tree_mos_classifier;

  assert.equal(workload.model.throughputKbps, fixture.selectedSample.throughputKbps);
  assert.equal(workload.model.bitrateKbps, fixture.selectedSample.bitrateKbps);
  assert.equal(workload.model.rootBitrateThresholdKbps, fixture.rootBitrateThresholdKbps);
  assert.equal(workload.model.lowTputThresholdKbps, fixture.lowTputThresholdKbps);
  assert.equal(workload.model.highTputThresholdKbps, fixture.highTputThresholdKbps);

  // Selected sample: bitrate above the root split, throughput below the
  // high-branch threshold, so the tree predicts poor QoE on the high branch.
  assert.equal(workload.model.branch, "high");
  assert.equal(workload.model.predictedPoor, 1);
  assert.equal(workload.model.alarm, 1);
  assert.equal(workload.model.observedPoor, 1);

  // 8 leaves, no padding: oblivious evaluation of both branches.
  assert.equal(workload.lowering.unpaddedLeafCount, 8);
  assert.equal(workload.witnesses.length, 8);
  assert.deepEqual(opcodeCounts(workload.witnesses), {
    BITAND: 3,
    BITOR: 1,
    BITXOR: 1,
    GT: 1,
    LT: 2
  });

  // The default manipulated leaf is the tree prediction bit: flipping it is
  // exactly how a malicious operator hides a poor-QoE session.
  const manipulated = workload.witnesses[workload.defaultManipulatedLeafIndex];
  assert.deepEqual(manipulated, {
    leaf_index: 6,
    opcode: 13,
    opcode_name: "BITOR",
    lhs: 0,
    rhs: 1,
    claimed: 1,
    note: "tree prediction bit"
  });

  // Straight-line dataflow: every masked branch value is consistent.
  const w = workload.witnesses;
  assert.equal(w[0].claimed ^ 1, w[1].claimed); // hi xor 1 = lo
  assert.equal(w[1].claimed & w[2].claimed, w[4].claimed);
  assert.equal(w[0].claimed & w[3].claimed, w[5].claimed);
  assert.equal(w[4].claimed | w[5].claimed, w[6].claimed);
});

test("quantized decision tree validates its parameters", () => {
  const base = qoeTreeWorkloadSpecs()[0];
  assert.throws(
    () =>
      lowerWorkloadSpec({
        ...base,
        operation: { ...base.operation, throughputKbps: 0 }
      }),
    /throughputKbps/
  );
  assert.throws(
    () =>
      lowerWorkloadSpec({
        ...base,
        operation: { ...base.operation, rootBitrateThresholdKbps: -5 }
      }),
    /rootBitrateThresholdKbps/
  );
});

test("allApplicationWorkloadSpecs includes synthetic, STAV360, drive-test and WebRTC-QoE workloads", () => {
  const ids = allApplicationWorkloadSpecs().map((w) => w.id);
  assert.equal(
    ids.length,
    stav360WorkloadSpecs().length +
      qoeMosWorkloadSpecs().length +
      qoeTreeWorkloadSpecs().length +
      regulatoryWorkloadSpecs().length +
      webrtcWorkloadSpecs().length
  );
  assert.ok(ids.includes("stav360_poor_rating_sla"));
  assert.ok(ids.includes("qoe_mos_degradation_alarm"));
  assert.ok(ids.includes("qoe_tree_mos_classifier"));
  assert.ok(ids.includes("regulatory_qoe_compliance"));
  assert.ok(ids.includes("regional_qoe_compliance"));
  assert.ok(ids.includes("webrtc_worst_acr_variance"));
  assert.ok(ids.includes("webrtc_poor_call_sla"));
  assert.ok(ids.includes("webrtc_poor_call_classifier"));
  assert.ok(ids.includes("webrtc_gaze_attention_monitor"));
});

test("regulatory QoE compliance monitor lowers real drive-test panel to a violation trace", () => {
  const workloads = defaultApplicationWorkloads();
  const byId = Object.fromEntries(workloads.map((w) => [w.id, w]));
  const panel = regulatoryPanel("bs1_3000kbps_compliance_16");
  const workload = byId.regulatory_qoe_compliance;

  assert.deepEqual(workload.model.valuesMilli, panel.valuesMilli);
  assert.equal(workload.model.goodCount, panel.goodCount);
  assert.equal(workload.model.goodPermille, panel.goodPermille);
  assert.equal(workload.model.targetPermille, panel.targetPermille);
  assert.equal(workload.model.violation, 1);
  assert.equal(workload.model.compliant, 0);

  // 16 GT leaves + 15 ADD sum-tree leaves + MUL, MUL, LT, BITXOR
  assert.equal(workload.lowering.unpaddedLeafCount, 35);
  assert.equal(workload.witnesses.length, 64);
  assert.deepEqual(opcodeCounts(workload.witnesses), {
    ADD: 44, // 15 sum-tree + 29 padding no-ops
    BITXOR: 1,
    GT: 16,
    LT: 1,
    MUL: 2
  });

  // The default manipulated leaf is the violation flag: flipping it is the
  // exact fraud a conflicted, operator-funded aggregator would attempt.
  const manipulated = workload.witnesses[workload.defaultManipulatedLeafIndex];
  assert.deepEqual(manipulated, {
    leaf_index: 33,
    opcode: 11,
    opcode_name: "LT",
    lhs: panel.goodCount * 1000,
    rhs: panel.n * panel.targetPermille,
    claimed: 1,
    note: "explicit compliance circuit",
    lhsRef: { kind: "output", index: 31 }, rhsRef: { kind: "output", index: 32 }
  });
  assert.equal(workload.witnesses[34].opcode_name, "BITXOR");
  assert.equal(workload.witnesses[34].claimed, 0);
});

test("regulatory compliance monitor validates its parameters", () => {
  const base = regulatoryWorkloadSpecs()[0];
  assert.throws(
    () =>
      lowerWorkloadSpec({
        ...base,
        operation: { ...base.operation, valuesMilli: [3000] }
      }),
    /invalid recordCount/
  );
  assert.throws(
    () =>
      lowerWorkloadSpec({
        ...base,
        operation: { ...base.operation, targetPermille: 1200 }
      }),
    /targetPermille exceeds 1000/
  );
});

test("regional QoE compliance monitor selects the target area homomorphically", () => {
  const workloads = defaultApplicationWorkloads();
  const byId = Object.fromEntries(workloads.map((w) => [w.id, w]));
  const panel = regulatoryPanel("bs1_bs4_3000kbps_regional_16");
  const workload = byId.regional_qoe_compliance;

  assert.deepEqual(
    workload.model.cells,
    panel.sessions.map((s) => s.cellIndex)
  );
  assert.deepEqual(
    workload.model.valuesMilli,
    panel.sessions.map((s) => s.mosMilli)
  );
  assert.equal(workload.model.targetCell, panel.targetCell);
  assert.equal(workload.model.inRegionCount, panel.inRegionCount);
  assert.equal(workload.model.goodInRegionCount, panel.goodInRegionCount);
  assert.equal(workload.model.regionGoodPermille, panel.regionGoodPermille);
  assert.equal(workload.model.violation, panel.violation);
  assert.equal(workload.model.compliant, panel.compliant);

  // The two coverage areas fall in disjoint coarse cells: the EQ leaves
  // select exactly the target area's sessions.
  const eqLeaves = workload.witnesses.slice(0, 16);
  for (const [i, w] of eqLeaves.entries()) {
    assert.equal(w.opcode_name, "EQ");
    assert.equal(w.lhs, panel.sessions[i].cellIndex);
    assert.equal(w.rhs, panel.targetCell);
    assert.equal(w.claimed, panel.sessions[i].cellIndex === panel.targetCell ? 1 : 0);
  }
  assert.equal(eqLeaves.filter((w) => w.claimed === 1).length, panel.inRegionCount);

  // 16 EQ + 16 GT + 16 BITAND + 15 ADD + 15 ADD + MUL, MUL, LT, BITXOR
  assert.equal(workload.lowering.unpaddedLeafCount, 84);
  assert.equal(workload.witnesses.length, 128);
  assert.deepEqual(opcodeCounts(workload.witnesses), {
    ADD: 74, // two 15-leaf sum trees + 44 result-carry padding leaves
    BITAND: 17,
    BITXOR: 1,
    EQ: 16,
    GT: 17,
    LT: 1,
    MUL: 2
  });

  // The default manipulated leaf is the regional violation flag: flipping it
  // is the exact fraud that hides a poor area inside a compliant mixed pool.
  const manipulated = workload.witnesses[workload.defaultManipulatedLeafIndex];
  assert.deepEqual(manipulated, {
    leaf_index: 80,
    opcode: 11,
    opcode_name: "LT",
    lhs: panel.goodInRegionCount * 1000,
    rhs: panel.inRegionCount * panel.targetPermille,
    claimed: panel.violation,
    note: "explicit compliance circuit",
    lhsRef: { kind: "output", index: 78 }, rhsRef: { kind: "output", index: 79 }
  });
  assert.equal(workload.witnesses[81].opcode_name, "BITXOR");
  assert.equal(workload.witnesses[81].claimed, panel.compliant);
});

test("regional compliance monitor validates its parameters", () => {
  const base = regulatoryWorkloadSpecs().find((w) => w.id === "regional_qoe_compliance");
  assert.throws(
    () =>
      lowerWorkloadSpec({
        ...base,
        operation: { ...base.operation, cells: base.operation.cells.slice(0, 8) }
      }),
    /one cell per MOS value/
  );
  assert.throws(
    () =>
      lowerWorkloadSpec({
        ...base,
        operation: { ...base.operation, targetPermille: 1200 }
      }),
    /targetPermille exceeds 1000/
  );
  // No observation cannot establish regional compliance.
  const vacuous = lowerWorkloadSpec({
    ...base,
    operation: { ...base.operation, targetCell: 1 }
  });
  assert.equal(vacuous.model.inRegionCount, 0);
  assert.equal(vacuous.model.violation, 1);
  assert.equal(vacuous.model.compliant, 0);
  assert.equal(vacuous.model.regionGoodPermille, null);
});

test("a data-manager style spec can be lowered without hand-writing leaves", () => {
  const workload = lowerWorkloadSpec({
    id: "qoe_mean_variance",
    domain: "QoE statistics",
    title: "QoE mean and variance",
    applicability: "Small deterministic QoE aggregate over quantized scores.",
    limitation: "Four-value fixture; larger datasets need a generalized reducer lowerer.",
    defaultManipulatedLeafIndex: 11,
    operation: {
      type: "mean_variance",
      values: [80, 75, 90, 85],
      divisor: 4,
      varianceThreshold: 20,
      meanThreshold: 70
    }
  });

  assert.equal(workload.lowering.operationType, "mean_variance");
  assert.equal(workload.witnesses.length, 32);
  assert.equal(workload.lowering.unpaddedLeafCount, 17);
  assert.equal(workload.model.mean, 82);
  assert.equal(workload.model.variance, 113);
  assert.equal(workload.witnesses[3].opcode_name, "DIV");
  assert.equal(workload.witnesses[13].opcode_name, "SUB");
  assert.equal(workload.witnesses[15].opcode_name, "GT");
  assert.equal(workload.witnesses[16].opcode_name, "BITAND");
  assert.equal(workload.witnesses[17].note, "padding no-op");
});

test("lowering rejects unsupported operations and invalid shapes", () => {
  assert.throws(
    () =>
      lowerWorkloadSpec({
        id: "bad",
        operation: { type: "unsupported_operation" }
      }),
    /Unsupported operation type/
  );

  // The classifier operation type stays supported even though no evaluated
  // workload instantiates it; its shape check must still reject bad input.
  assert.throws(
    () =>
      lowerWorkloadSpec({
        id: "shape-check",
        operation: {
          type: "quantized_linear_classifier",
          features: [1, 2, 3],
          weights: [1, 1, 1],
          bias: 0,
          scaleShift: 0,
          threshold: 0,
          expectedClass: 0
        }
      }),
    /exactly two features/
  );
});

test("WebRTC-QoE workloads lower real subjective, feature and gaze records", () => {
  const byId = Object.fromEntries(defaultApplicationWorkloads().map((w) => [w.id, w]));
  const worst = webrtcPanel("worst_acr_20");
  const fixtures = webrtcWorkloadSpecs();
  assert.equal(worst.ratings.length, 20, "20 subjects per test condition");

  // Statistics: integer mean/variance over the 20 encrypted ACR scores.
  const variance = byId.webrtc_worst_acr_variance;
  assert.equal(variance.model.mean, worst.mean);
  assert.equal(variance.model.variance, worst.variance);
  assert.equal(variance.lowering.unpaddedLeafCount, 89);
  assert.equal(variance.witnesses.length, 128);

  // Statistics: poor-call count against an SLA threshold; only the bit opens.
  const sla = byId.webrtc_poor_call_sla;
  assert.equal(sla.model.poorCount, worst.poorCount);
  assert.equal(sla.model.slaBreached, 1);
  assert.equal(sla.lowering.unpaddedLeafCount, 52);
  assert.deepEqual(opcodeCounts(sla.witnesses), { ADD: 43, GT: 1, LT: 20 });

  // ML inference: d-feature quantized classifier with public signed weights.
  // The totals are derived from the fixture rather than pinned, because the
  // fixture is regenerated from the raw export and its weights change with it.
  // What the test fixes is the lowering: the accumulation must reproduce the
  // fitted score and the decision must be the single GT leaf.
  const clf = byId.webrtc_poor_call_classifier;
  const clfFixture = loadWebrtcFixtures().classifier;
  const expectedPositive = clfFixture.features.reduce(
    (acc, x, j) => acc + Math.max(0, clfFixture.weights[j]) * x,
    Math.max(0, clfFixture.bias)
  );
  const expectedNegative = clfFixture.features.reduce(
    (acc, x, j) => acc + Math.max(0, -clfFixture.weights[j]) * x,
    Math.max(0, -clfFixture.bias)
  );
  assert.equal(clf.model.positiveTotal, expectedPositive);
  assert.equal(clf.model.negativeTotal, expectedNegative);
  assert.equal(clf.model.predicted, clfFixture.predictedPoor);
  assert.equal(clf.model.accepted, 1);
  assert.equal(clf.lowering.unpaddedLeafCount, 9);
  assert.equal(clf.witnesses[6].opcode_name, "GT", "decision leaf is the comparison");

  // Biometric-grade input: per-frame gaze deviations, one alarm bit opened.
  const gaze = byId.webrtc_gaze_attention_monitor;
  assert.equal(gaze.model.frames, 16);
  assert.equal(gaze.model.offCenterCount, 10);
  assert.equal(gaze.model.offCenterPermille, 625);
  assert.equal(gaze.model.alarm, 1);
  assert.equal(gaze.lowering.unpaddedLeafCount, 34);
  assert.equal(
    gaze.witnesses[gaze.defaultManipulatedLeafIndex].note,
    "attention alarm bit"
  );

  // Every WebRTC leaf stays inside the supported unsigned micro-ISA.
  for (const spec of fixtures) {
    const lowered = lowerWorkloadSpec(spec);
    for (const w of lowered.witnesses) {
      assert.ok(w.lhs >= 0 && w.rhs >= 0 && w.claimed >= 0, `${spec.id} leaf must be unsigned`);
    }
  }
});

test("linear_classifier_nd splits signed weights into unsigned accumulations", () => {
  const lowered = lowerWorkloadSpec({
    id: "signed_weight_probe",
    operation: {
      type: "linear_classifier_nd",
      features: [10, 4, 7],
      weights: [3, -5, 2],
      bias: 6,
      expectedClass: 1
    }
  });
  // positive: 10*3 + 7*2 + bias 6 = 50; negative: 4*5 = 20; decision 1.
  assert.equal(lowered.model.positiveTotal, 50);
  assert.equal(lowered.model.negativeTotal, 20);
  assert.equal(lowered.model.predicted, 1);
  for (const w of lowered.witnesses) {
    assert.ok(w.lhs >= 0 && w.rhs >= 0 && w.claimed >= 0);
  }
});
