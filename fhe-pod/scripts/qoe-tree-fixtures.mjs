/**
 * Real drive-test decision-tree QoE fixtures for quantized application-layer
 * ML inference.
 *
 * The fixture is derived from `VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv`
 * (training) and `VC-FHE/data/MOS_BS_4_Driver_PRB_10.csv` (held-out test).
 * The model is a depth-2 decision tree over two encrypted features
 * (throughputKbps, bitrateKbps) predicting poor QoE (MOS <= 2.0), the model
 * family used by decision-tree QoE predictors in the literature. The tree is
 * fitted off-chain from the public CSVs; the encrypted inference trace then
 * verifies one deterministic tree evaluation, with every branch computed
 * obliviously (no data-dependent control flow).
 *
 * Regenerate JSON + embedded snapshot:
 *   node scripts/generate-qoe-tree-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const QOE_TREE_FIXTURES_JSON = path.join(scriptDir, "qoe-tree-fixtures.json");

const embeddedFixtures = {
  dataset: {
    id: "MOS_BS_DRIVETEST_TREE",
    citation:
      "Local drive-test QoE CSVs with throughput and per-bitrate MOS columns; task shape follows decision-tree QoE prediction from network measurements.",
    trainCsv: "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv",
    testCsv: "VC-FHE/data/MOS_BS_4_Driver_PRB_10.csv",
    trainRows: 81091,
    testRows: 28863,
    label: "poor QoE when MOS <= 2"
  },
  models: {
    bs_crossstation_poor_tree: {
      modelClass: "depth-2 decision tree (features: throughputKbps, bitrateKbps)",
      trainedOn: "BS_1",
      heldOutOn: "BS_4",
      mosPoorThresholdMilli: 2000,
      rootBitrateThresholdKbps: 3000,
      lowTputThresholdKbps: 1928,
      highTputThresholdKbps: 4736,
      trainSamples: 1621820,
      trainPoorSamples: 231510,
      trainCorrect: 1553682,
      trainAccuracyPermille: 958,
      testSamples: 577260,
      testPoorSamples: 103802,
      testCorrect: 555088,
      testAccuracyPermille: 962,
      ratioRuleBaseline: {
        rule: "predictedPoor = (throughputKbps * 100) < (bitrateKbps * 72)",
        trainCorrect: 1592728,
        trainAccuracyPermille: 982,
        testCorrect: 570085,
        testAccuracyPermille: 988
      },
      selectedSample: {
        rowNumber: 1,
        throughputKbps: 2792,
        bitrateKbps: 4000,
        observedMosMilli: 1000,
        observedPoor: 1
      },
      model:
        "hi = bitrateKbps > rootBitrateThreshold; predictedPoor = hi ? (tput < highTputThreshold) : (tput < lowTputThreshold)",
      literatureTask:
        "Decision-tree QoE/acceptability classification from network measurements; implemented as verifiable encrypted inference of an off-chain-fitted quantized tree, not private training."
    }
  }
};

export function loadQoeTreeFixtures() {
  try {
    const raw = fs.readFileSync(QOE_TREE_FIXTURES_JSON, "utf8");
    return JSON.parse(raw);
  } catch {
    return embeddedFixtures;
  }
}

export function qoeTreeModel(name) {
  const fixtures = loadQoeTreeFixtures();
  const model = fixtures.models?.[name];
  if (!model) {
    throw new Error(`Unknown QoE tree model fixture: ${name}`);
  }
  return model;
}

export function qoeTreeWorkloadSpecs() {
  const fixture = qoeTreeModel("bs_crossstation_poor_tree");
  return [
    {
      id: "qoe_tree_mos_classifier",
      domain: "QoE / ML inference",
      title: "Drive-test decision-tree QoE classifier (2 features)",
      applicability:
        "Verifiable encrypted inference of an off-chain-fitted quantized decision tree over network measurements, matching decision-tree QoE/acceptability prediction in the literature; the tree is evaluated obliviously, so no data-dependent control flow enters the trace.",
      limitation:
        "Depth-2 tree with integer thresholds fitted off-chain from the local MOS_BS CSVs (trained on BS_1, held out on BS_4); the artifact verifies one deterministic inference and does not implement private training, ensembles, or neural networks.",
      // The prediction bit is the leaf a malicious operator flips to hide a
      // poor-QoE session, mirroring the regulatory workload's violation flag.
      defaultManipulatedLeafIndex: 6,
      operation: {
        type: "quantized_decision_tree",
        throughputKbps: fixture.selectedSample.throughputKbps,
        bitrateKbps: fixture.selectedSample.bitrateKbps,
        rootBitrateThresholdKbps: fixture.rootBitrateThresholdKbps,
        lowTputThresholdKbps: fixture.lowTputThresholdKbps,
        highTputThresholdKbps: fixture.highTputThresholdKbps,
        observedMosMilli: fixture.selectedSample.observedMosMilli,
        observedPoor: fixture.selectedSample.observedPoor,
        metadata: {
          dataset: "MOS_BS_DRIVETEST_TREE",
          trainCsv: "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv",
          testCsv: "VC-FHE/data/MOS_BS_4_Driver_PRB_10.csv",
          modelClass: fixture.modelClass,
          trainedOn: fixture.trainedOn,
          heldOutOn: fixture.heldOutOn,
          rowNumber: fixture.selectedSample.rowNumber,
          trainSamples: fixture.trainSamples,
          trainAccuracyPermille: fixture.trainAccuracyPermille,
          testSamples: fixture.testSamples,
          testAccuracyPermille: fixture.testAccuracyPermille,
          ratioRuleBaseline: fixture.ratioRuleBaseline,
          model: fixture.model
        }
      }
    }
  ];
}
