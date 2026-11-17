#!/usr/bin/env node
/**
 * Fit a depth-2 quantized decision tree for poor-QoE classification from the
 * local drive-test CSVs and emit the fixture consumed by
 * `qoe-tree-fixtures.mjs`.
 *
 * Model class: two-feature decision tree (features: throughputKbps,
 * bitrateKbps; label: poor QoE, MOS <= 2.0), the model family used by
 * decision-tree QoE predictors in the literature. The tree is fitted on
 * MOS_BS_1 and evaluated on the held-out MOS_BS_4 base station. Thresholds
 * are integer kbps, so the fitted tree lowers directly to the unsigned
 * 64-bit micro-ISA without further quantization.
 *
 * Usage (from VC-FHE/fhe-pod):
 *   node scripts/generate-qoe-tree-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const trainCsvRel = "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv";
const testCsvRel = "VC-FHE/data/MOS_BS_4_Driver_PRB_10.csv";
const outPath = path.join(scriptDir, "qoe-tree-fixtures.json");
const mosPoorThresholdMilli = 2000;

const BITRATES_KBPS = [
  50, 100, 150, 200, 250, 300, 400, 500, 600, 700, 900, 1200, 1500, 2000,
  2500, 3000, 4000, 5000, 6000, 8000
];

function parseCsv(csvRelPath) {
  const text = fs.readFileSync(path.join(repoRoot, csvRelPath), "utf8");
  const lines = text.trim().split(/\r?\n/);
  const header = lines[0].split(",");
  const idx = Object.fromEntries(header.map((h, i) => [h, i]));
  const tputKbps = [];
  const mosMilli = BITRATES_KBPS.map(() => []);
  const rowNumbers = [];
  for (let lineIndex = 1; lineIndex < lines.length; lineIndex += 1) {
    const cols = lines[lineIndex].split(",");
    const tput = Math.round(Number.parseFloat(cols[idx.Tput]) * 1000);
    if (!Number.isFinite(tput) || tput < 0) continue;
    const mosRow = BITRATES_KBPS.map((b) =>
      Math.round(Number.parseFloat(cols[idx[`MOS_${b}kbps`]]) * 1000)
    );
    if (mosRow.some((m) => !Number.isFinite(m))) continue;
    rowNumbers.push(lineIndex);
    tputKbps.push(tput);
    for (let b = 0; b < BITRATES_KBPS.length; b += 1) mosMilli[b].push(mosRow[b]);
  }
  return { rowNumbers, tputKbps, mosMilli };
}

function predictPoor(tree, throughputKbps, bitrateKbps) {
  const hi = bitrateKbps > tree.rootBitrateThresholdKbps ? 1 : 0;
  const threshold = hi ? tree.highTputThresholdKbps : tree.lowTputThresholdKbps;
  return throughputKbps < threshold ? 1 : 0;
}

function accuracyOf(tree, data) {
  const n = data.tputKbps.length;
  let correct = 0;
  let poor = 0;
  for (let b = 0; b < BITRATES_KBPS.length; b += 1) {
    for (let i = 0; i < n; i += 1) {
      const observedPoor = data.mosMilli[b][i] <= mosPoorThresholdMilli ? 1 : 0;
      poor += observedPoor;
      if (predictPoor(tree, data.tputKbps[i], BITRATES_KBPS[b]) === observedPoor) {
        correct += 1;
      }
    }
  }
  return { samples: n * BITRATES_KBPS.length, poorSamples: poor, correct };
}

function ratioRuleAccuracy(data, headroomPercent) {
  const n = data.tputKbps.length;
  let correct = 0;
  for (let b = 0; b < BITRATES_KBPS.length; b += 1) {
    for (let i = 0; i < n; i += 1) {
      const observedPoor = data.mosMilli[b][i] <= mosPoorThresholdMilli ? 1 : 0;
      const predicted =
        data.tputKbps[i] * 100 < BITRATES_KBPS[b] * headroomPercent ? 1 : 0;
      if (predicted === observedPoor) correct += 1;
    }
  }
  return { samples: n * BITRATES_KBPS.length, correct };
}

/**
 * For one branch (a set of bitrate columns), find the integer throughput
 * threshold t minimizing misclassification of "predict poor iff tput < t"
 * using prefix sums over rows sorted by throughput.
 */
function bestTputThreshold(order, sortedTput, poorPrefixPerBitrate, branchBitrateIdx, n) {
  const poorPrefix = new Float64Array(n + 1);
  for (const b of branchBitrateIdx) {
    const p = poorPrefixPerBitrate[b];
    for (let k = 0; k <= n; k += 1) poorPrefix[k] += p[k];
  }
  const branches = branchBitrateIdx.length;
  const totalPoor = poorPrefix[n];
  let best = { thresholdKbps: 0, errors: Number.POSITIVE_INFINITY };
  // Candidate split positions: k rows below the threshold. Ties in
  // throughput must fall on the same side, so k is valid only at strict
  // throughput increases (plus the two trivial endpoints).
  for (let k = 0; k <= n; k += 1) {
    if (k > 0 && k < n && sortedTput[k] === sortedTput[k - 1]) continue;
    // predicted poor: the k*branches samples below t; errors =
    // poor-with-tput>=t plus good-with-tput<t.
    const errors = (totalPoor - poorPrefix[k]) + (k * branches - poorPrefix[k]);
    if (errors < best.errors) {
      const thresholdKbps =
        k === 0 ? 0 : k === n ? sortedTput[n - 1] + 1 : sortedTput[k];
      best = { thresholdKbps, errors };
    }
  }
  return best;
}

function fitTree(train) {
  const n = train.tputKbps.length;
  const order = Array.from({ length: n }, (_, i) => i).sort(
    (a, b) => train.tputKbps[a] - train.tputKbps[b]
  );
  const sortedTput = order.map((i) => train.tputKbps[i]);
  // poorPrefixPerBitrate[b][k] = poor rows among the k lowest-throughput rows.
  const poorPrefixPerBitrate = BITRATES_KBPS.map((_, b) => {
    const prefix = new Float64Array(n + 1);
    for (let k = 0; k < n; k += 1) {
      const poor = train.mosMilli[b][order[k]] <= mosPoorThresholdMilli ? 1 : 0;
      prefix[k + 1] = prefix[k] + poor;
    }
    return prefix;
  });

  let best = null;
  // Root split: bitrate > B, with B chosen between consecutive bitrates.
  for (let rootIdx = 0; rootIdx < BITRATES_KBPS.length - 1; rootIdx += 1) {
    const rootBitrateThresholdKbps = BITRATES_KBPS[rootIdx];
    const lowIdx = [];
    const highIdx = [];
    for (let b = 0; b < BITRATES_KBPS.length; b += 1) {
      (BITRATES_KBPS[b] > rootBitrateThresholdKbps ? highIdx : lowIdx).push(b);
    }
    const low = bestTputThreshold(order, sortedTput, poorPrefixPerBitrate, lowIdx, n);
    const high = bestTputThreshold(order, sortedTput, poorPrefixPerBitrate, highIdx, n);
    const errors = low.errors + high.errors;
    if (!best || errors < best.errors) {
      best = {
        rootBitrateThresholdKbps,
        lowTputThresholdKbps: low.thresholdKbps,
        highTputThresholdKbps: high.thresholdKbps,
        errors
      };
    }
  }
  return best;
}

function selectFixtureSample(tree, test) {
  const n = test.tputKbps.length;
  // Deterministic pick: the first held-out sample, in (row, bitrate) order,
  // that is a true positive on the high-demand branch, so the trace
  // exercises the root split, the branch mask, and the prediction bit.
  for (let i = 0; i < n; i += 1) {
    for (let b = 0; b < BITRATES_KBPS.length; b += 1) {
      const bitrateKbps = BITRATES_KBPS[b];
      if (bitrateKbps <= tree.rootBitrateThresholdKbps) continue;
      const observedPoor = test.mosMilli[b][i] <= mosPoorThresholdMilli ? 1 : 0;
      if (observedPoor !== 1) continue;
      if (predictPoor(tree, test.tputKbps[i], bitrateKbps) !== 1) continue;
      return {
        rowNumber: test.rowNumbers[i],
        throughputKbps: test.tputKbps[i],
        bitrateKbps,
        observedMosMilli: test.mosMilli[b][i],
        observedPoor
      };
    }
  }
  throw new Error("No true-positive high-branch sample found in the held-out CSV");
}

const train = parseCsv(trainCsvRel);
const test = parseCsv(testCsvRel);
const tree = fitTree(train);
const trainAcc = accuracyOf(tree, train);
const testAcc = accuracyOf(tree, test);
const ratioTrain = ratioRuleAccuracy(train, 72);
const ratioTest = ratioRuleAccuracy(test, 72);
const selectedSample = selectFixtureSample(tree, test);

const fixtures = {
  dataset: {
    id: "MOS_BS_DRIVETEST_TREE",
    citation:
      "5G-QoERA drive-test export (Boffetti et al., IEEE WCNC 2025; telematics-lab/5G-QoERA, GPL-3.0), converted to CSV with throughput and per-bitrate MOS columns; task shape follows decision-tree QoE prediction from network measurements.",
    trainCsv: trainCsvRel,
    testCsv: testCsvRel,
    generatedAt: new Date().toISOString(),
    trainRows: train.tputKbps.length,
    testRows: test.tputKbps.length,
    bitratesKbps: BITRATES_KBPS,
    label: `poor QoE when MOS <= ${mosPoorThresholdMilli / 1000}`
  },
  models: {
    bs_crossstation_poor_tree: {
      modelClass: "depth-2 decision tree (features: throughputKbps, bitrateKbps)",
      trainedOn: "BS_1",
      heldOutOn: "BS_4",
      mosPoorThresholdMilli,
      rootBitrateThresholdKbps: tree.rootBitrateThresholdKbps,
      lowTputThresholdKbps: tree.lowTputThresholdKbps,
      highTputThresholdKbps: tree.highTputThresholdKbps,
      trainSamples: trainAcc.samples,
      trainPoorSamples: trainAcc.poorSamples,
      trainCorrect: trainAcc.correct,
      trainAccuracyPermille: Math.round((trainAcc.correct / trainAcc.samples) * 1000),
      testSamples: testAcc.samples,
      testPoorSamples: testAcc.poorSamples,
      testCorrect: testAcc.correct,
      testAccuracyPermille: Math.round((testAcc.correct / testAcc.samples) * 1000),
      ratioRuleBaseline: {
        rule: "predictedPoor = (throughputKbps * 100) < (bitrateKbps * 72)",
        trainCorrect: ratioTrain.correct,
        trainAccuracyPermille: Math.round((ratioTrain.correct / ratioTrain.samples) * 1000),
        testCorrect: ratioTest.correct,
        testAccuracyPermille: Math.round((ratioTest.correct / ratioTest.samples) * 1000)
      },
      selectedSample,
      model:
        "hi = bitrateKbps > rootBitrateThreshold; predictedPoor = hi ? (tput < highTputThreshold) : (tput < lowTputThreshold)",
      literatureTask:
        "Decision-tree QoE/acceptability classification from network measurements; implemented as verifiable encrypted inference of an off-chain-fitted quantized tree, not private training."
    }
  }
};

fs.writeFileSync(outPath, `${JSON.stringify(fixtures, null, 2)}\n`, "utf8");
console.log(`Wrote ${outPath}`);
console.log(JSON.stringify(fixtures.models, null, 2));
