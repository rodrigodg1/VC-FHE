#!/usr/bin/env node
/**
 * Build a compact QoE/MOS degradation fixture from the local drive-test CSV.
 *
 * Usage (from VC-FHE/fhe-pod):
 *   node scripts/generate-qoe-mos-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const sourceCsv = "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv";
const csvPath = path.join(repoRoot, sourceCsv);
const outPath = path.join(scriptDir, "qoe-mos-fixtures.json");
const bitrateKbps = 3000;
const mosColumn = `MOS_${bitrateKbps}kbps`;
const mosPoorThresholdMilli = 2000;

function parseCsv() {
  const text = fs.readFileSync(csvPath, "utf8");
  const lines = text.trim().split(/\r?\n/);
  const header = lines[0].split(",");
  const idx = Object.fromEntries(header.map((h, i) => [h, i]));
  const rows = [];
  for (let lineIndex = 1; lineIndex < lines.length; lineIndex += 1) {
    const cols = lines[lineIndex].split(",");
    const throughputKbps = Math.round(Number.parseFloat(cols[idx.Tput]) * 1000);
    const observedMosMilli = Math.round(Number.parseFloat(cols[idx[mosColumn]]) * 1000);
    if (!Number.isFinite(throughputKbps) || !Number.isFinite(observedMosMilli)) {
      continue;
    }
    rows.push({
      rowNumber: lineIndex,
      throughputKbps,
      observedMosMilli,
      observedPoor: observedMosMilli <= mosPoorThresholdMilli ? 1 : 0
    });
  }
  return rows;
}

function evaluateHeadroom(rows, headroomPercent) {
  let correct = 0;
  let poorRows = 0;
  for (const row of rows) {
    const predictedPoor =
      row.throughputKbps * 100 < bitrateKbps * headroomPercent ? 1 : 0;
    if (predictedPoor === row.observedPoor) correct += 1;
    if (row.observedPoor === 1) poorRows += 1;
  }
  return { correct, poorRows, accuracy: correct / rows.length };
}

function fitHeadroom(rows) {
  let best = { headroomPercent: 0, correct: -1, poorRows: 0, accuracy: 0 };
  for (let headroomPercent = 10; headroomPercent <= 140; headroomPercent += 1) {
    const score = evaluateHeadroom(rows, headroomPercent);
    if (score.correct > best.correct) {
      best = { headroomPercent, ...score };
    }
  }
  return best;
}

const rows = parseCsv();
const best = fitHeadroom(rows);
const selectedRow = rows.find(
  (row) =>
    row.observedPoor === 1 &&
    row.throughputKbps * 100 < bitrateKbps * best.headroomPercent
);

if (!selectedRow) {
  throw new Error("No true-positive poor-QoE row found for the fitted threshold");
}

const fixtures = {
  dataset: {
    id: "MOS_BS_DRIVETEST",
    citation:
      "5G-QoERA drive-test export (Boffetti et al., IEEE WCNC 2025; telematics-lab/5G-QoERA, GPL-3.0), converted to CSV with throughput and per-bitrate MOS columns; task supported by QoE prediction literature using in-device/network measurements.",
    sourceCsv,
    generatedAt: new Date().toISOString(),
    rowCount: rows.length,
    sensitiveFieldsPresent: ["User_ID", "Timestamp", "Latitude", "Longitude", "Tput"],
    label: "poor QoE when MOS <= 2"
  },
  models: {
    bs1_3000kbps_poor_alarm: {
      baseStation: "BS_1",
      bitrateKbps,
      mosColumn,
      mosPoorThresholdMilli,
      headroomPercent: best.headroomPercent,
      trainingRows: rows.length,
      poorRows: best.poorRows,
      correctRows: best.correct,
      accuracyPermille: Math.round(best.accuracy * 1000),
      selectedRow,
      model:
        "predictedPoor = (throughputKbps * 100) < (bitrateKbps * headroomPercent)",
      literatureTask:
        "QoE/MOS degradation classification from network-side or in-device measurements; implemented as deterministic quantized inference rather than private model training."
    }
  }
};

fs.writeFileSync(outPath, `${JSON.stringify(fixtures, null, 2)}\n`, "utf8");
console.log(`Wrote ${outPath}`);
console.log(JSON.stringify(fixtures.models, null, 2));
