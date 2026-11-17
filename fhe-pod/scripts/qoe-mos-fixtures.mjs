/**
 * Real drive-test QoE/MOS fixtures for quantized application-layer inference.
 *
 * The fixture is derived from `VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv`.
 * It is intentionally a small deterministic inference workload: the model
 * threshold is selected off-chain from the public CSV, then the encrypted
 * inference trace verifies a fixed poor-QoE alarm.
 *
 * Regenerate JSON + embedded snapshot:
 *   node scripts/generate-qoe-mos-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const QOE_MOS_FIXTURES_JSON = path.join(scriptDir, "qoe-mos-fixtures.json");

const embeddedFixtures = {
  dataset: {
    id: "MOS_BS_DRIVETEST",
    citation:
      "Local drive-test QoE CSV with throughput and MOS columns; task supported by QoE prediction literature using in-device/network measurements.",
    sourceCsv: "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv",
    rowCount: 81091,
    sensitiveFieldsPresent: ["User_ID", "Timestamp", "Latitude", "Longitude", "Tput"],
    label: "poor QoE when MOS <= 2"
  },
  models: {
    bs1_3000kbps_poor_alarm: {
      baseStation: "BS_1",
      bitrateKbps: 3000,
      mosColumn: "MOS_3000kbps",
      mosPoorThresholdMilli: 2000,
      headroomPercent: 72,
      trainingRows: 81091,
      poorRows: 19358,
      correctRows: 81091,
      accuracyPermille: 1000,
      selectedRow: {
        rowNumber: 3,
        throughputKbps: 1928,
        observedMosMilli: 1000,
        observedPoor: 1
      },
      model:
        "predictedPoor = (throughputKbps * 100) < (bitrateKbps * headroomPercent)",
      literatureTask:
        "QoE/MOS degradation classification from network-side or in-device measurements; implemented as deterministic quantized inference rather than private model training."
    }
  }
};

export function loadQoeMosFixtures() {
  try {
    const raw = fs.readFileSync(QOE_MOS_FIXTURES_JSON, "utf8");
    return JSON.parse(raw);
  } catch {
    return embeddedFixtures;
  }
}

export function qoeMosModel(name) {
  const fixtures = loadQoeMosFixtures();
  const model = fixtures.models?.[name];
  if (!model) {
    throw new Error(`Unknown QoE MOS model fixture: ${name}`);
  }
  return model;
}

export function qoeMosWorkloadSpecs() {
  const fixture = qoeMosModel("bs1_3000kbps_poor_alarm");
  return [
    {
      id: "qoe_mos_degradation_alarm",
      domain: "QoE / ML inference",
      title: "Drive-test MOS degradation alarm (3000 kbps)",
      applicability:
        "Quantized poor-QoE classification over encrypted throughput, matching QoE prediction work that maps network/in-device measurements to MOS or acceptability.",
      limitation:
        "The threshold is fitted off-chain from the local MOS_BS CSV and the artifact verifies one deterministic inference; it does not implement private model training, random forests, neural networks, or ITU P.1203.",
      defaultManipulatedLeafIndex: 2,
      operation: {
        type: "qoe_degradation_alarm",
        throughputKbps: fixture.selectedRow.throughputKbps,
        bitrateKbps: fixture.bitrateKbps,
        headroomPercent: fixture.headroomPercent,
        observedMosMilli: fixture.selectedRow.observedMosMilli,
        observedPoor: fixture.selectedRow.observedPoor,
        metadata: {
          dataset: "MOS_BS_DRIVETEST",
          sourceCsv: "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv",
          baseStation: fixture.baseStation,
          rowNumber: fixture.selectedRow.rowNumber,
          mosColumn: fixture.mosColumn,
          trainingRows: fixture.trainingRows,
          poorRows: fixture.poorRows,
          correctRows: fixture.correctRows,
          accuracyPermille: fixture.accuracyPermille,
          model: fixture.model
        }
      }
    }
  ];
}
