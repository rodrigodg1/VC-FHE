/**
 * Regulatory QoE compliance fixtures for application-layer evaluation.
 *
 * The panel is a deterministic stride sample of real drive-test video-MOS
 * rows from `VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv`. The workload models the
 * institutional setting documented in the literature: an operator-funded
 * measurement entity (ANATEL RQUAL Res. 717/2019 / ESAQ; FCC broadband-map
 * self-reports, IMC'24 DOI 10.1145/3646547.3688441) computes a periodic
 * compliance indicator over encrypted user measurements (consent-gated MDT per
 * 3GPP TS 32.422; QMC per TS 28.405) and the regulator verifies the result without
 * seeing raw per-user records.
 *
 * Regenerate JSON + embedded snapshot:
 *   node scripts/generate-regulatory-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const REGULATORY_FIXTURES_JSON = path.join(scriptDir, "regulatory-fixtures.json");

const embeddedFixtures = {
  "dataset": {
    "id": "MOS_BS_DRIVETEST",
    "citation": "Local drive-test QoE CSV with throughput and MOS columns; regulatory-compliance task supported by ANATEL RQUAL (Res. 717/2019, operator-funded ESAQ measurement entity), FCC broadband-map misreporting evidence (IMC'24, DOI 10.1145/3646547.3688441), and consent-gated 3GPP MDT (TS 32.422) and standardized QMC (TS 28.405) collection.",
    "sourceCsv": "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv",
    "sourceCsvBs4": "VC-FHE/data/MOS_BS_4_Driver_PRB_10.csv",
    "validRows": 81091,
    "validRowsBs4": 28863,
    "sensitiveFieldsPresent": [
      "User_ID",
      "Timestamp",
      "Latitude",
      "Longitude",
      "Tput"
    ],
    "samplingRule": "deterministic stride sample: row[i*floor(validRows/16)] for i in 0..15"
  },
  "panels": {
    "bs1_3000kbps_compliance_16": {
      "baseStation": "BS_1",
      "bitrateKbps": 3000,
      "mosColumn": "MOS_3000kbps",
      "n": 16,
      "rowNumbers": [
        1,
        5069,
        10137,
        15205,
        20273,
        25341,
        30409,
        35477,
        40545,
        45613,
        50681,
        55749,
        60817,
        65885,
        70953,
        76021
      ],
      "valuesMilli": [
        4834,
        1000,
        4834,
        1000,
        3241,
        4834,
        3241,
        4834,
        4834,
        4834,
        1000,
        4834,
        4834,
        1000,
        3241,
        4834
      ],
      "poorThresholdMilli": 2000,
      "targetPermille": 950,
      "goodCount": 12,
      "goodPermille": 750,
      "violation": 1,
      "compliant": 0,
      "indicator": "compliance <=> goodCount * 1000 >= n * targetPermille, good <=> mosMilli > poorThresholdMilli",
      "literatureTask": "Periodic regulatory quality indicator (share of sessions meeting target vs. reference value) computed by an operator-funded measurement entity over user measurements collected under consent-gated 3GPP MDT-style machinery; verifiability deters strategic misreporting documented for self-reported regulatory data."
    },
    "bs1_bs4_3000kbps_regional_16": {
      "baseStations": [
        "BS_1",
        "BS_4"
      ],
      "bitrateKbps": 3000,
      "mosColumn": "MOS_3000kbps",
      "n": 16,
      "samplingRule": "deterministic stride sample per CSV: row[i*floor(validRows/8)] for i in 0..7, BS_1 sessions first",
      "cellGranularityDegrees": 0.01,
      "latOffsetDegrees": 90,
      "lonOffsetDegrees": 180,
      "lonBinsPerRow": 36000,
      "cellIndexRule": "cellIndex = floor((lat+90)/g)*36000 + floor((lon+180)/g), g = 0.01 degrees (about 1.1 km); non-negative by construction for unsigned lowering",
      "distinctCellsInPanel": 2,
      "targetCell": 474859250,
      "sessions": [
        {
          "source": "BS_1",
          "rowNumber": 1,
          "cellIndex": 474859250,
          "mosMilli": 4834
        },
        {
          "source": "BS_1",
          "rowNumber": 10137,
          "cellIndex": 474859250,
          "mosMilli": 4834
        },
        {
          "source": "BS_1",
          "rowNumber": 20273,
          "cellIndex": 474859250,
          "mosMilli": 3241
        },
        {
          "source": "BS_1",
          "rowNumber": 30409,
          "cellIndex": 474859250,
          "mosMilli": 3241
        },
        {
          "source": "BS_1",
          "rowNumber": 40545,
          "cellIndex": 474859250,
          "mosMilli": 4834
        },
        {
          "source": "BS_1",
          "rowNumber": 50681,
          "cellIndex": 474859250,
          "mosMilli": 1000
        },
        {
          "source": "BS_1",
          "rowNumber": 60817,
          "cellIndex": 474859250,
          "mosMilli": 4834
        },
        {
          "source": "BS_1",
          "rowNumber": 70953,
          "cellIndex": 474859250,
          "mosMilli": 3241
        },
        {
          "source": "BS_4",
          "rowNumber": 1,
          "cellIndex": 474895250,
          "mosMilli": 3241
        },
        {
          "source": "BS_4",
          "rowNumber": 3608,
          "cellIndex": 474895250,
          "mosMilli": 3241
        },
        {
          "source": "BS_4",
          "rowNumber": 7215,
          "cellIndex": 474895250,
          "mosMilli": 4834
        },
        {
          "source": "BS_4",
          "rowNumber": 10822,
          "cellIndex": 474895250,
          "mosMilli": 3241
        },
        {
          "source": "BS_4",
          "rowNumber": 14429,
          "cellIndex": 474895250,
          "mosMilli": 1000
        },
        {
          "source": "BS_4",
          "rowNumber": 18036,
          "cellIndex": 474895250,
          "mosMilli": 3241
        },
        {
          "source": "BS_4",
          "rowNumber": 21643,
          "cellIndex": 474895250,
          "mosMilli": 4834
        },
        {
          "source": "BS_4",
          "rowNumber": 25250,
          "cellIndex": 474895250,
          "mosMilli": 4834
        }
      ],
      "poorThresholdMilli": 2000,
      "targetPermille": 950,
      "inRegionCount": 8,
      "goodInRegionCount": 7,
      "regionGoodPermille": 875,
      "violation": 1,
      "compliant": 0,
      "indicator": "regional compliance <=> inRegionCount > 0 and goodInRegionCount * 1000 >= inRegionCount * targetPermille, in <=> cellIndex == targetCell, good <=> mosMilli > poorThresholdMilli; returns zero when inRegionCount == 0",
      "privacyNote": "The encrypted operands are a coarse cell index (about 1.1 km grid) and the milli-MOS per session. The aggregator computes the area-scoped indicator without learning which session lies in the target area. A challenged trace disclosure publishes the trace structure and handle-level provenance, not operand values: the panel's coarse cell indices stay encrypted, the public target cell is a program constant, and raw coordinates never enter any computation.",
      "literatureTask": "Area-scoped periodic quality indicator (share of an area's sessions meeting target vs. reference value, as in per-municipality quality grades) computed over encrypted location cells and encrypted MOS, without revealing session-to-area membership to the aggregator."
    }
  }
};

export function loadRegulatoryFixtures() {
  try {
    const raw = fs.readFileSync(REGULATORY_FIXTURES_JSON, "utf8");
    return JSON.parse(raw);
  } catch {
    return embeddedFixtures;
  }
}

export function regulatoryPanel(name) {
  const fixtures = loadRegulatoryFixtures();
  const panel = fixtures.panels?.[name];
  if (!panel) {
    throw new Error(`Unknown regulatory panel fixture: ${name}`);
  }
  return panel;
}

export function regulatoryWorkloadSpecs() {
  const panel = regulatoryPanel("bs1_3000kbps_compliance_16");
  return [
    {
      id: "regulatory_qoe_compliance",
      domain: "QoE / regulatory compliance",
      title: "Regulatory QoE compliance monitor (95% target, operator-funded aggregator)",
      applicability:
        "Periodic regulator-facing quality indicators (share of sessions meeting target vs. reference value) computed by a measurement entity with a documented conflict of interest, over consent-gated encrypted user measurements.",
      limitation:
        "One indicator over one 16-session panel; production reporting covers many indicators, regions and periods, and the panel-size scaling limits of the trace apply.",
      // The violation flag (LT leaf) is exactly the leaf a conflicted
      // aggregator flips to report compliance; see defaultManipulatedLeafIndex.
      defaultManipulatedLeafIndex: 33,
      operation: {
        type: "regulatory_compliance_monitor",
        valuesMilli: panel.valuesMilli,
        poorThresholdMilli: panel.poorThresholdMilli,
        targetPermille: panel.targetPermille,
        metadata: {
          dataset: "MOS_BS_DRIVETEST",
          sourceCsv: "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv",
          baseStation: panel.baseStation,
          bitrateKbps: panel.bitrateKbps,
          mosColumn: panel.mosColumn,
          rowNumbers: panel.rowNumbers,
          indicator: panel.indicator,
          scenario:
            "ANATEL RQUAL / ESAQ-style operator-funded measurement entity; FCC BDC-style self-reported claims; consent-gated 3GPP MDT (TS 32.422); standardized QMC (TS 28.405)",
          literatureTask: panel.literatureTask
        }
      }
    },
    regionalWorkloadSpec()
  ];
}

function regionalWorkloadSpec() {
  const panel = regulatoryPanel("bs1_bs4_3000kbps_regional_16");
  return {
    id: "regional_qoe_compliance",
    domain: "QoE / regulatory compliance",
    title:
      "Area-scoped QoE compliance monitor over encrypted location cells (mixed two-area panel)",
    applicability:
      "Per-area regulator-facing indicators (as in per-municipality quality grades) computed over encrypted coarse location cells and encrypted MOS, without revealing session-to-area membership to the aggregator.",
    limitation:
      "One indicator over one 16-session two-area panel; the 0.01-degree cell granularity is forced by the dataset (the two coverage areas are about 1.1 km apart); a challenged trace publishes the structure and handle-level provenance of the cell-membership comparisons, not their operand values.",
    // The violation flag (LT leaf) is exactly the leaf a conflicted
    // aggregator flips to report regional compliance: 16 EQ + 16 GT +
    // 16 BITAND + 15 ADD + 15 ADD + 2 MUL place it at index 80.
    defaultManipulatedLeafIndex: 80,
    operation: {
      type: "regional_compliance_monitor",
      cells: panel.sessions.map((s) => s.cellIndex),
      valuesMilli: panel.sessions.map((s) => s.mosMilli),
      targetCell: panel.targetCell,
      poorThresholdMilli: panel.poorThresholdMilli,
      targetPermille: panel.targetPermille,
      metadata: {
        dataset: "MOS_BS_DRIVETEST",
        sourceCsvs: [
          "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv",
          "VC-FHE/data/MOS_BS_4_Driver_PRB_10.csv"
        ],
        baseStations: panel.baseStations,
        bitrateKbps: panel.bitrateKbps,
        mosColumn: panel.mosColumn,
        samplingRule: panel.samplingRule,
        cellIndexRule: panel.cellIndexRule,
        cellGranularityDegrees: panel.cellGranularityDegrees,
        rowNumbers: panel.sessions.map((s) => s.rowNumber),
        indicator: panel.indicator,
        privacyNote: panel.privacyNote,
        literatureTask: panel.literatureTask
      }
    }
  };
}
