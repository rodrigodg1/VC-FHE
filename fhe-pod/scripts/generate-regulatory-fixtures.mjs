#!/usr/bin/env node
/**
 * Build compliance fixtures from the local 5G-QoERA radio-simulation CSVs.
 *
 * Scenario grounding (see VC-FHE/docs/ARCHITECTURE.md):
 * a measurement entity funded by the operators it measures (ANATEL RQUAL /
 * ESAQ structure; FCC BDC self-reported claims) computes a periodic
 * compliance indicator -- the permille of user sessions whose video MOS is
 * above the "poor" level -- against a regulatory target. Users contribute
 * encrypted measurements (consent-gated MDT per 3GPP TS 32.422; QMC per TS 28.405); the regulator receives a verifiable compliance flag without seeing
 * raw per-user records.
 *
 * Two panels are emitted:
 *
 * 1. `bs1_3000kbps_compliance_16` -- the original single-area panel: a
 *    deterministic stride sample of 16 sessions from BS_1; the workload
 *    checks the share of sessions above the poor threshold against the
 *    permille target.
 *
 * 2. `bs1_bs4_3000kbps_regional_16` -- an area-scoped variant over a mixed
 *    panel: 8 stride-sampled sessions from BS_1 plus 8 from BS_4. Each
 *    session contributes an encrypted coarse cell index (0.01-degree grid,
 *    about 1.1 km at this latitude; the two coverage areas fall in disjoint
 *    cells) together with its encrypted milli-MOS. The workload selects the
 *    sessions of one target cell homomorphically (EQ against a public cell
 *    constant), counts the in-area and good-in-area sessions, and checks the
 *    area's share against the permille target. The aggregator never learns
 *    which encrypted cell belongs to which session from the ciphertext interface;
 *    trace disclosure contains handles and public program constants, not cell plaintexts.
 *    Public selection identities and auxiliary information remain outside that claim.
 *
 * The panels are deterministic stride samples of the supplied 5G-QoERA CSVs.
 * Their MOS values are simulation-derived, not subjective human ratings.
 *
 * Usage (from VC-FHE/fhe-pod):
 *   node scripts/generate-regulatory-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const sourceCsv = "VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv";
const sourceCsvBs4 = "VC-FHE/data/MOS_BS_4_Driver_PRB_10.csv";
const csvPath = path.join(repoRoot, sourceCsv);
const csvPathBs4 = path.join(repoRoot, sourceCsvBs4);
const outPath = path.join(scriptDir, "regulatory-fixtures.json");

const panelSize = 16;
const bitrateKbps = 3000;
const mosColumn = `MOS_${bitrateKbps}kbps`;
const poorThresholdMilli = 2000; // MOS <= 2.0 is "poor" (same label as qoe-mos fixture)
const targetPermille = 950; // regulatory target: >= 95% of sessions above poor

// Coarse location grid for the regional panel. 0.01 degrees is about 1.1 km
// of latitude; the BS_1 and BS_4 coverage areas (about 1.1 km apart) fall in
// disjoint cells at this granularity, and every session of one area shares
// one cell. Offsets keep the bins non-negative for unsigned 64-bit lowering.
const cellGranularityDegrees = 0.01;
const latOffsetDegrees = 90;
const lonOffsetDegrees = 180;
const lonBinsPerRow = 36000; // 360 / 0.01

function cellIndexOf(latitude, longitude) {
  const latBin = Math.floor((latitude + latOffsetDegrees) / cellGranularityDegrees);
  const lonBin = Math.floor((longitude + lonOffsetDegrees) / cellGranularityDegrees);
  return latBin * lonBinsPerRow + lonBin;
}

function parseCsv(file) {
  const text = fs.readFileSync(file, "utf8");
  const lines = text.trim().split(/\r?\n/);
  const header = lines[0].split(",");
  const idx = Object.fromEntries(header.map((h, i) => [h, i]));
  const rows = [];
  for (let lineIndex = 1; lineIndex < lines.length; lineIndex += 1) {
    const cols = lines[lineIndex].split(",");
    const mosMilli = Math.round(Number.parseFloat(cols[idx[mosColumn]]) * 1000);
    if (!Number.isFinite(mosMilli) || mosMilli <= 0) {
      continue;
    }
    rows.push({
      rowNumber: lineIndex,
      mosMilli,
      latitude: Number.parseFloat(cols[idx.Latitude]),
      longitude: Number.parseFloat(cols[idx.Longitude])
    });
  }
  return rows;
}

function stridePanel(rows, n) {
  const stride = Math.floor(rows.length / n);
  const panel = [];
  for (let i = 0; i < n; i += 1) {
    panel.push(rows[i * stride]);
  }
  return panel;
}

const rows = parseCsv(csvPath);
const rowsBs4 = parseCsv(csvPathBs4);

// Panel 1: original single-area compliance panel (unchanged sampling rule).
const panel = stridePanel(rows, panelSize);
const valuesMilli = panel.map((r) => r.mosMilli);
const goodBits = valuesMilli.map((v) => (v > poorThresholdMilli ? 1 : 0));
const goodCount = goodBits.reduce((a, b) => a + b, 0);
const goodPermille = Math.floor((goodCount * 1000) / panelSize);
const violation = goodCount * 1000 < panelSize * targetPermille ? 1 : 0;

// Panel 2: mixed-area regional panel (8 + 8 stride samples).
const half = panelSize / 2;
const regionalSessions = [
  ...stridePanel(rows, half).map((r) => ({ ...r, source: "BS_1" })),
  ...stridePanel(rowsBs4, half).map((r) => ({ ...r, source: "BS_4" }))
].map((r) => ({
  source: r.source,
  rowNumber: r.rowNumber,
  cellIndex: cellIndexOf(r.latitude, r.longitude),
  mosMilli: r.mosMilli
}));
const targetCell = regionalSessions[0].cellIndex; // BS_1's coverage cell
const inBits = regionalSessions.map((s) => (s.cellIndex === targetCell ? 1 : 0));
const regionalGoodBits = regionalSessions.map((s) =>
  s.mosMilli > poorThresholdMilli ? 1 : 0
);
const goodInBits = inBits.map((b, i) => b & regionalGoodBits[i]);
const inRegionCount = inBits.reduce((a, b) => a + b, 0);
const goodInRegionCount = goodInBits.reduce((a, b) => a + b, 0);
const regionGoodPermille =
  inRegionCount > 0 ? Math.floor((goodInRegionCount * 1000) / inRegionCount) : 0;
const regionalViolation =
  goodInRegionCount * 1000 < inRegionCount * targetPermille ? 1 : 0;
const distinctCells = new Set(regionalSessions.map((s) => s.cellIndex));

const fixtures = {
  dataset: {
    id: "MOS_BS_DRIVETEST",
    citation:
      "5G-QoERA drive-test export (Boffetti et al., IEEE WCNC 2025; telematics-lab/5G-QoERA, GPL-3.0), converted to CSV with throughput and MOS columns; regulatory-compliance task supported by ANATEL RQUAL (Res. 717/2019, operator-funded ESAQ measurement entity), FCC broadband-map misreporting evidence (IMC'24, DOI 10.1145/3646547.3688441), and consent-gated 3GPP MDT (TS 32.422) and standardized QMC (TS 28.405) collection.",
    sourceCsv,
    sourceCsvBs4,
    generatedAt: new Date().toISOString(),
    validRows: rows.length,
    validRowsBs4: rowsBs4.length,
    sensitiveFieldsPresent: ["User_ID", "Timestamp", "Latitude", "Longitude", "Tput"],
    samplingRule: `deterministic stride sample: row[i*floor(validRows/${panelSize})] for i in 0..${panelSize - 1}`
  },
  panels: {
    bs1_3000kbps_compliance_16: {
      baseStation: "BS_1",
      bitrateKbps,
      mosColumn,
      n: panelSize,
      rowNumbers: panel.map((r) => r.rowNumber),
      valuesMilli,
      poorThresholdMilli,
      targetPermille,
      goodCount,
      goodPermille,
      violation,
      compliant: violation ^ 1,
      indicator:
        "compliance <=> goodCount * 1000 >= n * targetPermille, good <=> mosMilli > poorThresholdMilli",
      literatureTask:
        "Periodic regulatory quality indicator (share of sessions meeting target vs. reference value) computed by an operator-funded measurement entity over user measurements collected under consent-gated 3GPP MDT-style machinery; verifiability deters strategic misreporting documented for self-reported regulatory data."
    },
    bs1_bs4_3000kbps_regional_16: {
      baseStations: ["BS_1", "BS_4"],
      bitrateKbps,
      mosColumn,
      n: panelSize,
      samplingRule: `deterministic stride sample per CSV: row[i*floor(validRows/${half})] for i in 0..${half - 1}, BS_1 sessions first`,
      cellGranularityDegrees,
      latOffsetDegrees,
      lonOffsetDegrees,
      lonBinsPerRow,
      cellIndexRule:
        "cellIndex = floor((lat+90)/g)*36000 + floor((lon+180)/g), g = 0.01 degrees (about 1.1 km); non-negative by construction for unsigned lowering",
      distinctCellsInPanel: distinctCells.size,
      targetCell,
      sessions: regionalSessions,
      poorThresholdMilli,
      targetPermille,
      inRegionCount,
      goodInRegionCount,
      regionGoodPermille,
      violation: regionalViolation,
      compliant: regionalViolation ^ 1,
      indicator:
        "regional compliance <=> inRegionCount > 0 and goodInRegionCount * 1000 >= inRegionCount * targetPermille, in <=> cellIndex == targetCell, good <=> mosMilli > poorThresholdMilli; returns zero when inRegionCount == 0",
      privacyNote:
        "The encrypted operands are a coarse cell index (about 1.1 km grid) and the milli-MOS per session. The aggregator computes the area-scoped indicator without learning which session lies in the target area. A challenged trace disclosure publishes the trace structure and handle-level provenance, not operand values: the panel's coarse cell indices stay encrypted, the public target cell is a program constant, and raw coordinates never enter any computation.",
      literatureTask:
        "Area-scoped periodic quality indicator (share of an area's sessions meeting target vs. reference value, as in per-municipality quality grades) computed over encrypted location cells and encrypted MOS, without revealing session-to-area membership to the aggregator."
    }
  }
};

fs.writeFileSync(outPath, `${JSON.stringify(fixtures, null, 2)}\n`, "utf8");
console.log(`Wrote ${outPath}`);
console.log(JSON.stringify(fixtures.panels, null, 2));
