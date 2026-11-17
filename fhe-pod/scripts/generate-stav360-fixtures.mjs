#!/usr/bin/env node
/**
 * Extract STAV360 panel fixtures from Users_Ratings.csv.
 *
 * Usage (from VC-FHE/fhe-pod):
 *   node scripts/generate-stav360-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
// The raw STAV360 ratings are NOT redistributed in this repository (upstream
// states no license). Candidates, in order: the datasets/ download location
// (node VC-FHE/datasets/download/download-stav360.mjs) and the legacy in-place
// copy that run-experiment.sh fetches on demand for the Rust emitter.
const csvCandidates = [
  path.join(repoRoot, "VC-FHE/datasets/raw/stav360/Raw_Ratings.csv"),
  path.join(repoRoot, "VC-FHE/BN254-Signatures/Users_Ratings.csv")
];
const csvPath = csvCandidates.find((p) => fs.existsSync(p));
const outPath = path.join(scriptDir, "stav360-fixtures.json");

// The derived fixtures are committed, so the evaluation is reproducible without
// redistributing the raw STAV360 rating export. Regeneration from the raw CSV
// happens only when that file is present; otherwise the committed fixtures are
// kept and the pipeline continues. Use --require-raw to fail instead.
const requireRaw = process.argv.includes("--require-raw");
if (!csvPath) {
  if (requireRaw) {
    console.error(`error: raw dataset not found; searched: ${csvCandidates.join(" ; ")}`);
    console.error("fetch it with: node VC-FHE/datasets/download/download-stav360.mjs");
    process.exit(1);
  }
  if (!fs.existsSync(outPath)) {
    console.error(
      `error: neither the raw dataset (${csvCandidates.join(" ; ")}) nor the committed fixtures (${outPath}) are present.`
    );
    process.exit(1);
  }
  console.log(
    `stav360 fixtures: raw dataset absent, keeping committed ${path.basename(outPath)} (fetch the export with VC-FHE/datasets/download/download-stav360.mjs to regenerate).`
  );
  process.exit(0);
}

function loadRatings() {
  const text = fs.readFileSync(csvPath, "utf8");
  const lines = text.trim().split(/\r?\n/);
  const header = lines[0].split(",");
  const idx = Object.fromEntries(header.map((h, i) => [h, i]));
  const rows = [];
  for (const line of lines.slice(1)) {
    const cols = line.split(",");
    const ratingRaw = cols[idx.rating]?.trim();
    if (!ratingRaw) continue;
    rows.push({
      user: cols[idx.user],
      video_title: cols[idx.video_title],
      video_tiling_pattern: cols[idx.video_tiling_pattern],
      rating: Math.round(Number.parseFloat(ratingRaw))
    });
  }
  return rows;
}

function panel(rows, video, pattern, n = null) {
  const subset = rows
    .filter((r) => r.video_title === video && r.video_tiling_pattern === pattern)
    .sort((a, b) => a.user.localeCompare(b.user));
  const slice = n ? subset.slice(0, n) : subset;
  const ratings = slice.map((r) => r.rating);
  const count = ratings.length;
  const sum = ratings.reduce((a, b) => a + b, 0);
  const mean = Math.floor(sum / count);
  const sqSum = ratings.reduce((a, v) => a + v * v, 0);
  const ex2 = Math.floor(sqSum / count);
  const variance = ex2 - mean * mean;
  const poorCount = ratings.filter((v) => v <= 2).length;
  return {
    video,
    pattern,
    n: count,
    ratings,
    mean,
    variance,
    poorCount,
    users: slice.map((r) => r.user)
  };
}

const rows = loadRatings();
const fixtures = {
  dataset: {
    id: "STAV360",
    citation:
      "Mahmoud et al., IEEE DataPort doi:10.21227/BCPT-3904; dataset experiment: ICIT 2025, doi:10.1109/ICIT64950.2025.11049277; prior use for QoE prediction: Mahmoud et al., IEEE TMM 2026, doi:10.1109/TMM.2026.3668490",
    mirror: "https://github.com/SLG-European-Projects/STAV360 (Raw_Ratings.csv; no upstream license, raw data not redistributed here)",
    scale: "ACR 1–5 subjective quality ratings",
    sourceCsv: path.relative(repoRoot, csvPath).split(path.sep).join("/"),
    generatedAt: new Date().toISOString(),
    validRows: rows.length
  },
  panels: {
    mos_variance_4: {
      ...panel(rows, "FeedTheDucks", "Pattern2_Uniform_Mid", 4),
      literatureTask:
        "Session MOS and opinion dispersion for one 360° video tiling configuration (ITU-T P.800-style aggregation over encrypted ACR scores)."
    },
    mos_variance_8: {
      ...panel(rows, "FeedTheDucks", "Pattern8_Checkerboard01", 8),
      literatureTask:
        "Checkerboard tiling QoE panel: encrypted mean/variance detect low MOS and rating disagreement without revealing individual viewers."
    },
    poor_rating_sla_8: {
      ...panel(rows, "FeedTheDucks", "Pattern1_Uniform_Low", 8),
      literatureTask:
        "Poor-experience SLA monitor: count encrypted ACR scores at or below 'fair' (≤2) for low-quality uniform tiling."
    }
  }
};

fs.writeFileSync(outPath, `${JSON.stringify(fixtures, null, 2)}\n`, "utf8");
console.log(`Wrote ${outPath}`);
console.log(JSON.stringify(fixtures.panels, null, 2));
