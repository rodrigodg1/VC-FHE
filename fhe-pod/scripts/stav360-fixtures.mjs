/**
 * STAV360 subjective QoE fixtures for application-layer evaluation.
 *
 * Ratings are extracted from `VC-FHE/BN254-Signatures/Users_Ratings.csv`
 * (ACR 1–5 scale; Mahmoud et al., IEEE DataPort 10.21227/bcpt-3904).
 *
 * Regenerate JSON + embedded snapshot:
 *   node scripts/generate-stav360-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const STAV360_FIXTURES_JSON = path.join(scriptDir, "stav360-fixtures.json");

/** @type {import("./stav360-fixtures.types.js").Stav360Fixtures} */
const embeddedFixtures = {
  dataset: {
    id: "STAV360",
    citation: "Mahmoud et al., IEEE DataPort 10.21227/bcpt-3904; ICIT 2025",
    scale: "ACR 1–5 subjective quality ratings",
    sourceCsv: "VC-FHE/BN254-Signatures/Users_Ratings.csv"
  },
  panels: {
    mos_variance_4: {
      video: "FeedTheDucks",
      pattern: "Pattern2_Uniform_Mid",
      n: 4,
      ratings: [3, 4, 4, 4],
      mean: 3,
      variance: 5,
      poorCount: 0,
      users: ["0001", "0002", "0003", "0004"],
      literatureTask:
        "Session MOS and opinion dispersion for one 360° video tiling configuration (ITU-T P.800-style aggregation over encrypted ACR scores)."
    },
    mos_variance_8: {
      video: "FeedTheDucks",
      pattern: "Pattern8_Checkerboard01",
      n: 8,
      ratings: [2, 2, 2, 2, 3, 2, 2, 2],
      mean: 2,
      variance: 0,
      poorCount: 7,
      users: ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008"],
      literatureTask:
        "Checkerboard tiling QoE panel: encrypted mean/variance detect low MOS and rating disagreement without revealing individual viewers."
    },
    poor_rating_sla_8: {
      video: "FeedTheDucks",
      pattern: "Pattern1_Uniform_Low",
      n: 8,
      ratings: [1, 1, 1, 2, 2, 2, 2, 1],
      mean: 1,
      variance: 1,
      poorCount: 8,
      users: ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008"],
      literatureTask:
        "Poor-experience SLA monitor: count encrypted ACR scores at or below 'fair' (≤2) for low-quality uniform tiling."
    }
  }
};

export function loadStav360Fixtures() {
  try {
    const raw = fs.readFileSync(STAV360_FIXTURES_JSON, "utf8");
    return JSON.parse(raw);
  } catch {
    return embeddedFixtures;
  }
}

export function stav360Panel(name) {
  const fixtures = loadStav360Fixtures();
  const panel = fixtures.panels?.[name];
  if (!panel) {
    throw new Error(`Unknown STAV360 panel: ${name}`);
  }
  return panel;
}

export function stav360WorkloadSpecs() {
  const p4 = stav360Panel("mos_variance_4");
  const p8 = stav360Panel("mos_variance_8");
  const sla = stav360Panel("poor_rating_sla_8");

  return [
    {
      id: "stav360_mos_variance",
      domain: "QoE / telecom",
      title: "STAV360 session MOS and variance (4-rating panel)",
      applicability: p4.literatureTask,
      limitation:
        "Integer floor mean/variance on a fixed 4-participant panel; full STAV360 sessions have ~27 participants and use the same deterministic formulas at larger N.",
      defaultManipulatedLeafIndex: 11,
      operation: {
        type: "mean_variance",
        values: p4.ratings,
        divisor: p4.n,
        meanThreshold: 2,
        varianceThreshold: 0,
        metadata: {
          dataset: "STAV360",
          video: p4.video,
          pattern: p4.pattern,
          users: p4.users
        }
      }
    },
    {
      id: "stav360_checkerboard_variance",
      domain: "QoE / 360° streaming",
      title: "STAV360 checkerboard tiling QoE dispersion (8-rating panel)",
      applicability: p8.literatureTask,
      limitation:
        "Demonstrates mean/variance over eight real ACR scores from Pattern8_Checkerboard01; thresholds are deployment parameters, not STAV360 ground truth.",
      defaultManipulatedLeafIndex: 11,
      operation: {
        type: "mean_variance",
        values: p8.ratings,
        divisor: p8.n,
        meanThreshold: 2,
        varianceThreshold: 0,
        metadata: {
          dataset: "STAV360",
          video: p8.video,
          pattern: p8.pattern,
          users: p8.users
        }
      }
    },
    {
      id: "stav360_poor_rating_sla",
      domain: "QoE / SLA monitoring",
      title: "STAV360 poor-experience rate (8-rating panel)",
      applicability: sla.literatureTask,
      limitation:
        "Counts poor scores (ACR ≤2) over eight encrypted ratings; SLA threshold is a policy parameter.",
      defaultManipulatedLeafIndex: 14,
      operation: {
        type: "poor_rating_sla",
        values: sla.ratings,
        poorThreshold: 2,
        slaThreshold: 5,
        metadata: {
          dataset: "STAV360",
          video: sla.video,
          pattern: sla.pattern,
          users: sla.users
        }
      }
    }
  ];
}
