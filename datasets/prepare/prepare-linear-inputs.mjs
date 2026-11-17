#!/usr/bin/env node
/**
 * Generate authorized linear-query fixtures for the linear path
 * (MKLHS/BN254 output-bound linear verification).
 *
 * Every fixture is a pre-authorized query: a linear aggregation
 * A_out = sum_i w_i * c_i over a FIXED scope (owner set, selection rule and
 * weights fixed before any ciphertext is admitted), matching the multi-key
 * linear path: per-index owner enrollment, per-record BLS admission,
 * all-N admission before the O(1) bound result submission, and one distinct
 * tag per (dataset, scope, operation).
 *
 * Usage (from VC-FHE/datasets):
 *   node prepare/prepare-linear-inputs.mjs [--dataset all|5gqoera|stav360|p1203]
 *
 * Inputs are looked up in datasets/raw/ first, then in the legacy repo
 * locations (VC-FHE/data, VC-FHE/BN254-Signatures). Missing datasets are
 * skipped with a notice; nothing is downloaded here.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadTable, firstExisting, quantizeMilli, intStats, intSum, writeJson
} from "./lib.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const datasetsDir = path.resolve(scriptDir, "..");
const vcfheDir = path.resolve(datasetsDir, "..");
const outPath = path.join(datasetsDir, "outputs", "linear-inputs.json");

const wanted = (process.argv.find((a) => a.startsWith("--dataset="))?.split("=")[1]
  ?? (process.argv.includes("--dataset") ? process.argv[process.argv.indexOf("--dataset") + 1] : "all"));

const queries = [];
const skipped = [];

/* ---------------------------------------------------------------- */
/* 5G-QoERA (drive-test corpus already used by the evaluation)       */
/* ---------------------------------------------------------------- */
function prepare5gqoera() {
  const bs1 = firstExisting([
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_1_Driver_PRB_10.tsv"),
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_1_Driver_PRB_10.csv"),
    path.join(vcfheDir, "data", "MOS_BS_1_Driver_PRB_10.csv")
  ]);
  const bs4 = firstExisting([
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_4_Driver_PRB_10.tsv"),
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_4_Driver_PRB_10.csv"),
    path.join(vcfheDir, "data", "MOS_BS_4_Driver_PRB_10.csv")
  ]);
  if (!bs1 || !bs4) {
    skipped.push("5gqoera (run download/download-5gqoera.mjs or keep VC-FHE/data/*.csv in place)");
    return;
  }

  /** First valid sample of each of the first n users (sorted by numeric id). */
  function panel(filePath, n) {
    const { rows } = loadTable(filePath);
    const byUser = new Map();
    for (const row of rows) {
      const uid = row.User_ID;
      const mos = row.MOS_3000kbps;
      if (!uid || !mos) continue;
      if (!byUser.has(uid)) byUser.set(uid, row); // first sample = fixed rule
    }
    const users = [...byUser.keys()].sort((a, b) => Number(a) - Number(b)).slice(0, n);
    return users.map((u) => ({
      user: u,
      mosMilli: quantizeMilli(byUser.get(u).MOS_3000kbps),
      tputMilli: quantizeMilli(byUser.get(u).Tput)
    }));
  }

  const N = 16;
  const p1 = panel(bs1, N);
  const p4 = panel(bs4, N);

  {
    const values = p1.map((r) => r.mosMilli);
    const s = intStats(values);
    queries.push({
      query_id: "qoera_bs1_mos_mean",
      dataset: "5G-QoERA",
      description: "Mean per-user milli-MOS at the 3000 kbps rung, cell BS_1 / PRB_10.",
      scope: {
        file: "MOS_BS_1_Driver_PRB_10", selection: "first sample of each user",
        owners: "first 16 users by numeric User_ID", column: "MOS_3000kbps", unit: "milli-MOS"
      },
      owners: p1.map((r) => r.user),
      values_milli: values,
      weights: values.map(() => 1),
      operation: "SUM",
      expected: { aggregate: s.sum, n: s.n, mean_milli: s.mean },
      linear_path: {
        statement: "A_out = sum_i c_i (uniform authorized weights)",
        tag_suggestion: "5gqoera/bs1-prb10/mos3000/sum/v1",
        all_n_admission: true
      }
    });
  }

  {
    const v1 = p1.map((r) => r.mosMilli);
    const v4 = p4.map((r) => r.mosMilli);
    const s1 = intSum(v1);
    const s4 = intSum(v4);
    const hi = Math.max(s1, s4);
    const lo = Math.min(s1, s4);
    queries.push({
      query_id: "qoera_bs1_vs_bs4_mos_gap",
      dataset: "5G-QoERA",
      description:
        "Authorized SUB query: difference between the BS_1 and BS_4 16-user milli-MOS sums (same PRB budget), i.e. an inter-cell QoE gap.",
      scope: {
        files: ["MOS_BS_1_Driver_PRB_10", "MOS_BS_4_Driver_PRB_10"],
        owners: "first 16 users by numeric User_ID in each cell",
        column: "MOS_3000kbps", unit: "milli-MOS",
        note: "operand order fixed at authorization time so the unsigned result is well defined"
      },
      owners: { bs1: p1.map((r) => r.user), bs4: p4.map((r) => r.user) },
      values_milli: { bs1: v1, bs4: v4 },
      operation: "SUB",
      expected: { sum_bs1: s1, sum_bs4: s4, gap: hi - lo, larger: s1 >= s4 ? "bs1" : "bs4" },
      linear_path: {
        statement: "A_out = sum_i c_i^{(hi)} - sum_i c_i^{(lo)}",
        tag_suggestion: "5gqoera/bs1-bs4-prb10/mos3000/sub/v1",
        all_n_admission: true
      }
    });
  }

  {
    // Owner-side indicator bits keep the AUTHORIZED query linear: each owner
    // encrypts poor = [milliMOS < 2000] locally; the query is a plain SUM.
    const bits = p1.map((r) => (r.mosMilli < 2000 ? 1 : 0));
    queries.push({
      query_id: "qoera_bs1_poor_count",
      dataset: "5G-QoERA",
      description:
        "Poor-experience compliance count: owners encrypt the indicator [MOS < 2.0] and the authorized query is the linear SUM of indicator bits.",
      scope: {
        file: "MOS_BS_1_Driver_PRB_10", owners: "first 16 users by numeric User_ID",
        indicator: "MOS_3000kbps < 2.000 (computed owner-side before encryption)"
      },
      owners: p1.map((r) => r.user),
      values: bits,
      weights: bits.map(() => 1),
      operation: "SUM",
      expected: { poor_count: intSum(bits), n: bits.length },
      linear_path: {
        statement: "A_out = sum_i b_i, b_i in {0,1}",
        tag_suggestion: "5gqoera/bs1-prb10/poor-indicator/sum/v1",
        all_n_admission: true,
        note: "the data-dependent threshold lives at the owner; the verified computation stays linear"
      }
    });
  }
}

/* ---------------------------------------------------------------- */
/* STAV360 (legacy subjective panel; see README.md for status)   */
/* ---------------------------------------------------------------- */
function prepareStav360() {
  const csv = firstExisting([
    path.join(datasetsDir, "raw", "stav360", "Raw_Ratings.csv"),
    path.join(vcfheDir, "BN254-Signatures", "Users_Ratings.csv")
  ]);
  if (!csv) {
    skipped.push("stav360 (run download/download-stav360.mjs)");
    return;
  }
  const { rows } = loadTable(csv);
  const ratings = rows
    .filter((r) => r.rating !== "")
    .map((r) => ({
      user: r.user,
      video: r.video_title,
      pattern: r.video_tiling_pattern,
      rating: Math.round(Number.parseFloat(r.rating))
    }));

  function panel(video, pattern, n) {
    return ratings
      .filter((r) => r.video === video && r.pattern === pattern)
      .sort((a, b) => a.user.localeCompare(b.user))
      .slice(0, n);
  }

  const p = panel("FeedTheDucks", "Pattern2_Uniform_Mid", 16);
  const values = p.map((r) => r.rating);
  const s = intStats(values);
  queries.push({
    query_id: "stav360_session_mos_sum",
    dataset: "STAV360",
    description:
      "Session ACR sum over the fixed 16-user panel (FeedTheDucks / Pattern2_Uniform_Mid). Matches the existing linear QoE case (expected sum 52).",
    scope: {
      video: "FeedTheDucks", pattern: "Pattern2_Uniform_Mid",
      owners: "first 16 users by id", scale: "ACR 1-5 integers"
    },
    owners: p.map((r) => r.user),
    values,
    weights: values.map(() => 1),
    operation: "SUM",
    expected: { aggregate: s.sum, n: s.n, mean_floor: s.mean },
    linear_path: {
      statement: "A_out = sum_i c_i",
      tag_suggestion: "stav360/feedtheducks-p2/acr/sum/v1",
      all_n_admission: true
    }
  });

  const poorPanel = panel("FeedTheDucks", "Pattern1_Uniform_Low", 8);
  const bits = poorPanel.map((r) => (r.rating <= 2 ? 1 : 0));
  queries.push({
    query_id: "stav360_poor_indicator_count",
    dataset: "STAV360",
    description:
      "Poor-rating SLA count via owner-side indicator bits [ACR <= 2] over the fixed 8-user low-quality panel.",
    scope: { video: "FeedTheDucks", pattern: "Pattern1_Uniform_Low", owners: "first 8 users by id" },
    owners: poorPanel.map((r) => r.user),
    values: bits,
    weights: bits.map(() => 1),
    operation: "SUM",
    expected: { poor_count: intSum(bits), n: bits.length },
    linear_path: {
      statement: "A_out = sum_i b_i, b_i in {0,1}",
      tag_suggestion: "stav360/feedtheducks-p1/poor-indicator/sum/v1",
      all_n_admission: true
    }
  });
}

/* ---------------------------------------------------------------- */
/* ITU-T P.1203 open dataset (per-subject ratings, research license) */
/* ---------------------------------------------------------------- */
function prepareP1203() {
  const ratingsCsv = firstExisting([
    path.join(datasetsDir, "raw", "p1203-open-dataset", "subjective_scores", "ratings.csv")
  ]);
  const mosCsv = firstExisting([
    path.join(datasetsDir, "raw", "p1203-open-dataset", "subjective_scores", "mos.csv")
  ]);
  if (!ratingsCsv || !mosCsv) {
    skipped.push("p1203 (run download/download-p1203-open-dataset.mjs)");
    return;
  }
  const { rows: ratingRows } = loadTable(ratingsCsv);
  const { rows: mosRows } = loadTable(mosCsv);

  // Fixed, recorded rule: the PVS with the LOWEST pc-context MOS (ties broken
  // by pvs_id order) so the poor-rating query is non-trivial.
  const pcMos = mosRows
    .filter((r) => r.context === "pc")
    .map((r) => ({ pvs: r.pvs_id, mos: Number.parseFloat(r.mos) }))
    .sort((a, b) => a.mos - b.mos || a.pvs.localeCompare(b.pvs));
  const target = pcMos[0];

  const subjectRatings = ratingRows
    .filter((r) => r.pvs_id === target.pvs && r.context === "pc")
    .sort((a, b) => a.subject.localeCompare(b.subject, undefined, { numeric: true }))
    .map((r) => ({ subject: r.subject, rating: Number.parseInt(r.rating, 10) }));

  const values = subjectRatings.map((r) => r.rating);
  const s = intStats(values);
  queries.push({
    query_id: "p1203_worst_pvs_rating_sum",
    dataset: "ITU-T P.1203 open dataset",
    description:
      `Per-subject ACR sum for the lowest-MOS pc-context PVS (${target.pvs}, MOS ${target.mos}).`,
    scope: {
      pvs_id: target.pvs, context: "pc",
      selection_rule: "PVS with minimum pc MOS in subjective_scores/mos.csv",
      owners: "all subjects who rated the PVS", scale: "ACR 1-5 integers"
    },
    owners: subjectRatings.map((r) => r.subject),
    values,
    weights: values.map(() => 1),
    operation: "SUM",
    expected: { aggregate: s.sum, n: s.n, mean_floor: s.mean },
    linear_path: {
      statement: "A_out = sum_i c_i",
      tag_suggestion: `p1203/${target.pvs.toLowerCase()}/acr/sum/v1`,
      all_n_admission: true
    }
  });

  const bits = values.map((v) => (v <= 2 ? 1 : 0));
  queries.push({
    query_id: "p1203_worst_pvs_poor_count",
    dataset: "ITU-T P.1203 open dataset",
    description: "Poor-rating count via owner-side indicator bits [ACR <= 2] over the same fixed PVS panel.",
    scope: { pvs_id: target.pvs, context: "pc", owners: "same panel as p1203_worst_pvs_rating_sum" },
    owners: subjectRatings.map((r) => r.subject),
    values: bits,
    weights: bits.map(() => 1),
    operation: "SUM",
    expected: { poor_count: intSum(bits), n: bits.length },
    linear_path: {
      statement: "A_out = sum_i b_i, b_i in {0,1}",
      tag_suggestion: `p1203/${target.pvs.toLowerCase()}/poor-indicator/sum/v1`,
      all_n_admission: true
    }
  });
}

if (wanted === "all" || wanted === "5gqoera") prepare5gqoera();
if (wanted === "all" || wanted === "stav360") prepareStav360();
if (wanted === "all" || wanted === "p1203") prepareP1203();

writeJson(outPath, {
  generator: "datasets/prepare/prepare-linear-inputs.mjs",
  contract_model:
    "MKLHS linear path: per-index enrollment, per-record BLS admission, all-N admission, O(1) bound submission; one tag per (dataset, scope, operation)",
  queries,
  skipped
});
for (const q of queries) console.log(`  ${q.query_id}: n=${q.owners.length ?? "-"} expected=${JSON.stringify(q.expected)}`);
if (skipped.length) console.log(`skipped: ${skipped.join("; ")}`);
