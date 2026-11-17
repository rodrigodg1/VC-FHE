#!/usr/bin/env node
/**
 * Generate non-linear workload plans for the non-linear path
 * (fhe-pod: trace commitment -> PoD audit -> challenge -> bisection ->
 * objective leaf resolution over the micro-ISA; these generators emit the 14
 * scalar opcodes of the lowering table, and the contract's fifteenth
 * supported operation is the grouped ADD_CHAIN leaf).
 *
 * Each plan is a SEQUENTIAL transformation that is NOT reducible to a single
 * authorized linear combination of the inputs (it multiplies, compares,
 * divides or selects on data-dependent intermediates). Plans are emitted as
 * ground-truth traces: every leaf carries {opcode, lhs, rhs, claimed} with the
 * honest claimed value, in the same shape consumed by
 * fhe-pod/scripts/application-lowering.mjs. Corrupted variants for dispute
 * experiments are produced downstream by the existing fhe-pod tooling.
 *
 * Usage (from VC-FHE/datasets):
 *   node prepare/prepare-nonlinear-inputs.mjs [--dataset all|5gqoera|stav360|p1203]
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadTable, firstExisting, quantizeMilli, intStats, writeJson,
  solveLinearSystem, Trace
} from "./lib.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const datasetsDir = path.resolve(scriptDir, "..");
const vcfheDir = path.resolve(datasetsDir, "..");
const outPath = path.join(datasetsDir, "outputs", "nonlinear-inputs.json");

const wanted = (process.argv.find((a) => a.startsWith("--dataset="))?.split("=")[1]
  ?? (process.argv.includes("--dataset") ? process.argv[process.argv.indexOf("--dataset") + 1] : "all"));

const workloads = [];
const skipped = [];

function pushWorkload(id, dataset, description, inputs, trace, expected, extra = {}) {
  workloads.push({
    workload_id: id,
    dataset,
    description,
    inputs,
    leaf_count: trace.leaves.length,
    leaves: trace.leaves,
    expected,
    nonlinearity:
      extra.nonlinearity
      ?? "contains MUL/DIV/comparison over data-dependent intermediates; not expressible as one authorized linear combination of the encrypted inputs",
    ...extra
  });
}

/* ---------------------------------------------------------------- */
/* STAV360: opinion-dispersion (variance) panel                       */
/* ---------------------------------------------------------------- */
function stav360Variance() {
  const csv = firstExisting([
    path.join(datasetsDir, "raw", "stav360", "Raw_Ratings.csv"),
    path.join(vcfheDir, "BN254-Signatures", "Users_Ratings.csv")
  ]);
  if (!csv) { skipped.push("stav360"); return; }
  const { rows } = loadTable(csv);
  const panel = rows
    .filter((r) => r.video_title === "FeedTheDucks"
      && r.video_tiling_pattern === "Pattern8_Checkerboard01" && r.rating !== "")
    .sort((a, b) => a.user.localeCompare(b.user))
    .slice(0, 8)
    .map((r) => ({ user: r.user, rating: Math.round(Number.parseFloat(r.rating)) }));
  const values = panel.map((r) => r.rating);
  // Centi-scale (x100) before squaring so integer floor division does not
  // erase the dispersion of a nearly-unanimous panel.
  const centi = values.map((v) => v * 100);
  const s = intStats(centi);

  const t = new Trace();
  const scaled = values.map((v) => t.emit("MUL", v, 100, "centi-scale"));
  const sum = t.addChain(scaled, "sum of centi-ratings");
  const squares = scaled.map((v) => t.emit("MUL", v, v, "square"));
  const sumsq = t.addChain(squares, "sum of squares");
  const mean = t.emit("DIV", sum, values.length, "mean = floor(sum/n)");
  const ex2 = t.emit("DIV", sumsq, values.length, "E[x^2]");
  const mean2 = t.emit("MUL", mean, mean, "mean^2");
  const guard = t.emit("MIN", mean2, ex2, "underflow guard");
  const variance = t.emit("SUB", ex2, guard, "variance (centi^2 units)");
  const disagreement = t.emit("GT", variance, 0, "disagreement flag");

  pushWorkload(
    "stav360_checkerboard_variance_v2",
    "STAV360",
    "Opinion dispersion over the fixed 8-user checkerboard panel: centi-scaled integer variance via E[x^2] - mean^2, then a disagreement flag.",
    { owners: panel.map((r) => r.user), ratings: values, scale: "ratings x100 in-trace" },
    t,
    { mean_centi: s.mean, variance_centi2: Math.max(0, s.variance), disagreement },
    { micro_ops_used: ["MUL", "ADD", "DIV", "MIN", "SUB", "GT"] }
  );
}

/* ---------------------------------------------------------------- */
/* 5G-QoERA: bitrate-ladder advisor (max-MOS + highest safe rung)     */
/* ---------------------------------------------------------------- */
function qoeraLoad() {
  const bs1 = firstExisting([
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_1_Driver_PRB_10.tsv"),
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_1_Driver_PRB_10.csv"),
    path.join(vcfheDir, "data", "MOS_BS_1_Driver_PRB_10.csv")
  ]);
  if (!bs1) return null;
  return loadTable(bs1);
}

function qoeraLadder(table) {
  const mosCols = table.header.filter((h) => h.startsWith("MOS_"));
  // ladder sorted by numeric bitrate ascending
  const ladder = mosCols
    .map((c) => ({ col: c, kbps: Number.parseInt(c.replace("MOS_", "").replace("kbps", ""), 10) }))
    .sort((a, b) => a.kbps - b.kbps);
  const row = table.rows.find((r) => r.User_ID && r.MOS_3000kbps);
  return { ladder, row };
}

function qoeraLadderAdvisor() {
  const table = qoeraLoad();
  if (!table) { skipped.push("5gqoera"); return; }
  const { ladder, row } = qoeraLadder(table);
  const mosMilli = ladder.map((l) => quantizeMilli(row[l.col]));
  const THRESHOLD = 2500; // milli-MOS "fair or better" target, deployment parameter

  const t = new Trace();
  // (a) best achievable milli-MOS across the ladder (chain of GT-selects)
  let best = mosMilli[0];
  for (let i = 1; i < mosMilli.length; i += 1) best = t.max(best, mosMilli[i], `max rung ${i}`);
  // (b) highest rung index whose MOS clears the threshold:
  //     ok_i = [mos_i > THRESHOLD-1]; idx_i = ok_i * (i+1); best_idx = max_i idx_i
  let bestIdx = 0;
  for (let i = 0; i < mosMilli.length; i += 1) {
    const ok = t.emit("GT", mosMilli[i], THRESHOLD - 1, `rung ${i} clears threshold`);
    const idx = t.emit("MUL", ok, i + 1);
    bestIdx = i === 0 ? idx : t.max(bestIdx, idx, `best rung after ${i}`);
  }
  const expectedBest = Math.max(...mosMilli);
  let expectedIdx = 0;
  mosMilli.forEach((m, i) => { if (m >= THRESHOLD) expectedIdx = Math.max(expectedIdx, i + 1); });

  pushWorkload(
    "qoera_bitrate_ladder_advisor",
    "5G-QoERA",
    `Encrypted bitrate-ladder advisor for one user sample: best achievable milli-MOS over the ${mosMilli.length}-rung ladder and the highest rung with MOS >= ${THRESHOLD / 1000} (1-based; 0 = none). Data-dependent argmax: a decision rule, not an aggregation.`,
    {
      user: row.User_ID,
      ladder: ladder.map((l) => l.kbps),
      mos_milli: mosMilli,
      threshold_milli: THRESHOLD
    },
    t,
    { best_mos_milli: expectedBest, best_safe_rung_1based: expectedIdx },
    { micro_ops_used: ["GT", "MUL", "SUB", "ADD"] }
  );
}

/* ---------------------------------------------------------------- */
/* 5G-QoERA: windowed MOS degradation alarm on one user's timeline   */
/* ---------------------------------------------------------------- */
function qoeraDegradationAlarm() {
  const table = qoeraLoad();
  if (!table) { return; }
  const W = 8;
  const DROP = 200; // milli-MOS mean-drop threshold used below
  // Fixed, recorded rule: the first user (numeric order) with >= 2W valid
  // samples whose two windows actually show a mean drop >= DROP (so the
  // honest trace raises the alarm); fallback: first user with >= 2W samples.
  const byUser = new Map();
  for (const r of table.rows) {
    if (!r.User_ID || !r.MOS_3000kbps) continue;
    if (!byUser.has(r.User_ID)) byUser.set(r.User_ID, []);
    byUser.get(r.User_ID).push(quantizeMilli(r.MOS_3000kbps));
  }
  const ordered = [...byUser.keys()].sort((a, b) => Number(a) - Number(b))
    .filter((u) => byUser.get(u).length >= 2 * W);
  const drops = (u) => {
    const s = byUser.get(u).slice(0, 2 * W);
    const a = s.slice(0, W).reduce((x, y) => x + y, 0);
    const b = s.slice(W).reduce((x, y) => x + y, 0);
    return a - b;
  };
  const uid = ordered.find((u) => drops(u) >= DROP * W) ?? ordered[0];
  if (!uid) { skipped.push("5gqoera degradation (no user with enough samples)"); return; }
  const series = byUser.get(uid).slice(0, 2 * W);
  const w1 = series.slice(0, W);
  const w2 = series.slice(W, 2 * W);
  const DROP_MILLI = DROP; // mean drop of 0.2 MOS triggers the alarm

  const t = new Trace();
  const s1 = t.addChain(w1, "window 1 sum");
  const s2 = t.addChain(w2, "window 2 sum");
  const degraded = t.emit("GT", s1, s2, "did the mean drop at all?");
  const lo = t.emit("MIN", s1, s2);
  const drop = t.emit("SUB", s1, lo, "guarded drop (0 when improving)");
  const alarm = t.emit("GT", drop, DROP_MILLI * W - 1, "alarm: mean drop >= 0.2 MOS");
  const alarmBit = t.emit("BITAND", degraded, alarm, "final alarm bit");

  const sum1 = w1.reduce((a, b) => a + b, 0);
  const sum2 = w2.reduce((a, b) => a + b, 0);
  pushWorkload(
    "qoera_mos_degradation_alarm_v2",
    "5G-QoERA",
    `Sequential degradation alarm on user ${uid}'s first ${2 * W} samples at 3000 kbps: compare two ${W}-sample windows and raise an alarm when the mean milli-MOS drops by >= ${DROP_MILLI}.`,
    { user: uid, window: W, window1_milli: w1, window2_milli: w2, drop_threshold_milli: DROP_MILLI },
    t,
    {
      sum_window1: sum1, sum_window2: sum2,
      alarm: sum1 > sum2 && (sum1 - sum2) >= DROP_MILLI * W ? 1 : 0
    },
    { micro_ops_used: ["ADD", "GT", "MIN", "SUB", "BITAND"] }
  );
}

/* ---------------------------------------------------------------- */
/* 5G-QoERA: regulatory permille compliance over a session sample    */
/* ---------------------------------------------------------------- */
function qoeraRegulatoryCompliance() {
  const table = qoeraLoad();
  if (!table) { return; }
  const N = 16;
  const valid = table.rows.filter((r) => r.User_ID && r.MOS_3000kbps);
  const stride = Math.floor(valid.length / N);
  const sample = Array.from({ length: N }, (_, i) => valid[i * stride]);
  const mos = sample.map((r) => quantizeMilli(r.MOS_3000kbps));
  const POOR = 2000;      // milli-MOS below this is a poor session
  const TARGET = 950;     // permille of good sessions required

  const t = new Trace();
  const goodBits = mos.map((m, i) => t.emit("GT", m, POOR - 1, `session ${i} good?`));
  const goodCount = t.addChain(goodBits, "good-session count");
  const scaled = t.emit("MUL", goodCount, 1000, "count * 1000");
  const permille = t.emit("DIV", scaled, N, "good permille");
  const violation = t.emit("LT", permille, TARGET, "below regulatory target?");

  const expectedGood = mos.filter((m) => m >= POOR).length;
  const expectedPermille = Math.floor((expectedGood * 1000) / N);
  pushWorkload(
    "qoera_regulatory_compliance_v2",
    "5G-QoERA",
    `Regulatory compliance monitor over a deterministic stride sample of ${N} sessions: good-session permille vs a ${TARGET} permille target (poor = milli-MOS < ${POOR}). In-trace thresholding variant of the linear-path indicator query.`,
    {
      selection: `stride ${stride} over ${valid.length} valid rows`,
      sessions: sample.map((r) => r.User_ID),
      mos_milli: mos, poor_threshold_milli: POOR, target_permille: TARGET
    },
    t,
    { good_count: expectedGood, good_permille: expectedPermille, violation: expectedPermille < TARGET ? 1 : 0 },
    { micro_ops_used: ["GT", "ADD", "MUL", "DIV", "LT"] }
  );
}

/* ---------------------------------------------------------------- */
/* P.1203-inspired fixed-point curve: bitrate -> quality mapping      */
/* ---------------------------------------------------------------- */
function p1203CurveEvaluation() {
  const mosCsv = firstExisting([
    path.join(datasetsDir, "raw", "p1203-open-dataset", "subjective_scores", "mos.csv")
  ]);
  const featDir = firstExisting([
    path.join(datasetsDir, "raw", "p1203-open-dataset", "features", "features_mode0.csv")
  ]);
  if (!mosCsv || !featDir) { skipped.push("p1203"); return; }

  const { rows: mosRows } = loadTable(mosCsv);
  const { rows: featRows } = loadTable(featDir);
  const mosByPvs = new Map(mosRows.filter((r) => r.context === "pc")
    .map((r) => [r.pvs_id, Number.parseFloat(r.mos)]));
  const byPvs = new Map();
  for (const r of featRows) {
    const pvs = r.pvs_id;
    if (!mosByPvs.has(pvs)) continue;
    if (!byPvs.has(pvs)) byPvs.set(pvs, []);
    byPvs.get(pvs).push(Number.parseFloat(r.bitrate_kbps_target));
  }
  // quadratic least-squares fit: mos_milli ~ c0 + c1*x + c2*x^2, x = kbps/100
  const pts = [...byPvs.entries()].map(([pvs, brs]) => ({
    x: (brs.reduce((a, b) => a + b, 0) / brs.length) / 100,
    y: mosByPvs.get(pvs) * 1000
  }));
  const S = (fn) => pts.reduce((a, p) => a + fn(p), 0);
  const A = [
    [pts.length, S((p) => p.x), S((p) => p.x * p.x)],
    [S((p) => p.x), S((p) => p.x * p.x), S((p) => p.x ** 3)],
    [S((p) => p.x * p.x), S((p) => p.x ** 3), S((p) => p.x ** 4)]
  ];
  const b = [S((p) => p.y), S((p) => p.x * p.y), S((p) => p.x * p.x * p.y)];
  const [c0, c1, c2] = solveLinearSystem(A, b);

  // Fixed-point encoding: SCALE = 2^8; negative curvature is handled by
  // computing positive and negative terms separately and using a guarded SUB.
  const SHIFT = 8;
  const SCALE = 2 ** SHIFT;
  const q0 = Math.round(Math.max(c0, 0) * SCALE);
  const q1 = Math.round(Math.abs(c1) * SCALE);
  const q2 = Math.round(Math.abs(c2) * SCALE);
  const sign1 = c1 >= 0 ? 1 : -1;
  const sign2 = c2 >= 0 ? 1 : -1;

  const x = Math.round(pts[Math.floor(pts.length / 2)].x); // representative input
  const t = new Trace();
  const term1 = t.emit("MUL", q1, x, "c1 * x (scaled)");
  const x2 = t.emit("MUL", x, x, "x^2");
  const term2 = t.emit("MUL", q2, x2, "c2 * x^2 (scaled)");
  const pos = sign1 > 0 ? t.emit("ADD", q0, term1, "positive terms") : q0;
  const posAll = sign2 > 0 ? t.emit("ADD", pos, term2) : pos;
  const negAll = t.addChain([
    sign1 < 0 ? term1 : 0,
    sign2 < 0 ? term2 : 0
  ], "negative terms");
  const floor = t.emit("MIN", negAll, posAll, "guard against underflow");
  const diff = t.emit("SUB", posAll, floor, "polynomial value (scaled)");
  const milli = t.emit("SHR", diff, SHIFT, "descale by 2^8");
  const capped = t.emit("MIN", milli, 5000, "cap at MOS 5.000");

  const clearPoly = Math.max(0, c0 + c1 * x + c2 * x * x);
  pushWorkload(
    "p1203_bitrate_quality_curve",
    "ITU-T P.1203 open dataset",
    "Fixed-point evaluation of a quadratic bitrate->milli-MOS curve fitted on the P.1203 pc-context databases (quantized coefficients, guarded subtraction, SHR descale, MOS cap). Demonstrates a smooth non-linear QoE mapping in the micro-ISA, in the spirit of the exponential/logistic stages of standardized QoE models.",
    {
      fit: { points: pts.length, c0, c1, c2, x_unit: "kbps/100" },
      quantized: { shift: SHIFT, q0, q1, q2, sign1, sign2 },
      input_x: x
    },
    t,
    { clear_poly_milli: Math.round(clearPoly), trace_result_milli: capped },
    {
      micro_ops_used: ["MUL", "ADD", "MIN", "SUB", "SHR"],
      note: "coefficients are public model parameters; only the bitrate input and the result are encrypted"
    }
  );
}

if (wanted === "all" || wanted === "stav360") stav360Variance();
if (wanted === "all" || wanted === "5gqoera") {
  qoeraLadderAdvisor();
  qoeraDegradationAlarm();
  qoeraRegulatoryCompliance();
}
if (wanted === "all" || wanted === "p1203") p1203CurveEvaluation();

writeJson(outPath, {
  generator: "datasets/prepare/prepare-nonlinear-inputs.mjs",
  micro_isa: "fhe-pod application-lowering v1 (MUL SHR CAST_U8 MIN BITAND ADD SUB DIV MOD EQ LT GT BITOR BITXOR)",
  workloads,
  skipped
});
for (const w of workloads) {
  console.log(`  ${w.workload_id}: ${w.leaf_count} leaves, expected=${JSON.stringify(w.expected)}`);
}
if (skipped.length) console.log(`skipped: ${skipped.join("; ")}`);
