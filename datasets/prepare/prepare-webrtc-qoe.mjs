#!/usr/bin/env node
/**
 * WebRTC-QoE showcase: reader-friendly statistics over biometric-grade
 * sensitive data, expressed in the two computation paths of the architecture.
 *
 * Dataset: WebRTC-QoE (Univ. of Cagliari), Zenodo 15836614, CC BY 4.0.
 *   - 20 subjects x 15 network conditions, 300 per-subject ACR scores;
 *   - OpenFace facial features per frame (gaze directions, eye landmarks,
 *     action units) and openSMILE speech features.
 * Citations: Bingol et al., ACM TOMM 2024, doi:10.1145/3638251 (QoE
 * estimation from facial and speech features on this data); Bingol et al.,
 * Computer Networks 2024, doi:10.1016/j.comnet.2024.110356 (dataset experiment).
 * Sensitivity evidence: gaze reveals identity and personal attributes
 * (Kroeger et al., IFIP 2020, doi:10.1007/978-3-030-42504-3_15); face/eye/
 * head features re-identify users (arXiv:2507.11138).
 *
 * The subjects' opinions and facial behavior are the sensitive assets; the
 * evaluator learns only authorized aggregates (linear path) or verdict bits
 * of committed traces (non-linear path).
 *
 * Usage (from VC-FHE/datasets):
 *   node prepare/prepare-webrtc-qoe.mjs [--raw raw/webrtc-qoe] [--out outputs/webrtcqoe-inputs.json]
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  argValue, loadWebrtcSubjective, findFacialCsvs, loadTable,
  intSum, intStats, writeJson, Trace
} from "./lib.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const datasetsDir = path.resolve(scriptDir, "..");
const rawDir = path.resolve(datasetsDir, argValue("raw", path.join("raw", "webrtc-qoe")));
const outPath = path.resolve(datasetsDir, argValue("out", path.join("outputs", "webrtcqoe-inputs.json")));

const CITATIONS = [
  "WebRTC-QoE dataset: Zenodo 10.5281/zenodo.15836614 (record 15836614), CC BY 4.0",
  "Dataset experiment: Bingol et al., Computer Networks 2024, doi:10.1016/j.comnet.2024.110356",
  "Prior ML use (QoE from facial+speech features): Bingol et al., ACM TOMM 2024, doi:10.1145/3638251",
  "Gaze sensitivity: Kroeger et al., IFIP AICT 576, 2020, doi:10.1007/978-3-030-42504-3_15"
];

const sub = loadWebrtcSubjective(rawDir);
if (!sub) {
  console.error(`no WebRTC-QoE subjective-scores CSV found under ${rawDir}.`);
  console.error("run: node download/download-webrtc-qoe.mjs --yes  (and extract the zip)");
  process.exit(1);
}

/* Fixed, recorded condition-selection rule. */
const byTc = new Map();
for (const s of sub.sessions) {
  if (!byTc.has(s.tc)) byTc.set(s.tc, []);
  byTc.get(s.tc).push(s);
}
const severity = (list) => list[0].delayMs + list[0].jitterMs + 20 * list[0].plrPct;
const tcs = [...byTc.entries()].map(([tc, list]) => ({ tc, list, sev: severity(list) }));
tcs.sort((a, b) => a.sev - b.sev || String(a.tc).localeCompare(String(b.tc)));
const clean = tcs[0];
const worst = tcs[tcs.length - 1];
const orderedUsers = (list) => [...list].sort((a, b) =>
  a.user.localeCompare(b.user, undefined, { numeric: true }));

const linearQueries = [];
const workloads = [];

/* ---------------- linear path: authorized queries ---------------- */
{
  const rows = orderedUsers(clean.list);
  const values = rows.map((r) => r.score);
  const s = intStats(values);
  linearQueries.push({
    query_id: "webrtc_clean_acr_sum",
    dataset: "WebRTC-QoE",
    description:
      `Per-subject ACR sum for the least-impaired condition (${clean.tc}: delay ${rows[0].delayMs} ms, jitter ${rows[0].jitterMs} ms, loss ${rows[0].plrPct}%).`,
    scope: {
      condition: clean.tc,
      selection_rule: "condition minimizing delay + jitter + 20*plr",
      owners: "all subjects, ordered by user id"
    },
    owners: rows.map((r) => r.user),
    values,
    weights: values.map(() => 1),
    operation: "SUM",
    expected: { aggregate: s.sum, n: s.n, mean_floor: s.mean },
    linear_path: {
      statement: "A_out = sum_i c_i",
      tag_suggestion: `webrtcqoe/${String(clean.tc).toLowerCase()}/acr/sum/v1`,
      all_n_admission: true
    }
  });

  const wRows = orderedUsers(worst.list);
  const wValues = wRows.map((r) => r.score);
  const sClean = intSum(values);
  const sWorst = intSum(wValues);
  const hi = Math.max(sClean, sWorst);
  const lo = Math.min(sClean, sWorst);
  linearQueries.push({
    query_id: "webrtc_impairment_acr_gap",
    dataset: "WebRTC-QoE",
    description:
      `Authorized SUB query: aggregate QoE damage of network impairments = ACR sum at ${clean.tc} minus ACR sum at ${worst.tc} (delay ${wRows[0].delayMs} ms, jitter ${wRows[0].jitterMs} ms, loss ${wRows[0].plrPct}%).`,
    scope: {
      conditions: [clean.tc, worst.tc],
      owners: "all subjects, ordered by user id, same panel in both scopes",
      note: "operand order fixed at authorization time"
    },
    owners: { clean: rows.map((r) => r.user), worst: wRows.map((r) => r.user) },
    values_by_scope: { clean: values, worst: wValues },
    operation: "SUB",
    expected: { sum_clean: sClean, sum_worst: sWorst, gap: hi - lo, larger: sClean >= sWorst ? "clean" : "worst" },
    linear_path: {
      statement: "A_out = sum_i c_i^{(clean)} - sum_i c_i^{(worst)}",
      tag_suggestion: "webrtcqoe/impairment-gap/acr/sub/v1",
      all_n_admission: true
    }
  });

  const bits = wValues.map((v) => (v <= 2 ? 1 : 0));
  linearQueries.push({
    query_id: "webrtc_worst_poor_count",
    dataset: "WebRTC-QoE",
    description:
      `Poor-call count at ${worst.tc}: owners encrypt the indicator [ACR <= 2]; the authorized query is the linear SUM of indicator bits.`,
    scope: { condition: worst.tc, owners: "all subjects, ordered by user id" },
    owners: wRows.map((r) => r.user),
    values: bits,
    weights: bits.map(() => 1),
    operation: "SUM",
    expected: { poor_count: intSum(bits), n: bits.length },
    linear_path: {
      statement: "A_out = sum_i b_i, b_i in {0,1}",
      tag_suggestion: "webrtcqoe/worst-poor-indicator/sum/v1",
      all_n_admission: true
    }
  });
}

/* ---------------- non-linear path: sequential workloads ---------------- */
{
  // Opinion dispersion at the worst condition (centi-scaled variance).
  const rows = orderedUsers(worst.list);
  const values = rows.map((r) => r.score);
  const centi = values.map((v) => v * 100);
  const s = intStats(centi);
  const t = new Trace();
  const scaled = values.map((v) => t.emit("MUL", v, 100, "centi-scale"));
  const sum = t.addChain(scaled, "sum of centi-ACR");
  const squares = scaled.map((v) => t.emit("MUL", v, v, "square"));
  const sumsq = t.addChain(squares, "sum of squares");
  const mean = t.emit("DIV", sum, values.length, "mean");
  const ex2 = t.emit("DIV", sumsq, values.length, "E[x^2]");
  const mean2 = t.emit("MUL", mean, mean, "mean^2");
  const guard = t.emit("MIN", mean2, ex2, "underflow guard");
  const variance = t.emit("SUB", ex2, guard, "variance (centi^2)");
  const disagreement = t.emit("GT", variance, 0, "disagreement flag");
  workloads.push({
    workload_id: "webrtc_worst_acr_variance",
    dataset: "WebRTC-QoE",
    description:
      `Opinion dispersion across subjects at the most-impaired condition (${worst.tc}): centi-scaled integer variance plus a disagreement flag.`,
    inputs: { owners: rows.map((r) => r.user), scores: values, scale: "ACR x100 in-trace" },
    leaf_count: t.leaves.length,
    leaves: t.leaves,
    expected: { mean_centi: s.mean, variance_centi2: Math.max(0, s.variance), disagreement },
    micro_ops_used: ["MUL", "ADD", "DIV", "MIN", "SUB", "GT"],
    nonlinearity: "squares and floor divisions of data-dependent intermediates"
  });
}

const facial = findFacialCsvs(rawDir);
if (facial.length > 0) {
  // Gaze-attention monitor over one recorded session: permille of frames with
  // |gaze_angle_x| beyond a threshold, alarm when attention drifts. Gaze
  // angles are biometric-adjacent; only the alarm bit ever leaves the trace.
  const K = 32;                 // frames considered (first K valid frames)
  const OFFSET = 2000;          // +2.000 rad offset keeps values unsigned
  const DEV_MRAD = 350;         // 0.35 rad ~ 20 degrees off-center
  const TARGET_PERMILLE = 500;  // alarm when > 50% of frames are off-center
  const file = facial[0];      // recorded rule: first file in sorted order
  const { rows } = loadTable(file);
  const frames = rows
    .filter((r) => r.gaze_angle_x !== undefined && r.gaze_angle_x !== "")
    .slice(0, K)
    .map((r) => Math.round((Number.parseFloat(r.gaze_angle_x) + 2) * 1000));
  if (frames.length === K) {
    const t = new Trace();
    const bits = frames.map((q, i) => {
      const hiSel = t.max(q, OFFSET, `frame ${i}: |dev| hi`);
      const loSel = t.emit("MIN", q, OFFSET);
      const dev = t.emit("SUB", hiSel, loSel, `frame ${i}: |gaze - center|`);
      return t.emit("GT", dev, DEV_MRAD, `frame ${i}: off-center?`);
    });
    const offCount = t.addChain(bits, "off-center frame count");
    const scaledCount = t.emit("MUL", offCount, 1000);
    const permille = t.emit("DIV", scaledCount, K, "off-center permille");
    const alarm = t.emit("GT", permille, TARGET_PERMILLE, "attention alarm");
    const expectedOff = frames.filter((q) => Math.abs(q - OFFSET) > DEV_MRAD).length;
    workloads.push({
      workload_id: "webrtc_gaze_attention_monitor",
      dataset: "WebRTC-QoE (OpenFace facial features)",
      description:
        `Attention monitor over one session's gaze stream (${path.basename(path.dirname(file))}/${path.basename(file)}, first ${K} frames): permille of frames with |gaze_angle_x| > ${DEV_MRAD / 1000} rad, alarm above ${TARGET_PERMILLE} permille. The raw gaze stream (re-identification-grade) never leaves the encrypted trace.`,
      inputs: {
        session_file: path.relative(rawDir, file).split(path.sep).join("/"),
        frames_quantized_mrad_offset2000: frames,
        deviation_threshold_mrad: DEV_MRAD,
        target_permille: TARGET_PERMILLE
      },
      leaf_count: t.leaves.length,
      leaves: t.leaves,
      expected: {
        off_center_frames: expectedOff,
        off_permille: Math.floor((expectedOff * 1000) / K),
        alarm: Math.floor((expectedOff * 1000) / K) > TARGET_PERMILLE ? 1 : 0
      },
      micro_ops_used: ["GT", "MUL", "SUB", "ADD", "MIN", "DIV"],
      nonlinearity: "per-frame absolute deviation and thresholding on data-dependent values"
    });
  }
} else {
  console.log("note: no OpenFace facial CSVs found; gaze workload skipped (extract Facial_expression_features_dataset.zip).");
}

writeJson(outPath, {
  generator: "datasets/prepare/prepare-webrtc-qoe.mjs",
  source_file: path.relative(rawDir, sub.file).split(path.sep).join("/"),
  citations: CITATIONS,
  condition_rule: "clean = min severity, worst = max severity, severity = delay + jitter + 20*plr",
  conditions: { clean: clean.tc, worst: worst.tc },
  linear_queries: linearQueries,
  workloads
});
for (const q of linearQueries) console.log(`  ${q.query_id}: expected=${JSON.stringify(q.expected)}`);
for (const w of workloads) console.log(`  ${w.workload_id}: ${w.leaf_count} leaves, expected=${JSON.stringify(w.expected)}`);
