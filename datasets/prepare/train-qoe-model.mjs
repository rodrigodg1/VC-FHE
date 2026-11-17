#!/usr/bin/env node
/**
 * Train a compact QoE prediction model and export it in the split form the
 * architecture consumes:
 *
 *  - a LINEAR model (ridge regression): its scoring is a pre-authorized
 *    weighted aggregation over one owner's encrypted feature vector, i.e. a
 *    linear-path query (indices = features, authorized weights = quantized
 *    model weights);
 *  - a small MLP (1 hidden ReLU layer): dot products are linear stages,
 *    activations/selections are non-linear stages; the quantized inference is
 *    emitted as a ground-truth micro-ISA trace for the non-linear path
 *    (pos/neg weight split keeps every intermediate unsigned).
 *
 * Everything is deterministic (seeded PRNG, fixed splits) and dependency-free.
 *
 * Usage (from VC-FHE/datasets):
 *   node prepare/train-qoe-model.mjs [--dataset 5gqoera|p1203] [--hidden 8]
 *     [--epochs 30] [--max-rows 20000] [--seed 42]
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadTable, firstExisting, quantizeMilli, writeJson, mulberry32,
  pearson, rmse, mae, solveLinearSystem, Trace
} from "./lib.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const datasetsDir = path.resolve(scriptDir, "..");
const vcfheDir = path.resolve(datasetsDir, "..");

function argValue(name, fallback) {
  const eq = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (eq) return eq.split("=")[1];
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return fallback;
}

const DATASET = argValue("dataset", "5gqoera");
const HIDDEN = Number.parseInt(argValue("hidden", "8"), 10);
const EPOCHS = Number.parseInt(argValue("epochs", "30"), 10);
const MAX_ROWS = Number.parseInt(argValue("max-rows", "20000"), 10);
const SEED = Number.parseInt(argValue("seed", "42"), 10);

/* ---------------------------------------------------------------- */
/* Dataset loaders: return {featureNames, rows:[{x:[...], y, group}]} */
/* ---------------------------------------------------------------- */
function load5gqoera() {
  const file = firstExisting([
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_1_Driver_PRB_10.tsv"),
    path.join(datasetsDir, "raw", "5g-qoera", "MOS_BS_1_Driver_PRB_10.csv"),
    path.join(vcfheDir, "data", "MOS_BS_1_Driver_PRB_10.csv")
  ]);
  if (!file) throw new Error("5G-QoERA raw file not found; run download/download-5gqoera.mjs");
  const { header, rows } = loadTable(file);
  const plrCols = header.filter((h) => !h.startsWith("MOS_")
    && !["User_ID", "Timestamp", "Tput", "Latitude", "Longitude"].includes(h));
  const plr3000 = plrCols.find((c) => c.endsWith("_3000kbps"));
  const plrMin = plrCols.find((c) => c.endsWith("_50kbps"));
  const plrMax = plrCols.find((c) => c.endsWith("_8000kbps"));
  const featureNames = ["Tput", plr3000, plrMin, plrMax];
  const data = [];
  for (const r of rows) {
    if (!r.User_ID || !r.MOS_3000kbps) continue;
    const x = featureNames.map((c) => Number.parseFloat(r[c]));
    if (x.some((v) => !Number.isFinite(v))) continue;
    data.push({ x, y: quantizeMilli(r.MOS_3000kbps), group: r.User_ID });
  }
  return {
    id: "5G-QoERA",
    file: path.relative(datasetsDir, file),
    featureNames,
    target: "MOS_3000kbps (milli)",
    rows: data,
    splitRule: "by User_ID: first 70% of numerically sorted users train, remaining 30% test (no user overlap)"
  };
}

function loadP1203() {
  const featCsv = firstExisting([
    path.join(datasetsDir, "raw", "p1203-open-dataset", "features", "features_mode0.csv")
  ]);
  const mosCsv = firstExisting([
    path.join(datasetsDir, "raw", "p1203-open-dataset", "subjective_scores", "mos.csv")
  ]);
  if (!featCsv || !mosCsv) throw new Error("P.1203 open dataset not found; run download/download-p1203-open-dataset.mjs");
  const { rows: feats } = loadTable(featCsv);
  const { rows: mosRows } = loadTable(mosCsv);
  const mosByPvs = new Map(mosRows.filter((r) => r.context === "pc")
    .map((r) => [r.pvs_id, Number.parseFloat(r.mos)]));
  const agg = new Map();
  for (const r of feats) {
    const pvs = r.pvs_id;
    if (!mosByPvs.has(pvs)) continue;
    if (!agg.has(pvs)) agg.set(pvs, { br: [], fr: [], h: [] });
    const a = agg.get(pvs);
    a.br.push(Number.parseFloat(r.bitrate_kbps_target));
    a.fr.push(Number.parseFloat(r.framerate));
    a.h.push(Number.parseFloat(r.coding_height));
  }
  const mean = (v) => v.reduce((x, y) => x + y, 0) / v.length;
  const data = [...agg.entries()].map(([pvs, a]) => ({
    x: [mean(a.br) / 100, Math.min(...a.br) / 100, mean(a.fr), mean(a.h) / 100],
    y: Math.round(mosByPvs.get(pvs) * 1000),
    group: pvs.startsWith("VL") ? "validation" : "training",
    pvs
  }));
  return {
    id: "ITU-T P.1203 open dataset",
    file: path.relative(datasetsDir, featCsv),
    featureNames: ["mean_target_kbps/100", "min_target_kbps/100", "framerate", "coding_height/100"],
    target: "pc-context MOS (milli)",
    rows: data,
    splitRule: "official design: TR04/TR06 databases train, VL04/VL13 validate (content-separated)"
  };
}

/* ---------------------------------------------------------------- */
const ds = DATASET === "p1203" ? loadP1203() : load5gqoera();
let rows = ds.rows;
if (rows.length > MAX_ROWS) {
  const stride = Math.ceil(rows.length / MAX_ROWS);
  rows = rows.filter((_, i) => i % stride === 0);
}

let train;
let test;
if (DATASET === "p1203") {
  train = rows.filter((r) => r.group === "training");
  test = rows.filter((r) => r.group === "validation");
} else {
  const users = [...new Set(rows.map((r) => r.group))].sort((a, b) => Number(a) - Number(b));
  const cut = Math.floor(users.length * 0.7);
  const trainUsers = new Set(users.slice(0, cut));
  train = rows.filter((r) => trainUsers.has(r.group));
  test = rows.filter((r) => !trainUsers.has(r.group));
}
if (train.length === 0 || test.length === 0) throw new Error("empty split");

/* standardize with train statistics */
const dim = ds.featureNames.length;
const mu = Array(dim).fill(0);
const sd = Array(dim).fill(0);
for (const r of train) r.x.forEach((v, j) => { mu[j] += v; });
mu.forEach((v, j) => { mu[j] = v / train.length; });
for (const r of train) r.x.forEach((v, j) => { sd[j] += (v - mu[j]) ** 2; });
sd.forEach((v, j) => { sd[j] = Math.sqrt(v / train.length) || 1; });
const std = (x) => x.map((v, j) => (v - mu[j]) / sd[j]);

/* ---------------- linear ridge (closed form) ---------------- */
const LAMBDA = 1e-3;
{
  const A = Array.from({ length: dim + 1 }, () => Array(dim + 1).fill(0));
  const b = Array(dim + 1).fill(0);
  for (const r of train) {
    const x = [...std(r.x), 1];
    for (let i = 0; i <= dim; i += 1) {
      for (let j = 0; j <= dim; j += 1) A[i][j] += x[i] * x[j];
      b[i] += x[i] * r.y;
    }
  }
  for (let i = 0; i < dim; i += 1) A[i][i] += LAMBDA * train.length;
  var ridge = solveLinearSystem(A, b); // [w..., bias], milli-MOS output
}
const ridgePredict = (x) => {
  const s = std(x);
  return s.reduce((a, v, j) => a + v * ridge[j], ridge[dim]);
};

/* ---------------- MLP (1 hidden ReLU layer) ---------------- */
const rnd = mulberry32(SEED);
const W1 = Array.from({ length: HIDDEN }, () => Array.from({ length: dim }, () => (rnd() - 0.5) * 0.5));
const b1 = Array(HIDDEN).fill(0);
const W2 = Array.from({ length: HIDDEN }, () => (rnd() - 0.5) * 0.5);
let b2 = 0;
const Y_SCALE = 1000; // train on MOS units, report milli

function mlpForward(xs) {
  const h = Array(HIDDEN);
  const a = Array(HIDDEN);
  for (let k = 0; k < HIDDEN; k += 1) {
    let z = b1[k];
    for (let j = 0; j < dim; j += 1) z += W1[k][j] * xs[j];
    h[k] = z;
    a[k] = Math.max(0, z);
  }
  let y = b2;
  for (let k = 0; k < HIDDEN; k += 1) y += W2[k] * a[k];
  return { h, a, y };
}

{
  const LR = 0.01;
  const idx = train.map((_, i) => i);
  for (let e = 0; e < EPOCHS; e += 1) {
    for (let i = idx.length - 1; i > 0; i -= 1) {
      const j = Math.floor(rnd() * (i + 1));
      [idx[i], idx[j]] = [idx[j], idx[i]];
    }
    for (const i of idx) {
      const r = train[i];
      const xs = std(r.x);
      const { h, a, y } = mlpForward(xs);
      const err = y - r.y / Y_SCALE;
      b2 -= LR * err;
      for (let k = 0; k < HIDDEN; k += 1) {
        const gW2 = err * a[k];
        const gA = err * W2[k];
        W2[k] -= LR * gW2;
        if (h[k] > 0) {
          b1[k] -= LR * gA;
          for (let j = 0; j < dim; j += 1) W1[k][j] -= LR * gA * xs[j];
        }
      }
    }
  }
}
const mlpPredict = (x) => mlpForward(std(x)).y * Y_SCALE;

/* ---------------- quantization for the encrypted paths ---------------- */
/*
 * Inputs: standardized features are affinely mapped to unsigned integers
 *   x_q = round((x_std - IN_MIN) * IN_SCALE), clamped to [0, IN_RANGE].
 * Weights: w_q = round(w * W_SCALE), split into positive and negative parts
 *   so every micro-ISA intermediate stays unsigned:
 *   z = z_pos - z_neg, ReLU(z) = GT-select(z_pos, z_neg) with guarded SUB.
 */
const IN_MIN = -4;
const IN_SCALE = 64;    // 2^6 per standardized unit
const IN_RANGE = 512;   // clamp at +4 sigma
const W_SHIFT = 8;
const W_SCALE = 2 ** W_SHIFT;

const quantX = (x) => std(x).map((v) => {
  const q = Math.round((v - IN_MIN) * IN_SCALE);
  return Math.max(0, Math.min(IN_RANGE, q));
});
const splitQ = (w) => ({
  pos: Math.max(0, Math.round(w * W_SCALE)),
  neg: Math.max(0, -Math.round(w * W_SCALE))
});

const W1q = W1.map((row) => row.map(splitQ));
// fold the input-offset into the bias: z = sum w (x_q/IN_SCALE + IN_MIN) + b
const b1Eff = b1.map((bk, k) => bk + W1[k].reduce((a, w) => a + w * IN_MIN, 0));
const b1q = b1Eff.map((v) => splitQ(v * IN_SCALE)); // same fixed-point grid as w*x_q
const W2q = W2.map(splitQ);
const b2Eff = b2;

/** Integer inference mirroring the emitted trace (for batch verification). */
function quantForward(x) {
  const xq = quantX(x);
  const act = Array(HIDDEN);
  for (let k = 0; k < HIDDEN; k += 1) {
    let zp = b1q[k].pos;
    let zn = b1q[k].neg;
    for (let j = 0; j < dim; j += 1) {
      zp += W1q[k][j].pos * xq[j];
      zn += W1q[k][j].neg * xq[j];
    }
    act[k] = Math.max(0, zp - zn); // scale: W_SCALE * IN_SCALE
  }
  let yp = Math.max(0, Math.round(b2Eff * W_SCALE)) * IN_SCALE * W_SCALE;
  let yn = Math.max(0, -Math.round(b2Eff * W_SCALE)) * IN_SCALE * W_SCALE;
  for (let k = 0; k < HIDDEN; k += 1) {
    yp += W2q[k].pos * act[k];
    yn += W2q[k].neg * act[k];
  }
  const raw = Math.max(0, yp - yn); // scale: W_SCALE^2 * IN_SCALE
  return Math.floor((raw * Y_SCALE) / (W_SCALE * W_SCALE * IN_SCALE));
}

/** Emit the full micro-ISA trace for one sample's quantized inference. */
function emitInferenceTrace(x) {
  const xq = quantX(x);
  const t = new Trace();
  const acts = [];
  for (let k = 0; k < HIDDEN; k += 1) {
    const posTerms = [b1q[k].pos];
    const negTerms = [b1q[k].neg];
    for (let j = 0; j < dim; j += 1) {
      if (W1q[k][j].pos) posTerms.push(t.emit("MUL", W1q[k][j].pos, xq[j], `h${k}: +w${j}*x${j}`));
      if (W1q[k][j].neg) negTerms.push(t.emit("MUL", W1q[k][j].neg, xq[j], `h${k}: -w${j}*x${j}`));
    }
    const zp = t.addChain(posTerms, `h${k}: positive accumulation`);
    const zn = t.addChain(negTerms, `h${k}: negative accumulation`);
    acts.push(t.reluShift(zp, zn, `h${k}`)); // ReLU(zp - zn), unsigned-safe
  }
  const yPos = [Math.max(0, Math.round(b2Eff * W_SCALE)) * IN_SCALE * W_SCALE];
  const yNeg = [Math.max(0, -Math.round(b2Eff * W_SCALE)) * IN_SCALE * W_SCALE];
  for (let k = 0; k < HIDDEN; k += 1) {
    if (W2q[k].pos) yPos.push(t.emit("MUL", W2q[k].pos, acts[k], `out: +v${k}*a${k}`));
    if (W2q[k].neg) yNeg.push(t.emit("MUL", W2q[k].neg, acts[k], `out: -v${k}*a${k}`));
  }
  const p = t.addChain(yPos, "out: positive accumulation");
  const n = t.addChain(yNeg, "out: negative accumulation");
  const m = t.emit("MIN", n, p, "out: underflow guard");
  const raw = t.emit("SUB", p, m, "out: raw score");
  const scaled = t.emit("MUL", raw, Y_SCALE, "out: to milli-MOS numerator");
  const yq = t.emit("DIV", scaled, W_SCALE * W_SCALE * IN_SCALE, "out: descale");
  return { trace: t, resultMilli: yq };
}

/* ---------------- evaluation ---------------- */
function evaluate(predict, set) {
  const yh = set.map((r) => predict(r.x));
  const y = set.map((r) => r.y);
  return {
    rmse_milli: Math.round(rmse(yh, y)),
    mae_milli: Math.round(mae(yh, y)),
    pcc: Number(pearson(yh, y).toFixed(4))
  };
}
const metrics = {
  linear_ridge: evaluate(ridgePredict, test),
  mlp_float: evaluate(mlpPredict, test),
  mlp_quantized: evaluate(quantForward, test)
};
const qDev = test.map((r) => Math.abs(quantForward(r.x) - mlpPredict(r.x)));
metrics.quantization = {
  mean_abs_dev_milli: Math.round(qDev.reduce((a, b) => a + b, 0) / qDev.length),
  max_abs_dev_milli: Math.round(Math.max(...qDev))
};

/* sample trace on the first test row, cross-checked against quantForward */
const sample = test[0];
const { trace, resultMilli } = emitInferenceTrace(sample.x);
if (resultMilli !== quantForward(sample.x)) {
  throw new Error(`trace/batch mismatch: ${resultMilli} vs ${quantForward(sample.x)}`);
}

/* ---------------- export ---------------- */
const ridgeQ = ridge.slice(0, dim).map(splitQ);
const out = {
  generator: "datasets/prepare/train-qoe-model.mjs",
  dataset: { id: ds.id, file: ds.file, target: ds.target, split_rule: ds.splitRule },
  features: ds.featureNames,
  sizes: { train: train.length, test: test.length, users_or_groups: new Set(rows.map((r) => r.group)).size },
  standardization: { mean: mu, std: sd },
  hyperparameters: { hidden: HIDDEN, epochs: EPOCHS, seed: SEED, lambda: LAMBDA, lr: 0.01 },
  quantization: {
    input: { min_sigma: IN_MIN, scale: IN_SCALE, range: IN_RANGE },
    weights: { shift: W_SHIFT, scale: W_SCALE, encoding: "pos/neg split keeps all intermediates unsigned" }
  },
  metrics,
  linear_path_integration: {
    model: "ridge regression (milli-MOS output)",
    statement:
      "score = sum_j w_j * x_j + b over ONE owner's encrypted standardized-quantized features; indices 1..d are the owner's feature slots, the quantized ridge weights are the authorized weight vector fixed at tag creation. Thresholding of the score, if needed, belongs to the non-linear path (hybrid flow).",
    weights_float: ridge.slice(0, dim),
    bias_float_milli: ridge[dim],
    weights_quantized_posneg: ridgeQ,
    tag_suggestion: `${DATASET}/qoe-ridge/score/v1`
  },
  nonlinear_path_integration: {
    model: `MLP ${dim}-${HIDDEN}-1, ReLU`,
    stage_layout:
      "one stage per hidden unit (pos/neg MUL-ADD accumulation + GT/MIN/SUB/MUL ReLU-select), then one output stage (accumulation, underflow guard, descale)",
    W1_quantized_posneg: W1q,
    b1_quantized_posneg: b1q,
    W2_quantized_posneg: W2q,
    b2_float: b2Eff
  },
  sample_inference: {
    group: sample.group,
    features_raw: sample.x,
    features_quantized: quantX(sample.x),
    expected_milli: resultMilli,
    actual_mos_milli: sample.y,
    leaf_count: trace.leaves.length,
    leaves: trace.leaves
  }
};

writeJson(path.join(datasetsDir, "outputs", `qoe-model-${DATASET}.json`), out);
console.log(JSON.stringify({ sizes: out.sizes, metrics }, null, 2));
