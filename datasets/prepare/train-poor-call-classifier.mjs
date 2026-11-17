#!/usr/bin/env node
/**
 * Train a poor-call classifier on WebRTC-QoE and export it split by path.
 *
 * Task (reader-friendly): predict whether a subject rates a call as poor
 * (ACR <= 2) from the session's network impairments, optionally extended
 * with per-session facial aggregates when the OpenFace files are extracted.
 * This is a simplified, integer-friendly version of the task published on
 * this dataset (Bingol et al., ACM TOMM 2024, doi:10.1145/3638251).
 *
 * Architecture split (hybrid flow):
 *   - the logistic scorer  z = w . x + b  over ONE owner's encrypted feature
 *     vector is an authorized weighted aggregation -> LINEAR path;
 *   - the decision  [z >= 0]  is a comparison on a data-dependent value ->
 *     NON-LINEAR path (single GT stage over the pos/neg accumulations).
 *
 * Deterministic: full-batch gradient descent, zero initialization, fixed
 * user-level split. No dependencies.
 *
 * Usage (from VC-FHE/datasets):
 *   node prepare/train-poor-call-classifier.mjs [--raw raw/webrtc-qoe]
 *     [--out outputs/poor-call-classifier-webrtcqoe.json] [--epochs 400]
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  argValue, loadWebrtcSubjective, findFacialCsvs, loadTable, writeJson, Trace
} from "./lib.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const datasetsDir = path.resolve(scriptDir, "..");
const rawDir = path.resolve(datasetsDir, argValue("raw", path.join("raw", "webrtc-qoe")));
const outPath = path.resolve(datasetsDir, argValue("out", path.join("outputs", "poor-call-classifier-webrtcqoe.json")));
const EPOCHS = Number.parseInt(argValue("epochs", "400"), 10);
const LR = 0.5;

const sub = loadWebrtcSubjective(rawDir);
if (!sub) {
  console.error(`no WebRTC-QoE subjective-scores CSV found under ${rawDir}.`);
  process.exit(1);
}

/* Optional facial aggregates: mean |gaze_angle_x| and mean AU12_r per
 * (user, condition) session, joined by directory/file naming. Used only when
 * a facial CSV can be matched for EVERY session (the real dataset has all
 * 300); otherwise the classifier stays network-only and says so. */
function facialAggregates() {
  const files = findFacialCsvs(rawDir);
  if (files.length === 0) return null;
  const bySession = new Map();
  for (const f of files) {
    const key = `${path.basename(path.dirname(f))}/${path.basename(f, ".csv")}`.toLowerCase();
    const { rows } = loadTable(f);
    const gaze = [];
    const au12 = [];
    for (const r of rows) {
      const g = Number.parseFloat(r.gaze_angle_x);
      if (Number.isFinite(g)) gaze.push(Math.abs(g));
      const a = Number.parseFloat(r.AU12_r);
      if (Number.isFinite(a)) au12.push(a);
    }
    if (gaze.length > 0) {
      bySession.set(key, {
        meanAbsGaze: gaze.reduce((x, y) => x + y, 0) / gaze.length,
        meanAu12: au12.length ? au12.reduce((x, y) => x + y, 0) / au12.length : 0
      });
    }
  }
  return bySession;
}

const facial = facialAggregates();
const featureNames = ["delay_s", "jitter_s", "plr_frac"];
const rows = [];
let facialMatched = 0;
for (const s of sub.sessions) {
  const x = [s.delayMs / 1000, s.jitterMs / 1000, s.plrPct / 100];
  if (facial) {
    const key = [...facial.keys()].find((k) =>
      k.includes(String(s.user).toLowerCase()) && k.includes(String(s.tc).toLowerCase()));
    if (key) {
      const f = facial.get(key);
      x.push(f.meanAbsGaze, f.meanAu12 / 5);
      facialMatched += 1;
    }
  }
  rows.push({ x, y: s.score <= 2 ? 1 : 0, user: s.user });
}
const useFacial = facial && facialMatched === rows.length;
const dim = useFacial ? 5 : 3;
if (useFacial) featureNames.push("mean_abs_gaze_rad", "mean_AU12_over5");
const data = rows.map((r) => ({ ...r, x: r.x.slice(0, dim) }));
if (facial && !useFacial) {
  console.log(`note: facial aggregates matched only ${facialMatched}/${rows.length} sessions; using network-only features.`);
}

/* user-level split: first 70% of users (natural order) train */
const users = [...new Set(data.map((r) => r.user))]
  .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
const cut = Math.max(1, Math.floor(users.length * 0.7));
const trainUsers = new Set(users.slice(0, cut));
const train = data.filter((r) => trainUsers.has(r.user));
const test = data.filter((r) => !trainUsers.has(r.user));

/* logistic regression, full-batch GD, zero init (deterministic).
 * Poor calls are the minority class, so positives are weighted by the
 * negative/positive ratio (standard class balancing); without it the model
 * can trivially predict "not poor" everywhere. */
const nPos = train.filter((r) => r.y === 1).length;
const nNeg = train.length - nPos;
const POS_WEIGHT = nPos > 0 ? nNeg / nPos : 1;
const w = Array(dim).fill(0);
let b = 0;
const sigmoid = (z) => 1 / (1 + Math.exp(-z));
for (let e = 0; e < EPOCHS; e += 1) {
  const gw = Array(dim).fill(0);
  let gb = 0;
  for (const r of train) {
    const z = r.x.reduce((a, v, j) => a + v * w[j], b);
    const cw = r.y === 1 ? POS_WEIGHT : 1;
    const err = cw * (sigmoid(z) - r.y);
    for (let j = 0; j < dim; j += 1) gw[j] += err * r.x[j];
    gb += err;
  }
  for (let j = 0; j < dim; j += 1) w[j] -= (LR * gw[j]) / train.length;
  b -= (LR * gb) / train.length;
}

/* quantization: x_q = round(x * 2^8), w split pos/neg at scale 2^8,
 * bias at scale 2^16; decision pos + 1 > neg  <=>  z >= 0 (integers). */
const X_SHIFT = 8;
const W_SHIFT = 8;
const XS = 2 ** X_SHIFT;
const WS = 2 ** W_SHIFT;
const quantX = (x) => x.map((v) => Math.max(0, Math.round(v * XS)));
const wq = w.map((v) => ({ pos: Math.max(0, Math.round(v * WS)), neg: Math.max(0, -Math.round(v * WS)) }));
const bq = { pos: Math.max(0, Math.round(b * XS * WS)), neg: Math.max(0, -Math.round(b * XS * WS)) };

function quantDecision(x) {
  const xq = quantX(x);
  let pos = bq.pos;
  let neg = bq.neg;
  for (let j = 0; j < dim; j += 1) {
    pos += wq[j].pos * xq[j];
    neg += wq[j].neg * xq[j];
  }
  return pos + 1 > neg ? 1 : 0;
}

function emitDecisionTrace(x) {
  const xq = quantX(x);
  const t = new Trace();
  const posTerms = [bq.pos];
  const negTerms = [bq.neg];
  for (let j = 0; j < dim; j += 1) {
    if (wq[j].pos) posTerms.push(t.emit("MUL", wq[j].pos, xq[j], `+w${j}*x${j}`));
    if (wq[j].neg) negTerms.push(t.emit("MUL", wq[j].neg, xq[j], `-w${j}*x${j}`));
  }
  const pos = posTerms.length > 1 ? t.addChain(posTerms, "positive accumulation") : posTerms[0];
  const neg = negTerms.length > 1 ? t.addChain(negTerms, "negative accumulation") : negTerms[0];
  const posPlus = t.emit("ADD", pos, 1, "strictness shift");
  const decision = t.emit("GT", posPlus, neg, "poor-call decision [z >= 0]");
  return { trace: t, decision };
}

/* evaluation */
function evaluate(set, predict) {
  let tp = 0; let fp = 0; let tn = 0; let fn = 0;
  for (const r of set) {
    const yh = predict(r.x);
    if (yh === 1 && r.y === 1) tp += 1;
    else if (yh === 1 && r.y === 0) fp += 1;
    else if (yh === 0 && r.y === 0) tn += 1;
    else fn += 1;
  }
  const acc = (tp + tn) / set.length;
  return {
    accuracy: Number(acc.toFixed(4)),
    tp, fp, tn, fn,
    precision: tp + fp ? Number((tp / (tp + fp)).toFixed(4)) : null,
    recall: tp + fn ? Number((tp / (tp + fn)).toFixed(4)) : null
  };
}
const floatPredict = (x) => (x.reduce((a, v, j) => a + v * w[j], b) >= 0 ? 1 : 0);
const metrics = {
  float: evaluate(test, floatPredict),
  quantized: evaluate(test, quantDecision)
};
metrics.float_quantized_agreement = Number((
  test.filter((r) => floatPredict(r.x) === quantDecision(r.x)).length / test.length
).toFixed(4));

const sample = test.find((r) => r.y === 1) ?? test[0];
const { trace, decision } = emitDecisionTrace(sample.x);
if (decision !== quantDecision(sample.x)) throw new Error("trace/batch decision mismatch");

writeJson(outPath, {
  generator: "datasets/prepare/train-poor-call-classifier.mjs",
  dataset: {
    id: "WebRTC-QoE",
    source_file: path.relative(rawDir, sub.file).split(path.sep).join("/"),
    citations: [
      "Zenodo 15836614, CC BY 4.0",
      "Bingol et al., ACM TOMM 2024, doi:10.1145/3638251 (published ML task on this data)",
      "Bingol et al., Computer Networks 2024, doi:10.1016/j.comnet.2024.110356"
    ]
  },
  task: "binary poor-call detection: ACR <= 2",
  features: featureNames.slice(0, dim),
  facial_features_used: Boolean(useFacial),
  sizes: { train: train.length, test: test.length, users: users.length, train_users: cut },
  hyperparameters: {
    epochs: EPOCHS, lr: LR, init: "zeros (deterministic)",
    positive_class_weight: Number(POS_WEIGHT.toFixed(4))
  },
  model_float: { weights: w, bias: b },
  quantization: { x_shift: X_SHIFT, w_shift: W_SHIFT, encoding: "pos/neg split, decision pos+1 > neg" },
  model_quantized: { weights_posneg: wq, bias_posneg: bq },
  metrics,
  linear_path_integration: {
    statement:
      "z = sum_j w_j * x_j + b over ONE owner's encrypted session features; quantized weights are the authorized weight vector fixed at tag creation; the score never needs to be opened when only the decision is queried.",
    tag_suggestion: "webrtcqoe/poor-call-score/v1"
  },
  nonlinear_path_integration: {
    statement:
      "decision [z >= 0] as a single GT stage over the positive and negative accumulations (pos/neg split keeps all intermediates unsigned).",
    stage_layout: "MUL/ADD accumulation stage + one GT decision stage"
  },
  sample_inference: {
    user: sample.user,
    features_raw: sample.x,
    features_quantized: quantX(sample.x),
    actual_poor: sample.y,
    expected_decision: decision,
    leaf_count: trace.leaves.length,
    leaves: trace.leaves
  }
});
console.log(JSON.stringify({ sizes: { train: train.length, test: test.length }, facial: useFacial, metrics }, null, 2));
