#!/usr/bin/env node
/**
 * Verification suite for datasets/ fixtures and models.
 *
 * Independent checks (no code shared with the generators' arithmetic):
 *   1. micro-ISA mirror is in sync with fhe-pod/scripts/application-lowering.mjs;
 *   2. linear fixtures: expected aggregates recomputed from values + weights;
 *   3. non-linear fixtures: EVERY leaf re-executed by an independent evaluator,
 *      opcode ids validated, final decision leaf checked against `expected`;
 *   4. regression models: integer inference rebuilt from the exported
 *      quantized weights, compared with the recorded sample expectation and
 *      with the emitted trace;
 *   5. classifier: decision recomputed from exported quantized weights;
 *   6. WebRTC-QoE pipeline end-to-end: on the real download when present,
 *      otherwise on a SCHEMA MOCK (documented layout, synthetic values) so the
 *      mechanics stay testable without redistribution or network access.
 *
 * Usage (from VC-FHE/datasets):  node test/run-checks.mjs
 * Exit code 0 = all checks passed.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const datasetsDir = path.resolve(scriptDir, "..");
const outputsDir = path.join(datasetsDir, "outputs");

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) { pass += 1; }
  else { fail += 1; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); }
}
function loadJson(p) { return JSON.parse(fs.readFileSync(p, "utf8")); }

/* ---------------- independent micro-op evaluator ----------------
   Independent restatement of the micro-ISA, kept here so this checker does not
   import the code it checks. ADD_CHAIN (15) is variadic and no dataset fixture
   emits it, so `evalOp` below has no case for it; it is listed because the
   adjudicable instruction set has fifteen entries, and a mirror that stopped at
   fourteen would disagree with the verifier contract and with the implementation. */
const OPCODE_IDS = {
  MUL: 1, SHR: 2, CAST_U8: 3, MIN: 4, BITAND: 5, ADD: 6, SUB: 7,
  DIV: 8, MOD: 9, EQ: 10, LT: 11, GT: 12, BITOR: 13, BITXOR: 14,
  ADD_CHAIN: 15
};
function evalOp(name, a, b) {
  switch (name) {
    case "MUL": return a * b;
    case "SHR": return Math.floor(a / 2 ** b);
    case "CAST_U8": return a % 256;
    case "MIN": return Math.min(a, b);
    case "BITAND": return a & b;
    case "ADD": return a + b;
    case "SUB": return a - b;
    case "DIV": return Math.floor(a / b);
    case "MOD": return a % b;
    case "EQ": return a === b ? 1 : 0;
    case "LT": return a < b ? 1 : 0;
    case "GT": return a > b ? 1 : 0;
    case "BITOR": return a | b;
    case "BITXOR": return a ^ b;
    default: return NaN;
  }
}

/* ---------------- check 1: opcode mirror sync ---------------- */
{
  // The table is declared once, in scripts/micro-isa.mjs; application-lowering
  // re-exports it. Look in the declaring module first and fall back to the
  // re-exporting one, so this check follows the code instead of pinning a file.
  const scriptsDir = path.resolve(datasetsDir, "..", "fhe-pod", "scripts");
  const lowering = [
    path.join(scriptsDir, "micro-isa.mjs"),
    path.join(scriptsDir, "application-lowering.mjs")
  ].find((candidate) => fs.existsSync(candidate));
  if (lowering) {
    const src = fs.readFileSync(lowering, "utf8");
    const m = src.match(/OPCODES\s*=\s*Object\.freeze\(\{([\s\S]*?)\}\)/);
    check("opcode-mirror: OPCODES block found", Boolean(m));
    if (m) {
      const entries = [...m[1].matchAll(/(\w+):\s*(\d+)/g)].map(([, k, v]) => [k, Number(v)]);
      const upstream = Object.fromEntries(entries);
      check("opcode-mirror: identical to fhe-pod",
        JSON.stringify(upstream) === JSON.stringify(OPCODE_IDS),
        `upstream=${JSON.stringify(upstream)}`);
    }
  } else {
    console.log("note: fhe-pod lowering script not reachable from here; mirror check skipped.");
  }
}

/* ---------------- linear fixture validation ---------------- */
function checkLinearQuery(q, label) {
  if (q.operation === "SUM") {
    const values = q.values ?? q.values_milli;
    const weights = q.weights ?? values.map(() => 1);
    const sum = values.reduce((a, v, i) => a + v * weights[i], 0);
    const expected = q.expected.aggregate ?? q.expected.poor_count;
    check(`${label}/${q.query_id}: SUM recompute`, sum === expected, `${sum} != ${expected}`);
    if (q.expected.n !== undefined) {
      check(`${label}/${q.query_id}: n`, values.length === q.expected.n);
    }
    if (Array.isArray(q.owners)) {
      check(`${label}/${q.query_id}: owner count`, q.owners.length === values.length);
    }
  } else if (q.operation === "SUB") {
    const scopes = q.values_by_scope ?? q.values_milli;
    const keys = Object.keys(scopes);
    const sums = keys.map((k) => scopes[k].reduce((a, b) => a + b, 0));
    const gap = Math.abs(sums[0] - sums[1]);
    check(`${label}/${q.query_id}: SUB recompute`, gap === q.expected.gap, `${gap} != ${q.expected.gap}`);
  } else {
    check(`${label}/${q.query_id}: known operation`, false, q.operation);
  }
}

/* ---------------- non-linear fixture validation ---------------- */
const FINAL_LEAF_KEY = {
  stav360_checkerboard_variance_v2: "disagreement",
  qoera_bitrate_ladder_advisor: "best_safe_rung_1based",
  qoera_mos_degradation_alarm_v2: "alarm",
  qoera_regulatory_compliance_v2: "violation",
  p1203_bitrate_quality_curve: "trace_result_milli",
  webrtc_worst_acr_variance: "disagreement",
  webrtc_gaze_attention_monitor: "alarm"
};
function checkWorkload(w, label) {
  let ok = true;
  for (const leaf of w.leaves) {
    if (OPCODE_IDS[leaf.opcode_name] !== leaf.opcode) { ok = false; break; }
    const r = evalOp(leaf.opcode_name, leaf.lhs, leaf.rhs);
    if (r !== leaf.claimed) { ok = false; break; }
    if (leaf.claimed < 0) { ok = false; break; }
  }
  check(`${label}/${w.workload_id}: ${w.leaves.length} leaves re-executed`, ok);
  check(`${label}/${w.workload_id}: leaf_count`, w.leaf_count === w.leaves.length);
  const key = FINAL_LEAF_KEY[w.workload_id];
  if (key !== undefined) {
    const last = w.leaves[w.leaves.length - 1];
    check(`${label}/${w.workload_id}: final leaf == expected.${key}`,
      last.claimed === w.expected[key], `${last.claimed} != ${w.expected[key]}`);
  }
}

{
  const p = path.join(outputsDir, "linear-inputs.json");
  if (fs.existsSync(p)) for (const q of loadJson(p).queries) checkLinearQuery(q, "linear");
  else check("linear-inputs.json present", false);

  const n = path.join(outputsDir, "nonlinear-inputs.json");
  if (fs.existsSync(n)) for (const w of loadJson(n).workloads) checkWorkload(w, "nonlinear");
  else check("nonlinear-inputs.json present", false);
}

/* ---------------- regression model validation ---------------- */
function checkRegressionModel(file) {
  const m = loadJson(file);
  const IN_SCALE = m.quantization.input.scale;
  const WS = m.quantization.weights.scale;
  const W1 = m.nonlinear_path_integration.W1_quantized_posneg;
  const b1 = m.nonlinear_path_integration.b1_quantized_posneg;
  const W2 = m.nonlinear_path_integration.W2_quantized_posneg;
  const b2 = m.nonlinear_path_integration.b2_float;
  const xq = m.sample_inference.features_quantized;
  const H = W1.length;
  const dim = W1[0].length;
  const act = [];
  for (let k = 0; k < H; k += 1) {
    let zp = b1[k].pos;
    let zn = b1[k].neg;
    for (let j = 0; j < dim; j += 1) {
      zp += W1[k][j].pos * xq[j];
      zn += W1[k][j].neg * xq[j];
    }
    act.push(Math.max(0, zp - zn));
  }
  let yp = Math.max(0, Math.round(b2 * WS)) * IN_SCALE * WS;
  let yn = Math.max(0, -Math.round(b2 * WS)) * IN_SCALE * WS;
  for (let k = 0; k < H; k += 1) {
    yp += W2[k].pos * act[k];
    yn += W2[k].neg * act[k];
  }
  const milli = Math.floor((Math.max(0, yp - yn) * 1000) / (WS * WS * IN_SCALE));
  const label = path.basename(file);
  check(`${label}: quantized inference rebuilt from exported weights`,
    milli === m.sample_inference.expected_milli,
    `${milli} != ${m.sample_inference.expected_milli}`);
  const last = m.sample_inference.leaves[m.sample_inference.leaves.length - 1];
  check(`${label}: trace final leaf`, last.claimed === m.sample_inference.expected_milli);
  let ok = true;
  for (const leaf of m.sample_inference.leaves) {
    if (evalOp(leaf.opcode_name, leaf.lhs, leaf.rhs) !== leaf.claimed) { ok = false; break; }
  }
  check(`${label}: sample trace re-executed`, ok);
}
for (const f of ["qoe-model-5gqoera.json", "qoe-model-p1203.json"]) {
  const p = path.join(outputsDir, f);
  if (fs.existsSync(p)) checkRegressionModel(p);
  else console.log(`note: ${f} absent (generate with prepare/train-qoe-model.mjs); skipped.`);
}

/* ---------------- classifier validation ---------------- */
function checkClassifier(file) {
  const m = loadJson(file);
  const wq = m.model_quantized.weights_posneg;
  const bq = m.model_quantized.bias_posneg;
  const xq = m.sample_inference.features_quantized;
  let pos = bq.pos;
  let neg = bq.neg;
  for (let j = 0; j < wq.length; j += 1) {
    pos += wq[j].pos * xq[j];
    neg += wq[j].neg * xq[j];
  }
  const decision = pos + 1 > neg ? 1 : 0;
  const label = path.basename(file);
  check(`${label}: decision rebuilt from exported weights`,
    decision === m.sample_inference.expected_decision);
  const last = m.sample_inference.leaves[m.sample_inference.leaves.length - 1];
  check(`${label}: trace final leaf`, last.claimed === m.sample_inference.expected_decision);
  let ok = true;
  for (const leaf of m.sample_inference.leaves) {
    if (evalOp(leaf.opcode_name, leaf.lhs, leaf.rhs) !== leaf.claimed) { ok = false; break; }
  }
  check(`${label}: sample trace re-executed`, ok);
}

/* ---------------- WebRTC-QoE end-to-end ---------------- */
{
  const realRaw = path.join(datasetsDir, "raw", "webrtc-qoe");
  const haveReal = fs.existsSync(realRaw)
    && fs.readdirSync(realRaw).some((f) => f.toLowerCase().endsWith(".csv") || fs.statSync(path.join(realRaw, f)).isDirectory());
  let rawArg;
  let outDir;
  let mode;
  if (haveReal) {
    rawArg = path.join("raw", "webrtc-qoe");
    outDir = outputsDir;
    mode = "REAL DATA";
  } else {
    mode = "SCHEMA MOCK (synthetic; mechanics only — download the real data for reportable numbers)";
    const mockDest = path.join("raw-mock", "webrtc-qoe");
    const mk = spawnSync(process.execPath, [path.join("test", "make-webrtc-mock.mjs"), "--dest", mockDest],
      { cwd: datasetsDir, encoding: "utf8" });
    check("webrtc-mock: generator ran", mk.status === 0, mk.stderr);
    rawArg = mockDest;
    outDir = path.join(datasetsDir, "raw-mock", "outputs");
    fs.mkdirSync(outDir, { recursive: true });
  }
  console.log(`webrtc-qoe end-to-end mode: ${mode}`);

  const fixturesOut = path.join(outDir, "webrtcqoe-inputs.json");
  const r1 = spawnSync(process.execPath,
    [path.join("prepare", "prepare-webrtc-qoe.mjs"), "--raw", rawArg, "--out", fixturesOut],
    { cwd: datasetsDir, encoding: "utf8" });
  check("webrtc-fixtures: generator ran", r1.status === 0, r1.stderr?.slice(0, 300));
  if (r1.status === 0) {
    const fx = loadJson(fixturesOut);
    for (const q of fx.linear_queries) checkLinearQuery(q, "webrtc");
    for (const w of fx.workloads) checkWorkload(w, "webrtc");
    check("webrtc-fixtures: citations recorded", Array.isArray(fx.citations) && fx.citations.length >= 3);
  }

  const clfOut = path.join(outDir, "poor-call-classifier-webrtcqoe.json");
  const r2 = spawnSync(process.execPath,
    [path.join("prepare", "train-poor-call-classifier.mjs"), "--raw", rawArg, "--out", clfOut],
    { cwd: datasetsDir, encoding: "utf8" });
  check("webrtc-classifier: trainer ran", r2.status === 0, r2.stderr?.slice(0, 300));
  if (r2.status === 0) checkClassifier(clfOut);
}

/* ---------------- summary ---------------- */
console.log(`\n${pass} passed, ${fail} failed`);
for (const f of failures) console.log(`  FAIL: ${f}`);
process.exit(fail === 0 ? 0 : 1);
