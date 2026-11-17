#!/usr/bin/env node
/**
 * SCHEMA MOCK generator for WebRTC-QoE — synthetic data in the documented
 * file layout of Zenodo record 15836614, used ONLY to validate the pipeline
 * mechanics when the real download is not present (for example in CI or a
 * sandbox without Zenodo access). Results computed on this mock carry no
 * scientific meaning; re-run the pipeline on the real download before using
 * any number.
 *
 * Layout produced (matching the record's documented structure):
 *   <dest>/Subjective_results_dataset.csv          300 rows, 20 users x 15 TCs
 *   <dest>/Facial_expression_features_dataset/UserN/TCk.csv   (OpenFace-style)
 *
 * Usage: node test/make-webrtc-mock.mjs [--dest raw-mock/webrtc-qoe]
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { argValue, mulberry32 } from "../prepare/lib.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const datasetsDir = path.resolve(scriptDir, "..");
const dest = path.resolve(datasetsDir, argValue("dest", path.join("raw-mock", "webrtc-qoe")));

const rnd = mulberry32(20260801);

/* 15 of the 18 factor combinations, in documented factor order. */
const DELAYS = [0, 500, 1000];
const JITTERS = [0, 500];
const LOSSES = [0, 15, 30];
const tcs = [];
for (const d of DELAYS) for (const j of JITTERS) for (const l of LOSSES) {
  if (tcs.length < 15) tcs.push({ d, j, l });
}

const lines = ["TC,Delay [ms],Jitter [ms],Packet Loss Rate [%],User,ACR Score"];
for (let u = 1; u <= 20; u += 1) {
  tcs.forEach((tc, k) => {
    const q = 5 - 1.5 * (tc.l / 30) - 1.2 * (tc.d / 1000) - 0.6 * (tc.j / 500) + (rnd() - 0.5);
    const acr = Math.min(5, Math.max(1, Math.round(q)));
    lines.push(`TC${k + 1},${tc.d},${tc.j},${tc.l},User${u},${acr}`);
  });
}
fs.mkdirSync(dest, { recursive: true });
fs.writeFileSync(path.join(dest, "Subjective_results_dataset.csv"), `${lines.join("\n")}\n`);

/* OpenFace-style facial CSVs for a few sessions (schema validation only). */
const FACIAL_HEADER = "frame,face_id,timestamp,confidence,success,gaze_angle_x,gaze_angle_y,AU12_r";
for (const u of [1, 2]) {
  for (const k of [1, 15]) {
    const dir = path.join(dest, "Facial_expression_features_dataset", `User${u}`);
    fs.mkdirSync(dir, { recursive: true });
    const rows = [FACIAL_HEADER];
    for (let f = 0; f < 64; f += 1) {
      const gx = (rnd() - 0.5) * (k === 15 ? 1.4 : 0.5); // more drift when impaired
      const gy = (rnd() - 0.5) * 0.4;
      const au12 = Math.max(0, (k === 15 ? 0.4 : 1.2) + (rnd() - 0.5));
      rows.push(`${f},0,${(f / 30).toFixed(3)},0.98,1,${gx.toFixed(4)},${gy.toFixed(4)},${au12.toFixed(3)}`);
    }
    fs.writeFileSync(path.join(dir, `TC${k}.csv`), `${rows.join("\n")}\n`);
  }
}
console.log(`SCHEMA MOCK written to ${dest} (synthetic; pipeline validation only).`);
