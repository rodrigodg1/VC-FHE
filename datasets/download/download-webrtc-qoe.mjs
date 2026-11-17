#!/usr/bin/env node
/**
 * Download the WebRTC-QoE dataset (Univ. of Cagliari): 20 subjects x 15
 * network-impairment conditions, 300 per-subject ACR scores, WebRTC-internals
 * network parameters, OpenFace facial features (gaze, landmarks, action
 * units) and openSMILE speech features.
 *
 * Source:  Zenodo record 15836614  — License: CC BY 4.0 (verified on record)
 *          https://zenodo.org/records/15836614
 * Experiments:  ACM TOMM 2024, DOI 10.1145/3638251;
 *          Computer Networks 2024, DOI 10.1016/j.comnet.2024.110356.
 *
 * The archive is ~613 MB (≈2.6 GB extracted); the download only starts when
 * --yes is passed.
 *
 * Usage (from VC-FHE/datasets):  node download/download-webrtc-qoe.mjs --yes
 */
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const dest = path.resolve(scriptDir, "..", "raw", "webrtc-qoe");
const API = "https://zenodo.org/api/records/15836614";

const res = await fetch(API);
if (!res.ok) {
  console.error(`Zenodo API request failed: ${res.status} ${res.statusText}`);
  process.exit(1);
}
const record = await res.json();
console.log(`record: ${record.metadata?.title}`);
console.log(`license: ${record.metadata?.license?.id ?? "(see record page)"}`);
for (const f of record.files ?? []) {
  console.log(`  file: ${f.key}  ${(f.size / 1e6).toFixed(1)} MB`);
}
if (!process.argv.includes("--yes")) {
  console.log("\nDry run. Re-run with --yes to download into datasets/raw/webrtc-qoe/.");
  process.exit(0);
}
fs.mkdirSync(dest, { recursive: true });
for (const f of record.files ?? []) {
  const target = path.join(dest, f.key);
  if (fs.existsSync(target) && fs.statSync(target).size === f.size) {
    console.log(`already present: ${f.key}`);
    continue;
  }
  console.log(`downloading ${f.key} ...`);
  const dl = await fetch(f.links.self);
  if (!dl.ok || !dl.body) {
    console.error(`  failed (${dl.status})`);
    process.exitCode = 1;
    continue;
  }
  await pipeline(Readable.fromWeb(dl.body), fs.createWriteStream(target));
  console.log(`  wrote ${target}`);
}
console.log("done. License: CC BY 4.0 — attribution required (cite the TOMM 2024 experiment).");
