#!/usr/bin/env node
/**
 * Download 5G-QoERA files (per-user 5G NR QoE corpus: User_ID, Timestamp,
 * Tput, Latitude, Longitude, 20 per-bitrate packet-loss columns, 20
 * per-bitrate MOS columns; 4 base stations x 8 PRB allocations, 259 users,
 * mobility from the CRAWDAD Rome taxi trace).
 *
 * Source:  https://github.com/telematics-lab/5G-QoERA   (License: GPL-3.0)
 * Experiment:   Boffetti, Rago, Piro, Boggia, IEEE WCNC 2025.
 *
 * By default fetches only the two files used by the evaluation
 * (BS_1 / BS_4 at PRB_10, ~30 MB). Use --all to clone the full ~1.1 GB repo.
 *
 * Note: VC-FHE/data/MOS_BS_{1,4}_Driver_PRB_10.csv are comma-separated
 * conversions of these TSVs, kept for compatibility with the existing
 * evaluation scripts. The preparation scripts accept either form.
 *
 * Usage (from VC-FHE/datasets):
 *   node download/download-5gqoera.mjs [--all] [--files MOS_BS_2_Driver_PRB_20.tsv,...]
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const dest = path.resolve(scriptDir, "..", "raw", "5g-qoera");
const RAW_BASE = "https://raw.githubusercontent.com/telematics-lab/5G-QoERA/main/5G-QoERA";
const DEFAULT_FILES = ["MOS_BS_1_Driver_PRB_10.tsv", "MOS_BS_4_Driver_PRB_10.tsv"];

if (process.argv.includes("--all")) {
  const full = path.resolve(scriptDir, "..", "raw", "5G-QoERA-full");
  console.log(`cloning the FULL repository (~1.1 GB) -> ${full}`);
  const r = spawnSync("git", ["clone", "--depth", "1",
    "https://github.com/telematics-lab/5G-QoERA.git", full], { stdio: "inherit" });
  process.exit(r.status ?? 0);
}

const filesArg = process.argv.find((a) => a.startsWith("--files="))?.split("=")[1];
const files = filesArg ? filesArg.split(",") : DEFAULT_FILES;
fs.mkdirSync(dest, { recursive: true });

for (const name of files) {
  const target = path.join(dest, name);
  if (fs.existsSync(target)) {
    console.log(`already present: ${name}`);
    continue;
  }
  const url = `${RAW_BASE}/${name}`;
  console.log(`fetching ${url}`);
  const res = await fetch(url);
  if (!res.ok) {
    console.error(`  failed (${res.status} ${res.statusText})`);
    process.exitCode = 1;
    continue;
  }
  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(target, buf);
  console.log(`  wrote ${target} (${(buf.length / 1e6).toFixed(1)} MB)`);
}
console.log("done. License: GPL-3.0; cite Boffetti et al. (WCNC 2025).");
