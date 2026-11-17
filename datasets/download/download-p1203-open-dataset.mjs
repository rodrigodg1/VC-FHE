#!/usr/bin/env node
/**
 * Download the ITU-T P.1203 open dataset (per-subject ratings, MOS, features,
 * and reference model outputs for 4 subjective databases).
 *
 * Source:  https://github.com/itu-p1203/open-dataset
 * Experiment:   Robitza et al., ACM MMSys 2018, DOI 10.1145/3204949.3208124
 * License: custom, "free of charge ... for non-commercial research purposes"
 *          (see the repository README; NOT an OSI/CC license, no patent grant).
 *
 * Usage (from VC-FHE/datasets):  node download/download-p1203-open-dataset.mjs
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const dest = path.resolve(scriptDir, "..", "raw", "p1203-open-dataset");
const REPO = "https://github.com/itu-p1203/open-dataset.git";

if (fs.existsSync(path.join(dest, ".git"))) {
  console.log(`updating existing clone at ${dest}`);
  const r = spawnSync("git", ["-C", dest, "pull", "--ff-only"], { stdio: "inherit" });
  process.exit(r.status ?? 0);
}
fs.mkdirSync(path.dirname(dest), { recursive: true });
console.log(`cloning ${REPO} -> ${dest}`);
const r = spawnSync("git", ["clone", "--depth", "1", REPO, dest], { stdio: "inherit" });
if (r.status !== 0) {
  console.error("git clone failed; check network access or download the ZIP from GitHub manually.");
  process.exit(r.status ?? 1);
}
console.log("done. License reminder: non-commercial research use only; cite Robitza et al. (MMSys 2018).");
