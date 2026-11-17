#!/usr/bin/env node
/**
 * Download the STAV360 public mirror (per-user ACR ratings, head-movement
 * traces, tiling patterns; 27 users x 6 videos x 12 patterns).
 *
 * Sources:
 *   - IEEE DataPort record DOI 10.21227/BCPT-3904 ("Standard Dataset":
 *     requires an IEEE DataPort SUBSCRIPTION; no license text on the record);
 *   - public GitHub mirror https://github.com/SLG-European-Projects/STAV360
 *     (ratings + traces; videos only by request; NO LICENSE FILE).
 *
 * IMPORTANT LICENSE / PRIVACY NOTICE
 *   The mirror carries no license, so redistribution rights are NOT
 *   established: keep the raw clone OUT of the repository (datasets/raw/ is
 *   gitignored) and commit only small derived fixtures (panel aggregates)
 *   under the research-use rationale, as the existing evaluation already
 *   does. The repository history of the mirror also contains a deleted
 *   per-user demographics file; do not resurrect or redistribute it.
 *   See datasets/README.md ("STAV360 findings") before using this
 *   dataset in new experiments.
 *
 * Usage (from VC-FHE/datasets):  node download/download-stav360.mjs
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const dest = path.resolve(scriptDir, "..", "raw", "stav360");
const REPO = "https://github.com/SLG-European-Projects/STAV360.git";

if (fs.existsSync(path.join(dest, ".git"))) {
  console.log(`updating existing clone at ${dest}`);
  const r = spawnSync("git", ["-C", dest, "pull", "--ff-only"], { stdio: "inherit" });
  process.exit(r.status ?? 0);
}
fs.mkdirSync(path.dirname(dest), { recursive: true });
console.log(`cloning ${REPO} -> ${dest}`);
const r = spawnSync("git", ["clone", "--depth", "1", REPO, dest], { stdio: "inherit" });
if (r.status !== 0) {
  console.error("git clone failed; check network access.");
  process.exit(r.status ?? 1);
}
console.log("done. REMINDER: no license file upstream — do not redistribute the raw data; derived fixtures only.");
