#!/usr/bin/env node
/**
 * Check a manually downloaded Waterloo SQoE-IV package
 * (see waterloo-sqoe4-instructions.md) and report whether per-subject
 * ratings are present.
 *
 * Usage (from VC-FHE/datasets):  node download/verify-waterloo-sqoe4.mjs
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const dir = path.resolve(scriptDir, "..", "raw", "waterloo-sqoe4");

if (!fs.existsSync(dir)) {
  console.error(`missing ${dir} — follow waterloo-sqoe4-instructions.md first.`);
  process.exit(1);
}

/** Collect entry names from extracted files and from zip listings. */
const entries = [];
function walk(p) {
  for (const e of fs.readdirSync(p, { withFileTypes: true })) {
    const full = path.join(p, e.name);
    if (e.isDirectory()) walk(full);
    else entries.push(path.relative(dir, full));
  }
}
walk(dir);

for (const zip of entries.filter((e) => e.toLowerCase().endsWith(".zip"))) {
  const r = spawnSync("unzip", ["-l", path.join(dir, zip)], { encoding: "utf8" });
  if (r.status === 0) {
    for (const line of r.stdout.split("\n")) {
      const m = line.trim().match(/\d+\s+\S+\s+\S+\s+(.+)$/);
      if (m) entries.push(`${zip}::${m[1]}`);
    }
  } else {
    console.warn(`note: could not list ${zip} (unzip not available?); extract it manually and re-run.`);
  }
}

console.log(`found ${entries.length} entries under raw/waterloo-sqoe4/`);
const subjectish = entries.filter((e) => /subject|individual|rating(?!s?_?mos)|raw_score/i.test(e));
const mosish = entries.filter((e) => /mos|score/i.test(e));

if (subjectish.length > 0) {
  console.log("PER-SUBJECT candidates found:");
  for (const e of subjectish.slice(0, 20)) console.log(`  ${e}`);
  console.log("→ SQoE-IV can drive the linear path with subject-level owners.");
} else {
  console.log("no per-subject ratings file detected (MOS-level files below):");
  for (const e of mosish.slice(0, 10)) console.log(`  ${e}`);
  console.log("→ use sessions/devices as owners, or fall back to the P.1203 open dataset for subject-level experiments (see README.md).");
}
