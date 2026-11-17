/**
 * Shared utilities for dataset preparation scripts.
 *
 * Conventions (aligned with the existing VC-FHE fixture generators):
 *  - all encrypted values are non-negative integers (TFHE/leveled encoding);
 *  - real-valued quantities are quantized to milli-units (x1000) unless noted;
 *  - integer statistics use floor semantics: mean = floor(sum/n),
 *    E[x^2] = floor(sumsq/n), variance = E[x^2] - mean^2 (matches
 *    fhe-pod/scripts/generate-stav360-fixtures.mjs).
 */
import fs from "node:fs";
import path from "node:path";

/** Parse a delimited text table (auto-detects TSV vs CSV from the header). */
export function parseTable(text) {
  const lines = text.trim().split(/\r?\n/);
  const delimiter = lines[0].includes("\t") ? "\t" : ",";
  const header = lines[0].split(delimiter).map((h) => h.trim());
  const rows = [];
  for (const line of lines.slice(1)) {
    if (!line.trim()) continue;
    const cols = line.split(delimiter);
    const row = {};
    for (let i = 0; i < header.length; i += 1) row[header[i]] = cols[i]?.trim() ?? "";
    rows.push(row);
  }
  return { header, rows };
}

export function loadTable(filePath) {
  return parseTable(fs.readFileSync(filePath, "utf8"));
}

/** Return the first existing path from a candidate list, or null. */
export function firstExisting(candidates) {
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return null;
}

export function quantizeMilli(value) {
  const v = Number.parseFloat(value);
  if (!Number.isFinite(v)) throw new Error(`not a finite number: ${value}`);
  return Math.round(v * 1000);
}

export function intSum(values) {
  return values.reduce((a, b) => a + b, 0);
}

/** Integer floor statistics matching the committed STAV360 fixture semantics. */
export function intStats(values) {
  const n = values.length;
  const sum = intSum(values);
  const mean = Math.floor(sum / n);
  const sumsq = values.reduce((a, v) => a + v * v, 0);
  const ex2 = Math.floor(sumsq / n);
  const variance = ex2 - mean * mean;
  return { n, sum, mean, sumsq, ex2, variance };
}

/** Deterministic PRNG (mulberry32) so every fixture is reproducible. */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pearson(xs, ys) {
  const n = xs.length;
  const mx = xs.reduce((a, b) => a + b, 0) / n;
  const my = ys.reduce((a, b) => a + b, 0) / n;
  let num = 0;
  let dx = 0;
  let dy = 0;
  for (let i = 0; i < n; i += 1) {
    num += (xs[i] - mx) * (ys[i] - my);
    dx += (xs[i] - mx) ** 2;
    dy += (ys[i] - my) ** 2;
  }
  return num / Math.sqrt(dx * dy);
}

export function rmse(xs, ys) {
  const n = xs.length;
  return Math.sqrt(xs.reduce((a, x, i) => a + (x - ys[i]) ** 2, 0) / n);
}

export function mae(xs, ys) {
  const n = xs.length;
  return xs.reduce((a, x, i) => a + Math.abs(x - ys[i]), 0) / n;
}

/** Solve a small dense linear system A x = b by Gaussian elimination. */
export function solveLinearSystem(A, b) {
  const n = A.length;
  const M = A.map((row, i) => [...row, b[i]]);
  for (let col = 0; col < n; col += 1) {
    let pivot = col;
    for (let r = col + 1; r < n; r += 1) {
      if (Math.abs(M[r][col]) > Math.abs(M[pivot][col])) pivot = r;
    }
    if (Math.abs(M[pivot][col]) < 1e-12) throw new Error("singular system");
    [M[col], M[pivot]] = [M[pivot], M[col]];
    for (let r = 0; r < n; r += 1) {
      if (r === col) continue;
      const f = M[r][col] / M[col][col];
      for (let c = col; c <= n; c += 1) M[r][c] -= f * M[col][c];
    }
  }
  return M.map((row, i) => row[n] / M[i][i]);
}

export function writeJson(filePath, obj) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(obj, null, 2)}\n`, "utf8");
  console.log(`wrote ${filePath}`);
}

/* ------------------------------------------------------------------ */
/* Micro-ISA (mirror of fhe-pod/scripts/application-lowering.mjs).     */
/* Kept as a literal copy so datasets/ has no import dependency on     */
/* fhe-pod; the numeric values MUST stay in sync with OPCODES there.   */
/* ------------------------------------------------------------------ */
export const OPCODES = Object.freeze({
  MUL: 1,
  SHR: 2,
  CAST_U8: 3,
  MIN: 4,
  BITAND: 5,
  ADD: 6,
  SUB: 7,
  DIV: 8,
  MOD: 9,
  EQ: 10,
  LT: 11,
  GT: 12,
  BITOR: 13,
  BITXOR: 14
});

/**
 * Tiny trace builder: records leaves {opcode_name, opcode, lhs, rhs, claimed}
 * evaluating each micro-op in the clear, exactly like the lowering engine's
 * ground-truth pass. `claimed` is the honest result; corruption for dispute
 * experiments is applied downstream by the existing fhe-pod tooling.
 */
export class Trace {
  constructor() {
    this.leaves = [];
  }

  emit(opcodeName, lhs, rhs, note) {
    if (!(opcodeName in OPCODES)) throw new Error(`unsupported opcode ${opcodeName}`);
    const a = Math.trunc(lhs);
    const b = Math.trunc(rhs);
    if (a < 0 || b < 0) throw new Error(`negative operand for ${opcodeName}: ${a}, ${b}`);
    let claimed;
    switch (opcodeName) {
      case "MUL": claimed = a * b; break;
      case "SHR": claimed = Math.floor(a / 2 ** b); break;
      case "CAST_U8": claimed = a % 256; break;
      case "MIN": claimed = Math.min(a, b); break;
      case "BITAND": claimed = a & b; break;
      case "ADD": claimed = a + b; break;
      case "SUB": {
        if (a < b) throw new Error(`unsigned underflow in SUB: ${a} - ${b}`);
        claimed = a - b;
        break;
      }
      case "DIV": claimed = Math.floor(a / b); break;
      case "MOD": claimed = a % b; break;
      case "EQ": claimed = a === b ? 1 : 0; break;
      case "LT": claimed = a < b ? 1 : 0; break;
      case "GT": claimed = a > b ? 1 : 0; break;
      case "BITOR": claimed = a | b; break;
      case "BITXOR": claimed = a ^ b; break;
      default: throw new Error(`unhandled opcode ${opcodeName}`);
    }
    this.leaves.push({
      leaf_index: this.leaves.length,
      opcode_name: opcodeName,
      opcode: OPCODES[opcodeName],
      lhs: a,
      rhs: b,
      claimed,
      ...(note ? { note } : {})
    });
    return claimed;
  }

  /** max(a, b) via GT-select: gt = [a>b]; max = gt*a + (1-gt)*b. */
  max(a, b, note) {
    const gt = this.emit("GT", a, b, note ? `${note}: gt` : undefined);
    const t1 = this.emit("MUL", gt, a);
    const inv = this.emit("SUB", 1, gt);
    const t2 = this.emit("MUL", inv, b);
    return this.emit("ADD", t1, t2, note ? `${note}: select` : undefined);
  }

  /** ReLU(x - t) without signed values: gt = [x>t]; out = gt * (x - min(x,t)). */
  reluShift(x, t, note) {
    const gt = this.emit("GT", x, t, note ? `${note}: gate` : undefined);
    const m = this.emit("MIN", x, t);
    const diff = this.emit("SUB", x, m);
    return this.emit("MUL", gt, diff, note ? `${note}: relu` : undefined);
  }

  addChain(values, note) {
    if (values.length === 0) throw new Error("addChain over empty list");
    let acc = values[0];
    for (let i = 1; i < values.length; i += 1) {
      acc = this.emit("ADD", acc, values[i], i === 1 && note ? note : undefined);
    }
    return acc;
  }
}

/* ------------------------------------------------------------------ */
/* Shared CLI + WebRTC-QoE helpers                                     */
/* ------------------------------------------------------------------ */
export function argValue(name, fallback) {
  const eq = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (eq) return eq.split("=").slice(1).join("=");
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--")) return process.argv[i + 1];
  return fallback;
}

/** Recursively list files under dir (depth-limited). */
export function listFiles(dir, depth = 3) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory() && depth > 0) out.push(...listFiles(full, depth - 1));
    else if (e.isFile()) out.push(full);
  }
  return out;
}

/**
 * Locate and parse the WebRTC-QoE subjective-scores table
 * (Zenodo 15836614, CC BY 4.0: 20 users x 15 test conditions, ACR 1-5,
 * columns for test condition, delay, jitter, packet loss rate, user, score).
 * Column names are DISCOVERED from the header so renames upstream do not
 * break the pipeline.
 */
export function loadWebrtcSubjective(rawDir) {
  const files = listFiles(rawDir, 3).filter((f) => f.toLowerCase().endsWith(".csv"));
  for (const f of files) {
    const { header, rows } = loadTable(f);
    const find = (re, exclude = []) =>
      header.find((h) => re.test(h) && !exclude.some((x) => x === h));
    const cDelay = find(/delay/i);
    const cJitter = find(/jitter/i);
    const cPlr = find(/packet|loss/i);
    if (!cDelay || !cJitter || !cPlr) continue;

    // The published table is WIDE: one row per test condition, with one column
    // per subject (`User1` ... `User20`) holding that subject's ACR score. An
    // earlier long layout (one row per (condition, subject) with a single score
    // column) is also accepted, because the mock used when the download is
    // absent is written that way. Melt the wide form to the long form so that
    // everything downstream sees one session per (condition, subject).
    const perSubject = header.filter((h) => /^user\s*\d+$/i.test(h.trim()));
    const sessions = [];
    if (perSubject.length >= 2) {
      const cTc = find(/^tc$|test.?condition/i, [cDelay, cJitter, cPlr]);
      for (const r of rows) {
        for (const column of perSubject) {
          sessions.push({
            tc: cTc ? r[cTc] : `${r[cDelay]}/${r[cJitter]}/${r[cPlr]}`,
            user: column.trim(),
            delayMs: Number.parseFloat(r[cDelay]),
            jitterMs: Number.parseFloat(r[cJitter]),
            plrPct: Number.parseFloat(r[cPlr]),
            score: Math.round(Number.parseFloat(r[column]))
          });
        }
      }
    } else {
      const cUser = find(/user|subject|participant/i);
      const cScore = find(/acr|score|rating|mos/i, [cUser, cDelay, cJitter, cPlr]);
      const cTc = find(/^tc$|test.?condition/i, [cUser, cDelay, cJitter, cPlr, cScore]);
      if (!cUser || !cScore) continue;
      for (const r of rows) {
        sessions.push({
          tc: cTc ? r[cTc] : `${r[cDelay]}/${r[cJitter]}/${r[cPlr]}`,
          user: r[cUser],
          delayMs: Number.parseFloat(r[cDelay]),
          jitterMs: Number.parseFloat(r[cJitter]),
          plrPct: Number.parseFloat(r[cPlr]),
          score: Math.round(Number.parseFloat(r[cScore]))
        });
      }
    }

    const usable = sessions.filter(
      (s) => Number.isFinite(s.delayMs) && Number.isFinite(s.score) && s.score >= 1 && s.score <= 5
    );
    if (usable.length >= 30) {
      return {
        file: f,
        layout: perSubject.length >= 2 ? "wide" : "long",
        columns: { cDelay, cJitter, cPlr, subjects: perSubject.length || null },
        sessions: usable
      };
    }
  }
  return null;
}

/** Locate OpenFace-style facial-feature CSVs (gaze_angle_x column present). */
export function findFacialCsvs(rawDir) {
  return listFiles(rawDir, 4)
    .filter((f) => f.toLowerCase().endsWith(".csv"))
    .filter((f) => {
      try {
        const fd = fs.openSync(f, "r");
        const buf = Buffer.alloc(4096);
        const n = fs.readSync(fd, buf, 0, 4096, 0);
        fs.closeSync(fd);
        return buf.toString("utf8", 0, n).split(/\r?\n/)[0].includes("gaze_angle_x");
      } catch { return false; }
    })
    .sort();
}
