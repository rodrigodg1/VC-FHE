/**
 * Stage-by-stage narrator for the SIMPLIFIED ANATEL RQUAL demonstration.
 *
 * Same purpose as ../anatel-rqual/narrate-anatel-rqual.mjs, over the short
 * trace. Because the whole trace is 32 leaves, this narrator never elides: every
 * act prints every leaf it produced, and act 6 prints the trace end to end on
 * one screen. That is the reason this variant exists.
 *
 * It computes nothing of its own. Every number is read back from the witnesses
 * `lowerSimplifiedRqual()` emitted, and every leaf is re-checked against the
 * micro-ISA reference predicate before being displayed. It contacts no chain,
 * spawns no process and writes no file.
 *
 * USAGE
 *   node Anatel/anatel-rqual-simplificado/narrate-anatel-simplified.mjs
 *   node Anatel/anatel-rqual-simplificado/narrate-anatel-simplified.mjs --pause
 *   node Anatel/anatel-rqual-simplificado/narrate-anatel-simplified.mjs --acts 1-6
 *
 * Or through the wrapper:
 *   NARRATE=1 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh
 *   NARRATE=1 NARRATE_PAUSE=1 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh
 */
import readline from "node:readline";

import { simplifiedRqualInputs } from "./anatel-rqual-simplified-fixtures.mjs";
import { lowerSimplifiedRqual } from "./anatel-rqual-simplified-lowering.mjs";
import { evaluateLeaf } from "../../fhe-pod/scripts/micro-isa.mjs";

// ------------------------------------------------------------- arguments --

function parseActSpec(spec) {
  if (spec === undefined || spec === null || spec === "") {
    throw new Error("--act/--acts requires a value, for example 5, 1-6 or 0,2,5");
  }
  const wanted = new Set();
  for (const part of String(spec).split(",")) {
    const range = part.trim().match(/^(\d+)\s*-\s*(\d+)$/);
    if (range) {
      const from = Number.parseInt(range[1], 10);
      const to = Number.parseInt(range[2], 10);
      if (to < from) throw new Error(`--acts range "${part}" runs backwards`);
      for (let n = from; n <= to; n += 1) wanted.add(n);
      continue;
    }
    const single = Number.parseInt(part.trim(), 10);
    if (!Number.isInteger(single)) throw new Error(`--acts: "${part}" is not an act number`);
    wanted.add(single);
  }
  return wanted;
}

function parseArgs(argv) {
  const parsed = { pause: false, slowSeconds: 0, act: null, color: true, bare: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--pause") parsed.pause = true;
    else if (arg === "--bare") parsed.bare = true;
    else if (arg === "--no-color") parsed.color = false;
    // Accepted and ignored: the full narrator elides long chains and needs this
    // flag; here nothing is ever elided, so honouring it would be a no-op and
    // rejecting it would break the shared wrapper that passes it through.
    else if (arg === "--leaves") continue;
    else if (arg === "--slow") {
      i += 1;
      const value = Number.parseFloat(argv[i]);
      if (!Number.isFinite(value) || value < 0) throw new Error("--slow requires a number of seconds");
      parsed.slowSeconds = value;
    } else if (arg.startsWith("--slow=")) {
      parsed.slowSeconds = Number.parseFloat(arg.slice(7));
    } else if (arg === "--act" || arg === "--acts") {
      i += 1;
      parsed.act = parseActSpec(argv[i]);
    } else if (arg.startsWith("--act=")) {
      parsed.act = parseActSpec(arg.slice(6));
    } else if (arg.startsWith("--acts=")) {
      parsed.act = parseActSpec(arg.slice(7));
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: node Anatel/anatel-rqual-simplificado/narrate-anatel-simplified.mjs [options]

  --pause        wait for Enter between acts (use this in a live meeting)
  --slow <s>     auto-advance every <s> seconds
  --acts <spec>  print only these acts: 5, or 1-6, or 0,2,5  (--act is a synonym)
  --bare         omit the opening banner and the closing footer
  --leaves       accepted and ignored; this trace is short enough to always print in full
  --no-color     plain text, for logs and for projectors that mangle ANSI
  --help         this message`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (parsed.pause && parsed.slowSeconds > 0) {
    throw new Error("--pause and --slow are mutually exclusive");
  }
  return parsed;
}

const config = parseArgs(process.argv.slice(2));

// ------------------------------------------------------------- rendering --

const USE_COLOR = config.color && process.stdout.isTTY === true && !process.env.NO_COLOR;
const c = (code) => (s) => (USE_COLOR ? `[${code}m${s}[0m` : String(s));
const bold = c("1");
const dim = c("2");
const cyan = c("36");
const yellow = c("33");
const green = c("32");
const red = c("31");

const WIDTH = 78;
const rule = (ch = "-") => ch.repeat(WIDTH);

function actHeader(n, total, title, slide) {
  console.log("");
  console.log(cyan(rule("=")));
  console.log(cyan(bold(` ACT ${n}/${total}  ${title}`)));
  if (slide) console.log(cyan(dim(` deck: ${slide}`)));
  console.log(cyan(rule("=")));
}

function para(text) {
  const words = String(text).split(/\s+/);
  let line = "";
  console.log("");
  for (const word of words) {
    if (line.length + word.length + 1 > WIDTH) {
      console.log("  " + line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) console.log("  " + line);
}

const bullet = (t) => console.log(`  ${yellow("*")} ${t}`);
const kv = (label, value) => console.log(`  ${label.padEnd(34)} ${bold(value)}`);
const blank = () => console.log("");

function leafHeader() {
  console.log("");
  console.log(dim("   idx  opcode        lhs         rhs     claimed   note"));
  console.log(dim("   ---  ------  ---------  ----------  ----------   " + "-".repeat(34)));
}

function leafLine(w, mark) {
  console.log(
    `   ${String(w.leaf_index).padStart(3)}  ${w.opcode_name.padEnd(6)}  ` +
      `${String(w.lhs).padStart(9)}  ${String(w.rhs).padStart(10)}  ` +
      `${bold(String(w.claimed).padStart(10))}   ${dim(w.note)}${mark ? red(" <<") : ""}`
  );
}

/** Prints a block of leaves in full. Nothing is ever elided in this variant. */
function leafBlock(witnesses, { highlight = [] } = {}) {
  if (witnesses.length === 0) return;
  leafHeader();
  for (const w of witnesses) leafLine(w, highlight.includes(w.leaf_index));
}

async function waitForNext(actIndex, total) {
  if (config.slowSeconds > 0) {
    await new Promise((resolve) => setTimeout(resolve, config.slowSeconds * 1000));
    return;
  }
  if (!config.pause || actIndex >= total || !process.stdin.isTTY) return;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  await new Promise((resolve) => {
    rl.question(dim("\n  [Enter] next act, or Ctrl-C to stop  "), () => {
      rl.close();
      resolve();
    });
  });
}

// ----------------------------------------------------------------- model --

const inputs = simplifiedRqualInputs();
const workload = lowerSimplifiedRqual(inputs);
const W = workload.witnesses;
const model = workload.model;
const P = model.declaredParameters;
const L = model.leafIndex;
const unpadded = workload.lowering.unpaddedLeafCount;
const padded = workload.lowering.paddedLeafCount;
const manipulated = workload.defaultManipulatedLeafIndex;

const byPrefix = (prefix) => W.filter((w) => w.note.startsWith(prefix));

function verifyTrace() {
  const failures = [];
  for (const [index, w] of W.entries()) {
    if (w.leaf_index !== index) failures.push(`leaf ${index} declares leaf_index ${w.leaf_index}`);
    const verdict = evaluateLeaf(w.opcode_name, w.lhs, w.rhs);
    if (!verdict.valid) failures.push(`leaf ${index} (${w.opcode_name}) invalid: ${verdict.reason}`);
    else if (Number(verdict.value) !== Number(w.claimed)) {
      failures.push(`leaf ${index} claims ${w.claimed}, micro-ISA yields ${verdict.value}`);
    }
  }
  return failures;
}

function bisectionLadder(size, target) {
  const rounds = [];
  let lo = 0;
  let hi = size - 1;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    const goLeft = target <= mid;
    rounds.push({ lo, hi, mid, side: goLeft ? "left" : "right" });
    if (goLeft) hi = mid;
    else lo = mid + 1;
  }
  return rounds;
}
const ladder = bisectionLadder(padded, manipulated);

const LEAF_BUDGET = [
  ["IR and its inversion", "IR: ", "the formula, plus the MIN guard"],
  ["F(IQS)", "F(IQS):", `${P.bandEdgesPermille.length} edges: k GT + (k-1) ADD`],
  ["F(IQP)", "F(IQP):", `${P.bandEdgesPermille.length} edges: k GT + (k-1) ADD`],
  ["F(IR)", "F(IR):", `${P.bandEdgesPermille.length} edges: k GT + (k-1) ADD`],
  ["S", "S:", "3 terms cost 3 - 1 adds"],
  ["seal", "seal:", `${P.sealCutoffs.length} cut-offs: k GT + (k-1) ADD`],
];

// ------------------------------------------------------------------ acts --

const acts = [];
const act = (title, slide, body) => acts.push({ title, slide, body });

/* ---------------------------------------------------------------- act 0 -- */
act("The same expression, on the shortest trace that still carries it", "slide 2", () => {
  para(
    "This is the teaching variant. The expression is the one the regulator publishes, identical to " +
      "the full demonstration in ../anatel-rqual/; what changed is only how much work happens before " +
      "the expression starts."
  );
  blank();
  console.log("    IR  = 1000 * A_P / B_P        IRscore = 1000 - min(IR, 1000)");
  console.log("    " + bold("S = F(IQS) + F(IQP) + F(IR)   ->   quality seal"));
  blank();
  console.log(dim("                              this variant      ../anatel-rqual/"));
  console.log(`    useful leaves               ${bold(String(unpadded).padEnd(16))} 89`);
  console.log(`    padded leaves               ${bold(String(padded).padEnd(16))} 128`);
  console.log(`    bisection rounds            ${bold(String(ladder.length).padEnd(16))} 7`);
  console.log(`    IQS and IQP                 ${bold("given".padEnd(16))} computed from panels`);
  console.log(`    band edges in F(.)          ${bold(String(P.bandEdgesPermille.length).padEnd(16))} 4`);
  console.log(`    measured inputs             ${bold("none".padEnd(16))} 36 records`);
  blank();
  bullet("Verified against Res. 717/2019: Art. 7 defines IQS (VI), IQP (VII) and IR (V); Art. 11 assigns seals A to E.");
  bullet(red("NOT verified, and NOT measured: every number below is a declared deployment parameter."));
  bullet(red("Because F(.) has three edges here and four there, the two runs release different seals. That is by construction."));
});

/* ---------------------------------------------------------------- act 1 -- */
act("Everything becomes an unsigned 64-bit integer", "slide 4", () => {
  para(
    "The dispute has to be settled by a rule two parties cannot read differently, so the computation " +
      "runs over unsigned 64-bit integers, with fractions carried as permille. These are all the " +
      "uint64 values this run created."
  );

  const rows = [
    ["ENCRYPT", "IQS, technical indicator", [inputs.iqsPermille], "permille, given directly"],
    ["ENCRYPT", "IQP, perceived-quality indicator", [inputs.iqpPermille], "permille, given directly"],
    ["ENCRYPT", "A_P, complaint count", [inputs.complaintsAp], "count"],
    ["PUBLIC ", "B_P, access base", [inputs.accessBaseBp], "DIV right-hand scalar"],
    ["PUBLIC ", "permille scale", [1000], "MUL right-hand constant"],
    ["PUBLIC ", "band edges F(.)", P.bandEdgesPermille, "GT right-hand constants"],
    ["PUBLIC ", "seal cut-offs", P.sealCutoffs, "GT right-hand constants"],
  ];
  const VALUE_COL = 26;
  blank();
  console.log(dim("   " + "role".padEnd(7) + "  " + "what it is".padEnd(32) + "  " + "uint64".padEnd(VALUE_COL) + "  role in the trace"));
  console.log(dim("   -------  --------------------------------  " + "-".repeat(VALUE_COL) + "  " + "-".repeat(23)));
  for (const [role, label, values, unit] of rows) {
    const paint = role.trim() === "ENCRYPT" ? red : green;
    console.log(`   ${paint(role)}  ${label.padEnd(32)}  ${bold(values.join(" ").padEnd(VALUE_COL))}  ${dim(unit)}`);
  }
  const enc = rows.filter((r) => r[0].trim() === "ENCRYPT").reduce((n, r) => n + r[2].length, 0);
  const pub = rows.filter((r) => r[0].trim() === "PUBLIC").reduce((n, r) => n + r[2].length, 0);
  blank();
  kv("encrypted input operands", `${enc}   (against 37 in the full demonstration)`);
  kv("public program constants", `${pub}`);
  blank();
  para(
    "The split is forced by the instruction set: DIV, MOD and SHR take a public scalar on the right " +
      "only, which is why A_P is encrypted and B_P is not."
  );
  blank();
  const failures = verifyTrace();
  if (failures.length === 0) {
    console.log("  " + green(`every one of the ${padded} leaves re-evaluated against the micro-ISA: OK`));
  } else {
    console.log("  " + red(`micro-ISA re-evaluation FAILED (${failures.length}):`));
    for (const f of failures.slice(0, 5)) console.log("    " + red(f));
    process.exitCode = 1;
  }
});

/* ---------------------------------------------------------------- act 2 -- */
act("IR: four leaves that carry both rules of the instruction set", "slide 5", () => {
  para(
    "The complaint indicator is the only stage of this variant that still computes something rather " +
      "than receiving it, and it was kept for that reason: in four leaves it shows the public-scalar " +
      "division rule and the underflow guard, which nothing else in the trace would show."
  );
  leafBlock(byPrefix("IR: "));
  blank();
  console.log("  " + bold(`IR = 1000 * ${P.complaintsAp} / ${P.accessBaseBp} = ${model.irPermille} permille`) + dim(`   [leaf ${L.ir}]`));
  console.log("  " + bold(`IRscore = 1000 - min(${model.irPermille}, 1000) = ${model.irScorePermille} permille`) + dim(`   [leaf ${L.irScore}]`));
  blank();
  bullet(`leaf ${L.ir}: the divisor B_P is a PUBLIC scalar, because DIV rejects an encrypted right-hand operand`);
  bullet(`leaf ${L.irScore - 1}: the MIN clamps IR to the ceiling BEFORE the SUB, because an underflowing SUB is rejected`);
  bullet("without that MIN, a provider with more complaints than accesses would abort the trace, not score zero");
});

/* ---------------------------------------------------------------- act 3 -- */
act("F(.): a band table with no branching, three times", "slide 5", () => {
  para(
    "F maps an indicator to a band. In a document it is a table of ranges; in a branch-free integer " +
      "machine it is a count of edges the indicator exceeds: one GT per edge, then a chain of adds to " +
      "count the ones that fired. Both sides of every decision are computed, so the instruction " +
      "sequence does not depend on the data."
  );
  blank();
  kv("declared band edges (permille)", `[${P.bandEdgesPermille.join(", ")}]`);
  blank();
  for (const [label, value, leafIdx, band] of [
    ["F(IQS)", model.iqsPermille, L.bandIqs, model.bandIqs],
    ["F(IQP)", model.iqpPermille, L.bandIqp, model.bandIqp],
    ["F(IR) ", model.irScorePermille, L.bandIr, model.bandIr],
  ]) {
    const exceeded = P.bandEdgesPermille.filter((e) => value > e);
    console.log(
      `  ${bold(label)} = |{ ${exceeded.join(", ") || "-"} }| = ${bold(String(band))}` +
        dim(`      (${value} permille exceeds ${exceeded.length} of ${P.bandEdgesPermille.length} edges)  [leaf ${leafIdx}]`)
    );
  }
  leafBlock([...byPrefix("F(IQS):"), ...byPrefix("F(IQP):"), ...byPrefix("F(IR):")]);
});

/* ---------------------------------------------------------------- act 4 -- */
act("S and the seal: the only value that leaves the computation", "slide 6", () => {
  leafBlock([...byPrefix("S:"), ...byPrefix("seal:")]);
  blank();
  console.log(
    "  " + bold(`S = ${model.bandIqs} + ${model.bandIqp} + ${model.bandIr} = ${model.compositeScoreS}`) +
      dim(`  (range 0..${model.compositeScoreMax})   [leaf ${L.compositeScoreS}]`)
  );
  kv("declared seal cut-offs", `[${P.sealCutoffs.join(", ")}]`);
  console.log(
    "  " + bold(`seal index = ${model.sealIndex}`) +
      (model.sealLabel ? bold(`  (band "${model.sealLabel}")`) : "") +
      dim(`   [leaf ${L.sealIndex}, the released value]`)
  );
  blank();
  para(
    "Four cut-offs are kept even though F(.) lost an edge, because Art. 11 establishes five seals and " +
      "five bands need four separators. They are placed inside 0.." + model.compositeScoreMax +
      " so that every one of the five seals is reachable; the parameter loader rejects a cut-off that " +
      "would leave a band dead."
  );
});

/* ---------------------------------------------------------------- act 5 -- */
act("The whole trace, and where every leaf came from", "slide 5", () => {
  para(
    "This is the point of the variant: the entire committed trace on one screen. No count below was " +
      "chosen by hand. One comparison per edge, n-1 additions to add n values, one multiplication per " +
      "scale change, one division per normalisation by a public scalar."
  );
  blank();
  console.log(dim("   part of the formula                leaves  positions   why that many"));
  console.log(dim("   ---------------------------------  ------  ---------   " + "-".repeat(28)));
  let budgeted = 0;
  for (const [label, prefix, why] of LEAF_BUDGET) {
    const g = W.filter((x) => x.note.startsWith(prefix));
    if (g.length === 0) continue;
    budgeted += g.length;
    const span = `${g[0].leaf_index}..${g[g.length - 1].leaf_index}`;
    console.log(`   ${label.padEnd(33)}  ${String(g.length).padStart(6)}  ${span.padStart(9)}   ${dim(why)}`);
  }
  console.log(dim("   ---------------------------------  ------  ---------"));
  console.log(`   ${"useful".padEnd(33)}  ${String(unpadded).padStart(6)}  ${`0..${unpadded - 1}`.padStart(9)}`);
  console.log(
    `   ${"padding, ADD 0+0".padEnd(33)}  ${String(padded - unpadded).padStart(6)}  ` +
      `${`${unpadded}..${padded - 1}`.padStart(9)}   ${dim("to the next power of two")}`
  );
  console.log(`   ${bold("total".padEnd(33))}  ${bold(String(padded).padStart(6))}  ${`0..${padded - 1}`.padStart(9)}`);
  if (budgeted !== unpadded) {
    console.log("  " + red(`accounting does not close: ${budgeted} attributed, ${unpadded} useful.`));
  }
  blank();
  kv("opcode histogram", JSON.stringify(workload.lowering.opcodeHistogram));
  leafBlock(W, { highlight: [manipulated] });
});

/* ---------------------------------------------------------------- act 6 -- */
act("Encryption, authorization, and the optimistic path", "slides 7 to 9", () => {
  para(
    "From here the pipeline is the full demonstration's, unchanged. Every leaf above is executed over " +
      "real FheUint64 ciphertexts with tfhe-rs, in both variants, honest and corrupted, and every " +
      "result is decrypted and checked against the value the lowering claims."
  );
  blank();
  console.log("    " + bold("handle = keccak256( safe_serialize( ciphertext ) )"));
  blank();
  kv("leaves executed under encryption", `${padded} honest + ${padded} corrupted = ${2 * padded}`);
  kv("in the full demonstration", "256");
  blank();
  para(
    "Each input operand is then registered as (owner, handle, metadata hash), signed by its owner, and " +
      "the requester signs five roots: inputs, program, provenance, trace and the output commitment. " +
      "After that the operator cannot change the formula or the records without an on-chain check failing."
  );
  blank();
  console.log("  " + green(`released if nobody challenges:  sealIndex = ${model.sealIndex}` + (model.sealLabel ? ` (band "${model.sealLabel}")` : "")));
  console.log("  " + dim("withheld:  IQS, IQP, IR, the complaint count, and every intermediate value"));
  blank();
  para(
    "An unchallenged task finalizes with no verification at all. The security comes from challenging " +
      "being cheap and lying being expensive, not from re-execution."
  );
});

/* ---------------------------------------------------------------- act 7 -- */
act("The dispute: five rounds instead of seven", "slides 10 to 12", () => {
  const w = W[manipulated];
  para(
    "The run creates two tasks: one with this trace and one in which exactly leaf " + manipulated +
      " was altered, the last real instruction, the one that produces the released seal. The operator " +
      "must publish the whole trace as calldata before bisection starts: per leaf the opcode, the three " +
      "handles and the provenance of each operand, and no operand value."
  );
  blank();
  leafBlock([w], { highlight: [manipulated] });
  blank();
  console.log(`  Bisection ladder for leaf ${bold(String(manipulated))} over ${padded} leaves, ${bold(String(ladder.length))} rounds:`);
  blank();
  for (const [i, r] of ladder.entries()) {
    const next = r.side === "left" ? `[${r.lo}, ${r.mid}]` : `[${r.mid + 1}, ${r.hi}]`;
    console.log(
      `    round ${String(i + 1).padStart(2)}   interval [${String(r.lo).padStart(3)}, ${String(r.hi).padStart(3)}]` +
        `   midpoint ${String(r.mid).padStart(3)}   go ${r.side.padEnd(5)} -> ${bold(next)}`
    );
  }
  blank();
  console.log(`    ${green(`isolated: leaf ${manipulated}`)}`);
  blank();
  para(
    `Publishing costs N and locating costs log2(N): ${ladder.length} rounds for ${padded} leaves, against 7 for ` +
      "128. Quartering the trace removed two rounds, which is the shape of a logarithm and is worth " +
      "saying out loud when both runs are shown."
  );
});

/* ---------------------------------------------------------------- act 8 -- */
act("Leaf decision under encryption, and settlement", "slides 13 and 14", () => {
  para("The isolated leaf is recomputed homomorphically from the ciphertexts of its operands, and each side's claim is compared against that recomputation.");
  blank();
  console.log("    recomputed := eval( opcode, lhsCiphertext, rhsCiphertext )     " + dim("// homomorphic"));
  console.log("    valid      := decrypt( FHE.eq( recomputed, claimed ) )        " + dim("// only the BIT"));
  blank();
  bullet("only the equality bit is decrypted: never an operand, never a result, never a claim");
  bullet("each adjudicated ciphertext must hash to the handle published on-chain, or it is not adjudicated");
  bullet("the bit reaches the chain with t+1 EIP-712 signatures bound to this contract, chain, task, leaf and opcode");
  bullet("auditor votes settle nothing; the rule is objective and lives in the contract");
  blank();
  para(
    "The dishonest operator is slashed, the challenger's bond is returned, the honest task finalizes as " +
      "accepted, and the seal attached to the corrupted trace falls with it, because the output " +
      "commitment was bound on-chain to that trace's terminal leaf at task creation."
  );
  blank();
  para(
    "What is modelled, said without rounding: here the recomputation and the single decryption run in a " +
      "local process holding the evaluation key pair. In production the recomputation runs on the FHEVM " +
      "coprocessor and the bits are threshold-decrypted by the key-management service. The transport, " +
      "the EIP-712 digest, the t+1 rule and the on-chain verification code are the production ones."
  );
});

// ------------------------------------------------------------------- run --

if (!config.bare) {
  console.log("");
  console.log(bold(rule("=")));
  console.log(bold(" ANATEL RQUAL  |  SIMPLIFIED teaching narration"));
  console.log(bold(rule("=")));
  console.log("");
  console.log("  " + red("TEACHING DEMONSTRATION. Nothing here is measured data."));
  console.log("  Only the STRUCTURE of the expression was verified against Res. 717/2019.");
  console.log("  Every indicator, edge and cut-off is a DECLARED DEPLOYMENT PARAMETER.");
  console.log("  F(.) uses three band edges here and four in ../anatel-rqual/, so the two");
  console.log("  demonstrations release different seals. The seal is NOT an official result.");
  console.log("");
  console.log(dim("  No chain is contacted, no process is spawned and no file is written."));
}

const selected = acts
  .map((a, i) => ({ ...a, number: i }))
  .filter((a) => config.act === null || config.act.has(a.number));
if (selected.length === 0) {
  console.error(`No such act: ${[...config.act].join(", ")}. Valid range is 0 to ${acts.length - 1}.`);
  process.exit(1);
}

for (const [i, a] of selected.entries()) {
  actHeader(a.number, acts.length - 1, a.title, a.slide);
  a.body();
  await waitForNext(i + 1, selected.length);
}

if (!config.bare) {
  console.log("");
  console.log(bold(rule("=")));
  console.log(bold(" Narration complete."));
  console.log(bold(rule("=")));
  console.log("");
  console.log("  To perform what acts 6 to 8 describe, against the validator network:");
  console.log("     " + bold("Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh"));
  console.log("");
}
