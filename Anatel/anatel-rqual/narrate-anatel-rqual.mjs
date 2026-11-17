/**
 * Stage-by-stage narrator for the ANATEL RQUAL demonstration.
 *
 * PURPOSE
 * -------
 * `run-anatel-rqual-demo.mjs` reports the lowering as aggregates: leaf counts,
 * an opcode histogram, the reference values. That is the right output for a
 * recorded run and the wrong output for a live audience, which needs to see the
 * formula turning into leaves one stage at a time.
 *
 * This file prints the SAME trace, produced by the SAME `lowerAnatelRqual()`,
 * as eleven acts that follow the walkthrough deck slide by slide. It computes
 * nothing of its own: every number it shows is read back from the witnesses the
 * lowering emitted, and every leaf is re-checked against the micro-ISA
 * reference predicate before being displayed.
 *
 * It contacts no chain, spawns no process and writes no file. It is safe to run
 * at any point, including mid-meeting.
 *
 * USAGE
 * -----
 *   node Anatel/anatel-rqual/narrate-anatel-rqual.mjs                 print all acts
 *   node Anatel/anatel-rqual/narrate-anatel-rqual.mjs --pause         wait for Enter between acts
 *   node Anatel/anatel-rqual/narrate-anatel-rqual.mjs --slow 6        auto-advance every 6 s
 *   node Anatel/anatel-rqual/narrate-anatel-rqual.mjs --leaves        print every leaf of each act
 *   node Anatel/anatel-rqual/narrate-anatel-rqual.mjs --act 4         print one act and exit
 *   node Anatel/anatel-rqual/narrate-anatel-rqual.mjs --no-color      plain text
 *
 * Or through the wrapper:
 *   NARRATE=1 Anatel/anatel-rqual/run-anatel-demo.sh
 *   NARRATE=1 NARRATE_PAUSE=1 Anatel/anatel-rqual/run-anatel-demo.sh
 *
 * WHAT IT DOES NOT DO
 * -------------------
 * Acts 7 to 11 describe the encrypted execution, the on-chain phases and the
 * settlement. The narrator does NOT perform them: it explains what the live run
 * does at each point and prints the values that are already determined by the
 * trace, such as the exact bisection interval sequence. To perform them, run
 * `Anatel/anatel-rqual/run-anatel-demo.sh` without NARRATE.
 */
import readline from "node:readline";

import { anatelRqualInputs } from "./anatel-rqual-fixtures.mjs";
import { lowerAnatelRqual } from "./anatel-rqual-lowering.mjs";
import { evaluateLeaf } from "../../fhe-pod/scripts/micro-isa.mjs";

// ------------------------------------------------------------- arguments --

/**
 * Act selector: "5" one act, "1-6" a range, "0,2,5" a list, or any combination.
 * Returns a Set of act numbers, or null for "all".
 */
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
  const parsed = { pause: false, slowSeconds: 0, leaves: false, act: null, color: true, bare: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--pause") parsed.pause = true;
    else if (arg === "--leaves") parsed.leaves = true;
    else if (arg === "--bare") parsed.bare = true;
    else if (arg === "--no-color") parsed.color = false;
    else if (arg === "--slow") {
      i += 1;
      const value = Number.parseFloat(argv[i]);
      if (!Number.isFinite(value) || value < 0) throw new Error("--slow requires a number of seconds");
      parsed.slowSeconds = value;
    } else if (arg.startsWith("--slow=")) {
      const value = Number.parseFloat(arg.slice(7));
      if (!Number.isFinite(value) || value < 0) throw new Error("--slow requires a number of seconds");
      parsed.slowSeconds = value;
    } else if (arg === "--act" || arg === "--acts") {
      i += 1;
      parsed.act = parseActSpec(argv[i]);
    } else if (arg.startsWith("--act=")) {
      parsed.act = parseActSpec(arg.slice(6));
    } else if (arg.startsWith("--acts=")) {
      parsed.act = parseActSpec(arg.slice(7));
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: node Anatel/anatel-rqual/narrate-anatel-rqual.mjs [options]

  --pause        wait for Enter between acts (use this in a live meeting)
  --slow <s>     auto-advance every <s> seconds
  --leaves       print every leaf of every act, not just the summary
  --acts <spec>  print only these acts: 5, or 1-6, or 0,2,5  (--act is a synonym)
  --bare         omit the opening banner and the closing footer. Used when the
                 full run calls this file phase by phase, so the disclaimer and
                 the footer are not repeated three times in one run
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

// Colour only when a terminal is attached and the environment does not opt out.
// A projector fed by a pipe, a CI log and `| tee` all end up without escapes.
const USE_COLOR =
  config.color && process.stdout.isTTY === true && !process.env.NO_COLOR;

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
  // Wrap at WIDTH so the output stays readable when projected.
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

function bullet(text) {
  console.log(`  ${yellow("*")} ${text}`);
}

function kv(label, value) {
  console.log(`  ${label.padEnd(34)} ${bold(value)}`);
}

function blank() {
  console.log("");
}

function leafHeader() {
  console.log("");
  console.log(dim("   idx  opcode        lhs         rhs     claimed   note"));
  console.log(dim("   ---  ------  ---------  ----------  ----------   " + "-".repeat(34)));
}

function leafLine(w, mark) {
  const flag = mark ? red(" <<") : "";
  console.log(
    `   ${String(w.leaf_index).padStart(3)}  ${w.opcode_name.padEnd(6)}  ` +
      `${String(w.lhs).padStart(9)}  ${String(w.rhs).padStart(10)}  ` +
      `${bold(String(w.claimed).padStart(10))}   ${dim(w.note)}${flag}`
  );
}

/**
 * Prints a block of leaves. Long blocks are elided in the middle unless
 * --leaves was given, because a 20-leaf accumulation chain scrolling past is
 * noise, not evidence.
 */
function leafBlock(witnesses, { highlight = [], maxRows = 8 } = {}) {
  if (witnesses.length === 0) return;
  leafHeader();
  const show = config.leaves || witnesses.length <= maxRows;
  if (show) {
    for (const w of witnesses) leafLine(w, highlight.includes(w.leaf_index));
    return;
  }
  const head = Math.ceil(maxRows / 2);
  const tail = Math.floor(maxRows / 2);
  for (const w of witnesses.slice(0, head)) leafLine(w, highlight.includes(w.leaf_index));
  console.log(
    dim(`   ...  ${witnesses.length - head - tail} more leaves of the same kind (run with --leaves to see them all)`)
  );
  for (const w of witnesses.slice(-tail)) leafLine(w, highlight.includes(w.leaf_index));
}

async function waitForNext(actIndex, total) {
  if (config.slowSeconds > 0) {
    await new Promise((resolve) => setTimeout(resolve, config.slowSeconds * 1000));
    return;
  }
  if (!config.pause) return;
  if (actIndex >= total) return;
  // A non-interactive stdin (a pipe, a CI runner) would hang here forever.
  if (!process.stdin.isTTY) return;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  await new Promise((resolve) => {
    rl.question(dim("\n  [Enter] next act, or Ctrl-C to stop  "), () => {
      rl.close();
      resolve();
    });
  });
}

// ----------------------------------------------------------------- model --

const inputs = anatelRqualInputs();
const workload = lowerAnatelRqual(inputs);
const W = workload.witnesses;
const model = workload.model;
const P = model.declaredParameters;
const L = model.leafIndex;
const unpadded = workload.lowering.unpaddedLeafCount;
const padded = workload.lowering.paddedLeafCount;

/** Every leaf whose note starts with the given prefix, in trace order. */
const byPrefix = (prefix) => W.filter((w) => w.note.startsWith(prefix));

/** Re-checks the trace against the micro-ISA before narrating anything. */
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

/**
 * The exact interval sequence the bisection game walks to isolate `target`
 * over a trace of `size` leaves. Deterministic, so it can be shown before the
 * dispute is ever played.
 */
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

const manipulated = workload.defaultManipulatedLeafIndex;
const ladder = bisectionLadder(padded, manipulated);

/**
 * Leaf budget: which part of the formula produced which leaves, and the reason
 * that part costs that many. The counts are not written here; they are counted
 * off the emitted trace, so this table cannot drift from the lowering.
 */
const LEAF_BUDGET = [
  ["IQS, one comparison per session", "IQS: session", `panel holds ${P.iqsSessionCount} sessions`],
  ["IQS, addition chain", "IQS: good-session count", `${P.iqsSessionCount} values cost ${P.iqsSessionCount} - 1 adds`],
  ["IQS, scale to permille", "IQS: scale", "one scale change"],
  ["IQS, divide by panel size", "IQS: permille", "public scalar divisor"],
  ["IQP, addition chain", "IQP: opinion-score", `${P.iqpPanelSize} ratings cost ${P.iqpPanelSize} - 1 adds`],
  ["IQP, scale to milli-units", "IQP: scale", "one scale change"],
  ["IQP, divide by panel size", "IQP: milli-ACR", "public scalar divisor"],
  ["IQP, divide by scale ceiling", "IQP: permille", "public scalar divisor"],
  ["IR and its inversion", "IR: ", "the formula, plus the MIN guard"],
  ["F(IQS)", "F(IQS):", `${P.bandEdgesPermille.length} edges: 4 GT + 3 ADD`],
  ["F(IQP)", "F(IQP):", `${P.bandEdgesPermille.length} edges: 4 GT + 3 ADD`],
  ["F(IR)", "F(IR):", `${P.bandEdgesPermille.length} edges: 4 GT + 3 ADD`],
  ["S", "S:", "3 terms cost 3 - 1 adds"],
  ["seal", "seal:", `${P.sealCutoffs.length} cut-offs: 4 GT + 3 ADD`],
];

// ------------------------------------------------------------------ acts --

const acts = [];
const act = (title, slide, body) => acts.push({ title, slide, body });

/* ---------------------------------------------------------------- act 0 -- */
act("The expression already exists in the regulation", "slide 2", () => {
  para(
    "Nothing in this stage is our design. The regulator publishes the shape of the assessment; " +
      "the protocol enters afterwards and answers a narrower question: did the operator compute " +
      "what it committed to compute, over the records that were registered?"
  );
  blank();
  console.log("    technical measurements   ->  IQS");
  console.log("    survey responses         ->  IQP = ISG");
  console.log("    user complaints          ->  IR  = 1000 * A_P / B_P");
  console.log("");
  console.log("    " + bold("S = F(IQS) + F(IQP) + F(IR)   ->   quality seal"));
  blank();
  bullet("Verified against Res. 717/2019: Art. 7 defines IQS (VI), IQP (VII) and IR (V); Art. 11 assigns seals A to E.");
  bullet(red("NOT verified: F(.), the band edges and the seal cut-offs. Those are declared deployment parameters."));
  bullet("The seal this run releases is " + red("not") + " an official ANATEL result.");
  blank();
  para(
    "Where the inputs come from. Two of the five groups are measured records from public datasets; " +
      "three are not measured at all, and saying which is which is part of presenting this honestly."
  );

  const prov = inputs.provenance;
  blank();
  console.log(`  ${bold("IQS")}  ${prov.iqs.n} technical measurements   ${green("MEASURED")}`);
  console.log(`       dataset   ${prov.iqs.datasetId}, drive-test campaign`);
  console.log(`       citation  ${dim(String(prov.iqs.datasetCitation).split(";").slice(0, 2).join(";"))}`);
  console.log(`       file      ${dim(prov.iqs.sourceCsv)}`);
  console.log(`       column    ${dim(`${prov.iqs.mosColumn} at base station ${prov.iqs.baseStation}`)}`);
  console.log(`       sampling  ${dim(prov.iqs.samplingRule)}`);
  console.log(`       rows      ${dim(prov.iqs.rowNumbers.join(", "))}`);
  console.log(`       frozen in ${dim(`${prov.iqs.fixtureFile} -> ${prov.iqs.fixturePanel}`)}`);
  blank();
  console.log(`  ${bold("IQP")}  ${prov.iqp.n} opinion scores from ${prov.iqp.subjects} distinct people   ${green("MEASURED")}`);
  console.log(`       dataset   ${prov.iqp.datasetId}, subjective test  (${prov.iqp.scale})`);
  console.log(`       citation  ${dim(prov.iqp.datasetCitation)}`);
  console.log(`       file      ${dim(prov.iqp.sourceCsv)}`);
  console.log(
    `       condition ${dim(`${prov.iqp.testCondition}: ${prov.iqp.impairment.delayMs} ms delay, ` +
      `${prov.iqp.impairment.jitterMs} ms jitter, ${prov.iqp.impairment.lossPercent} % loss`)}`
  );
  console.log(`       frozen in ${dim(`${prov.iqp.fixtureFile} -> ${prov.iqp.fixturePanel}`)}`);
  blank();
  console.log(`  ${bold("IR")}   A_P = ${P.complaintsAp}, B_P = ${P.accessBaseBp}   ${red("NOT MEASURED")}`);
  console.log(`       ${dim("no complaint register and no access-base filing was consulted;")}`);
  console.log(`       ${dim("both are illustrative period constants declared in the parameter file")}`);
  blank();
  console.log(`  ${bold("F(.)")} threshold ${P.iqsPoorThresholdMilli}, edges [${P.bandEdgesPermille.join(", ")}], ` +
    `cut-offs [${P.sealCutoffs.join(", ")}]   ${red("NOT MEASURED")}`);
  console.log(`       ${dim("declared by this repository; the regulation publishes none of them")}`);
});

/* ---------------------------------------------------------------- act 1 -- */
act("Everything becomes an unsigned 64-bit integer", "slide 4", () => {
  para(
    "A contract has to settle a disagreement without interpretation, so the whole computation is " +
      "expressed over unsigned 64-bit integers: no floating point, no signed value, no rounding mode. " +
      "Decimals enter as fixed scale, and the scaling is part of the program, not of the data."
  );
  blank();
  console.log(`    MOS ${(inputs.iqsValuesMilli[0] / 1000).toFixed(3)}   ->  ${inputs.iqsValuesMilli[0]}  milli-MOS      (x1000)`);
  console.log(`    ACR ${(model.iqpMeanMilli / 1000).toFixed(3)}   ->  ${model.iqpMeanMilli}  milli-ACR      (x1000)`);
  console.log(`    ${(model.iqsPermille / 10).toFixed(1)} %      ->   ${model.iqsPermille}  permille       (x1000)`);
  blank();
  para("These are the uint64 values this run created. Nothing else enters the trace.");

  const encrypted = [
    [`${inputs.iqsValuesMilli.length} drive-test measurements (IQS)`, inputs.iqsValuesMilli, "milli-MOS"],
    [`${inputs.iqpRatings.length} human ratings (IQP)`, inputs.iqpRatings, "ACR points"],
    ["A_P, complaint count (IR)", [inputs.complaintsAp], "count"],
  ];
  const publics = [
    ["B_P, access base", [inputs.accessBaseBp], "DIV right-hand scalar"],
    ["poor threshold", [P.iqsPoorThresholdMilli], "GT right-hand constant"],
    ["session count", [P.iqsSessionCount], "DIV right-hand scalar"],
    ["panel size", [P.iqpPanelSize], "DIV right-hand scalar"],
    ["scale ceiling", [P.iqpScaleMax], "DIV right-hand scalar"],
    ["permille scale", [1000], "MUL right-hand constant"],
    ["band edges F(.)", P.bandEdgesPermille, "GT right-hand constants"],
    ["seal cut-offs", P.sealCutoffs, "GT right-hand constants"],
  ];

  // The value column is padded to a fixed width so the "what it is" and the
  // operand-role columns line up; an overlong list is elided rather than
  // wrapped, since a wrapped row is unreadable on a projector.
  const VALUE_COL = 40;
  const fmt = (values) => {
    let text = values.join(" ");
    if (text.length > VALUE_COL) {
      let shown = 0;
      let acc = "";
      for (const v of values) {
        const next = acc ? `${acc} ${v}` : String(v);
        if (next.length > VALUE_COL - 10) break;
        acc = next;
        shown += 1;
      }
      text = `${acc} +${values.length - shown} more`;
    }
    return text.padEnd(VALUE_COL);
  };

  blank();
  console.log(
    dim(
      "   " + "role".padEnd(7) + "  " + "what it is".padEnd(32) + "  " +
        "uint64 values".padEnd(VALUE_COL) + "  unit / operand role"
    )
  );
  console.log(dim("   -------  --------------------------------  " + "-".repeat(VALUE_COL) + "  " + "-".repeat(23)));
  for (const [label, values, unit] of encrypted) {
    console.log(`   ${red("ENCRYPT")}  ${label.padEnd(32)}  ${bold(fmt(values))}  ${dim(unit)}`);
  }
  for (const [label, values, unit] of publics) {
    console.log(`   ${green("PUBLIC ")}  ${label.padEnd(32)}  ${bold(fmt(values))}  ${dim(unit)}`);
  }

  const encryptedCount = encrypted.reduce((n, [, v]) => n + v.length, 0);
  const publicCount = publics.reduce((n, [, v]) => n + v.length, 0);
  blank();
  kv("encrypted input operands", `${encryptedCount}  (one owner record each)`);
  kv("public program constants", `${publicCount}  (part of the formula, not of the measurement)`);
  blank();
  para(
    "The split matters and is forced by the instruction set, not chosen for convenience. A public " +
      "constant travels in clear because for it the handle IS the value by construction; an owner " +
      "record never does. DIV, MOD and SHR accept a public scalar on the right only, which is why " +
      "A_P is encrypted and B_P is not."
  );
  blank();
  bullet(`the adjudicated instruction set has ${bold(String(workload.lowering.microIsaSize ?? 15))} deterministic operations`);
  bullet("SUB must not underflow, so the IR inversion is guarded by a MIN placed before it");
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
act("IQS: sixteen measurements become one number", "slide 5", () => {
  const compare = byPrefix("IQS: session");
  const count = byPrefix("IQS: good-session count");
  const scale = W.filter((w) => w.note.startsWith("IQS: scale"));
  const div = W[L.iqs];
  para(
    "The technical indicator is the share of measured sessions whose quality exceeds the declared " +
      "poor threshold. One comparison per session, then an accumulation chain, then a scale and a " +
      "division by a public scalar. No individual measurement survives into the released output."
  );
  leafBlock(compare, { maxRows: 6 });
  blank();
  kv(
    `${compare.length} GT leaves, positions ${compare[0].leaf_index}..${compare[compare.length - 1].leaf_index}`,
    `one per session, and the panel holds ${P.iqsSessionCount}`
  );
  kv("threshold on the right of each GT", `${P.iqsPoorThresholdMilli} milli-MOS (declared parameter)`);
  kv("sessions above it", `${model.iqsGoodCount} of ${P.iqsSessionCount}`);
  kv(
    `${count.length} ADD leaves, positions ${count[0].leaf_index}..${count[count.length - 1].leaf_index}`,
    `adding ${P.iqsSessionCount} values two at a time costs ${P.iqsSessionCount} - 1`
  );
  blank();
  leafBlock([...scale, div]);
  blank();
  console.log(
    "  " + bold(`IQS = 1000 * ${model.iqsGoodCount} / ${P.iqsSessionCount} = ${model.iqsPermille} permille`) +
      dim(`   [leaf ${L.iqs}]`)
  );
});

/* ---------------------------------------------------------------- act 3 -- */
act("IQP: twenty human ratings become one number", "slide 5", () => {
  const chain = byPrefix("IQP: opinion-score accumulation");
  const tail = W.filter((w) => w.note.startsWith("IQP: scale") || w.note.startsWith("IQP: milli-ACR") || w.note.startsWith("IQP: permille"));
  para(
    "The perceived-quality indicator is the panel mean on the opinion scale, expressed as a fraction " +
      "of the scale ceiling. The panel total is the only aggregate that leaves this stage; no " +
      "subject's individual score is released."
  );
  leafBlock(chain, { maxRows: 4 });
  blank();
  kv(
    `${chain.length} ADD leaves, positions ${chain[0].leaf_index}..${chain[chain.length - 1].leaf_index}`,
    `adding ${P.iqpPanelSize} ratings two at a time costs ${P.iqpPanelSize} - 1`
  );
  kv("subjects", `${P.iqpPanelSize} distinct human raters`);
  kv("panel total", `${model.iqpSum}`);
  kv("panel mean", `${model.iqpMeanMilli} milli-ACR`);
  kv("scale ceiling", `${P.iqpScaleMax} (ITU-T ACR, a property of the scale)`);
  blank();
  leafBlock(tail);
  blank();
  console.log(
    "  " + bold(`IQP = (1000 * ${model.iqpSum} / ${P.iqpPanelSize}) / ${P.iqpScaleMax} = ${model.iqpPermille} permille`) +
      dim(`   [leaf ${L.iqp}]`)
  );
});

/* ---------------------------------------------------------------- act 4 -- */
act("IR: the complaint rate, and the guard that protects the subtraction", "slide 5", () => {
  const irLeaves = byPrefix("IR: ");
  para(
    "The complaint indicator is literally the formula in the regulation. A_P, the complaint count, " +
      "is the encrypted and authenticated input of this stage; B_P, the access base, enters as a " +
      "public scalar divisor, because the instruction set divides by public scalars only."
  );
  leafBlock(irLeaves);
  blank();
  console.log("  " + bold(`IR = 1000 * ${P.complaintsAp} / ${P.accessBaseBp} = ${model.irPermille} permille`) + dim(`   [leaf ${L.ir}]`));
  blank();
  para(
    "IR rises with complaints, so it is inverted into a score where higher is better. That " +
      "subtraction could underflow, and an underflowing SUB is rejected outright by the objective " +
      "verifier, which would abort the trace instead of producing a floor of zero. The MIN leaf " +
      "immediately before the SUB is what makes the inversion safe."
  );
  blank();
  console.log(
    "  " + bold(`IRscore = 1000 - min(${model.irPermille}, 1000) = ${model.irScorePermille} permille`) +
      dim(`   [leaf ${L.irScore}]`)
  );
});

/* ---------------------------------------------------------------- act 5 -- */
act("F(.): a regulatory band table with no branching", "slide 5", () => {
  para(
    "F maps an indicator to a band. In a document it is a table of ranges; in a branch-free integer " +
      "machine it is a count of edges the indicator exceeds. Four comparisons and an accumulation, " +
      "applied three times. Both sides of every decision are computed and masked, so the instruction " +
      "sequence does not depend on the data and the contract can adjudicate any position."
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
  leafBlock(byPrefix("F(IQS):"), { maxRows: 8 });
});

/* ---------------------------------------------------------------- act 6 -- */
act("S and the seal: the only value that leaves the computation", "slide 6", () => {
  const sLeaves = byPrefix("S:");
  const sealLeaves = byPrefix("seal:");
  para("The composite score is the sum of the three bands, and the seal is the same edge-counting trick applied to it.");
  leafBlock(sLeaves);
  blank();
  console.log(
    "  " + bold(`S = ${model.bandIqs} + ${model.bandIqp} + ${model.bandIr} = ${model.compositeScoreS}`) +
      dim(`  (range 0..12)   [leaf ${L.compositeScoreS}]`)
  );
  blank();
  kv("declared seal cut-offs", `[${P.sealCutoffs.join(", ")}]`);
  leafBlock(sealLeaves, { maxRows: 8 });
  blank();
  console.log(
    "  " + bold(`seal index = ${model.sealIndex}`) +
      (model.sealLabel ? bold(`  (band "${model.sealLabel}")`) : "") +
      dim(`   [leaf ${L.sealIndex}, the released value]`)
  );
  blank();
  para(
    "Where every leaf came from. No count below was chosen by hand: a comparison per panel item, " +
      "n-1 additions to add n values, one multiplication per scale change and one division per " +
      "normalisation by a public scalar. The trace length follows from the PANEL SIZES and the " +
      "number of declared edges, never from the measured values."
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
    console.log(
      `   ${label.padEnd(33)}  ${String(g.length).padStart(6)}  ${span.padStart(9)}   ${dim(why)}`
    );
  }
  console.log(dim("   ---------------------------------  ------  ---------"));
  console.log(`   ${"useful".padEnd(33)}  ${String(unpadded).padStart(6)}  ${`0..${unpadded - 1}`.padStart(9)}`);
  console.log(
    `   ${"padding, ADD 0+0".padEnd(33)}  ${String(padded - unpadded).padStart(6)}  ` +
      `${`${unpadded}..${padded - 1}`.padStart(9)}   ${dim("to the next power of two")}`
  );
  console.log(`   ${bold("total".padEnd(33))}  ${bold(String(padded).padStart(6))}  ${`0..${padded - 1}`.padStart(9)}`);
  // The table above is grouped by note prefix. If the lowering ever emits a
  // leaf whose note no other row claims, the accounting stops closing, and
  // silently showing a table that does not add up would be worse than saying so.
  if (budgeted !== unpadded) {
    console.log(
      "  " + red(`accounting does not close: ${budgeted} leaves attributed, ${unpadded} useful leaves in the trace.`)
    );
    console.log("  " + red("A stage was added to the lowering without a row in LEAF_BUDGET."));
  }
  blank();
  kv("opcode histogram", JSON.stringify(workload.lowering.opcodeHistogram));
  blank();
  para(
    `Leaf ${L.sealIndex} is the last real instruction of the trace and the one that produces the ` +
      "released seal. It is therefore also the leaf a conflicted operator has every incentive to " +
      "inflate, which is why the demonstration corrupts exactly that one."
  );
});

/* ---------------------------------------------------------------- act 7 -- */
act("Encryption: the chain stores handles, never values", "slide 7", () => {
  para(
    "Up to here the values are in clear, because this narrator exists to show the arithmetic. In the " +
      "live run every one of these leaves is executed over real FheUint64 ciphertexts with tfhe-rs, " +
      "in both variants, honest and corrupted, and every result is decrypted and checked against the " +
      "value the lowering claims. A divergence aborts before the network is touched."
  );
  blank();
  console.log("    " + bold("handle = keccak256( safe_serialize( ciphertext ) )"));
  blank();
  kv("leaves executed under encryption", `${padded} honest + ${padded} corrupted = ${2 * padded}`);
  blank();
  bullet("an input operand is a fresh encryption: the owner's authenticated record");
  bullet("an operand coming from a previous leaf REUSES that leaf's result ciphertext, without re-encrypting");
  bullet("DIV, MOD and SHR take a public scalar; no ciphertext is created for the divisor");
  blank();
  para(
    "A handle identifies an execution, not an operation: re-running the same leaf over the same " +
      "operands with the same key can serialize different bytes, because tfhe-rs evaluates in " +
      "parallel. That was measured, not assumed, and it is the reason act 10 compares with FHE.eq " +
      "rather than with byte equality."
  );
});

/* ---------------------------------------------------------------- act 8 -- */
act("Authorization: the expression becomes the law of the system", "slide 8", () => {
  para(
    "Each input operand is registered as (owner, handle, metadata hash), signed by the owner's " +
      "account. The requester then signs five roots. After that the operator cannot change the " +
      "formula or the records without an on-chain check failing."
  );
  blank();
  console.log("    inputs root");
  console.log("    program root");
  console.log("    provenance root");
  console.log("    trace root");
  console.log("    output commitment");
  blank();
  para(
    "What this does NOT give: it authenticates the origin of the ciphertext, not the truth of the " +
      "measurement. An owner can register a fabricated measurement under its own identity and no " +
      "part of this system detects it."
  );
});

/* ---------------------------------------------------------------- act 9 -- */
act("The optimistic path, and what is actually released", "slide 9", () => {
  para(
    "If the challenge window elapses with no dissent, the task finalizes as accepted with no " +
      "verification of the computation at all. That is what makes the cost viable: the chain only " +
      "works when there is disagreement."
  );
  blank();
  console.log("  " + green(`released:  sealIndex = ${model.sealIndex}` + (model.sealLabel ? ` (band "${model.sealLabel}")` : "")));
  console.log("  " + dim(`withheld:  the ${P.iqsSessionCount} milli-MOS values, the ${P.iqpPanelSize} ratings, IQS, IQP, IR, the complaint count`));
  blank();
  para(
    "Say this plainly: acceptance by silence is not proof. The security of this path does not come " +
      "from re-execution; it comes from challenging being cheap and lying being expensive, and it is " +
      "conditional on at least one diligent auditor inside the window."
  );
});

/* --------------------------------------------------------------- act 10 -- */
act("The dispute: disclosure, then bisection", "slides 10 to 12", () => {
  const w = W[manipulated];
  para(
    "The live run creates two tasks: one with this trace and one in which exactly one leaf was " +
      "altered. Auditors commit hidden evidence, a challenger posts a bond, and from that point " +
      "auditor votes decide nothing."
  );
  blank();
  kv("corrupted leaf", `${manipulated} (${w.opcode_name})`);
  console.log("  " + dim(`  note: ${w.note}`));
  blank();
  para(
    "The operator must then publish the whole trace as calldata, in batches, before bisection " +
      "starts. Per leaf: the opcode, the three handles and the provenance of each operand. No " +
      "operand value. What becomes public is the SHAPE of the computation, not the data."
  );
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
    `Publishing the trace costs N; locating the error costs log2(N), which is ${ladder.length} rounds here. ` +
      "It would be incorrect to call the challenged path logarithmic, though: only the localization is."
  );
});

/* --------------------------------------------------------------- act 11 -- */
act("Leaf decision under encryption, and settlement", "slides 13 and 14", () => {
  const w = W[manipulated];
  para("The isolated leaf is recomputed homomorphically from the ciphertexts of its operands, and each side's claim is compared against that recomputation.");
  blank();
  console.log("    recomputed := eval( opcode, lhsCiphertext, rhsCiphertext )     " + dim("// homomorphic"));
  console.log("    valid      := decrypt( FHE.eq( recomputed, claimed ) )        " + dim("// only the BIT"));
  blank();
  console.log(`  For leaf ${manipulated}, the honest claim is the one the micro-ISA reproduces:`);
  leafBlock([w], { highlight: [manipulated] });
  blank();
  bullet("only the equality bit is decrypted: never an operand, never a result, never a claim");
  bullet("each adjudicated ciphertext must hash to the handle published on-chain, or it is not adjudicated");
  bullet("the bit reaches the chain with t+1 EIP-712 signatures bound to this contract, chain, task, leaf and opcode");
  blank();
  para(
    "Settlement then rests on the operator's own claim, not on a majority: the dishonest operator is " +
      "slashed, the challenger's bond is returned, the honest task finalizes as accepted, and the " +
      "seal attached to the corrupted trace falls with it, because the output commitment was bound " +
      "on-chain to that trace's terminal leaf at task creation."
  );
  blank();
  para(
    "What is modelled here, said without rounding: in this demonstration the recomputation and the " +
      "single decryption run in a local process holding the evaluation key pair. In production the " +
      "recomputation runs on the FHEVM coprocessor and the two bits are threshold-decrypted by the " +
      "key-management service. The transport, the EIP-712 digest, the t+1 rule and the on-chain " +
      "verification code are the production ones; what is modelled is who holds the decryption key."
  );
});

// ------------------------------------------------------------------- run --

if (!config.bare) {
  console.log("");
  console.log(bold(rule("=")));
  console.log(bold(" ANATEL RQUAL  |  stage-by-stage narration of the lowering"));
  console.log(bold(rule("=")));
  console.log("");
  console.log("  " + red("DEMONSTRATION ONLY."));
  console.log("  Only the STRUCTURE of the expression was verified against Res. 717/2019.");
  console.log("  Every threshold, band edge and cut-off is a DECLARED DEPLOYMENT PARAMETER,");
  console.log("  not an ANATEL value. The seal below is NOT an official RQUAL result.");
  console.log("");
  console.log(dim("  No chain is contacted, no process is spawned and no file is written."));
  if (config.pause && !process.stdin.isTTY) {
    console.log(dim("  --pause was requested but stdin is not a terminal; running straight through."));
  }
}

const selected = acts
  .map((a, i) => ({ ...a, number: i }))
  .filter((a) => config.act === null || config.act.has(a.number));
if (selected.length === 0) {
  console.error(
    `No such act: ${[...config.act].join(", ")}. Valid range is 0 to ${acts.length - 1}.`
  );
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
  console.log("  To perform what acts 7 to 11 describe, against the validator network:");
  console.log("     " + bold("Anatel/anatel-rqual/run-anatel-demo.sh"));
  console.log("");
}
