/**
 * Narration of the minimal arithmetic example, act by act.
 *
 * Contacts no network, spawns no process and writes no file: it reads the
 * declared values, runs the same lowering the real execution runs, and prints
 * what each stage of the protocol does to that calculation.
 *
 * Usage:
 *   node examples/exemplo-aritmetico/narrate-arithmetic-demo.mjs
 *   node examples/exemplo-aritmetico/narrate-arithmetic-demo.mjs --pause
 *   node examples/exemplo-aritmetico/narrate-arithmetic-demo.mjs --acts 2-4
 */
import { arithmeticInputs } from "./arithmetic-demo-fixtures.mjs";
import { lowerArithmeticDemo } from "./arithmetic-demo-lowering.mjs";

const TOTAL_ACTS = 9; // 0..8

function parseActSpec(spec) {
  if (spec === undefined) {
    throw new Error("--act/--acts requires a value, for example 5, 1-6 or 0,2,5");
  }
  const wanted = new Set();
  for (const part of String(spec).split(",")) {
    const trimmed = part.trim();
    if (trimmed.length === 0) continue;
    const range = trimmed.match(/^(\d+)-(\d+)$/);
    if (range) {
      const from = Number(range[1]);
      const to = Number(range[2]);
      if (to < from) throw new Error(`--acts: the range "${trimmed}" is inverted`);
      for (let i = from; i <= to; i += 1) wanted.add(i);
      continue;
    }
    const single = Number(trimmed);
    if (!Number.isInteger(single)) throw new Error(`--acts: "${trimmed}" is not an act number`);
    wanted.add(single);
  }
  if (wanted.size === 0) throw new Error("--acts selected no act at all");
  return wanted;
}

function parseArgs(argv) {
  const parsed = { pause: false, bare: false, slow: null, act: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--pause") parsed.pause = true;
    else if (arg === "--bare") parsed.bare = true;
    // Accepted and ignored: this trace has two leaves and always fits on the
    // screen whole, so there is no summary to expand. The flag exists so the
    // scripts that drive the other narrators can pass it without failing.
    else if (arg === "--leaves") continue;
    else if (arg === "--slow") {
      i += 1;
      const value = Number.parseFloat(argv[i]);
      if (!Number.isFinite(value) || value < 0) throw new Error("--slow requires a number of seconds");
      parsed.slow = value;
    } else if (arg.startsWith("--slow=")) {
      parsed.slow = Number.parseFloat(arg.slice("--slow=".length));
    } else if (arg === "--act" || arg === "--acts") {
      i += 1;
      parsed.act = parseActSpec(argv[i]);
    } else if (arg.startsWith("--act=")) {
      parsed.act = parseActSpec(arg.slice("--act=".length));
    } else if (arg.startsWith("--acts=")) {
      parsed.act = parseActSpec(arg.slice("--acts=".length));
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Narration of the minimal arithmetic example.

  --pause        wait for Enter between acts
  --slow <s>     auto-advance every <s> seconds
  --acts <spec>  print only these acts: 5, or 1-6, or 0,2,5  (--act is a synonym)
  --bare         omit the header and the footer
  --leaves       accepted and ignored; this trace is always printed whole
`);
      process.exit(0);
    } else {
      throw new Error(`unrecognized argument: ${arg}`);
    }
  }
  if (parsed.pause && parsed.slow !== null) {
    throw new Error("--pause and --slow are mutually exclusive");
  }
  return parsed;
}

const config = parseArgs(process.argv.slice(2));

function rule(char = "=") {
  console.log(char.repeat(78));
}

function head(n, title, sub) {
  if (config.act !== null && !config.act.has(n)) return false;
  console.log();
  rule();
  console.log(` ACT ${n}/${TOTAL_ACTS - 1}  ${title}`);
  if (sub) console.log(` ${sub}`);
  rule();
  console.log();
  return true;
}

async function waitBetweenActs() {
  if (config.slow !== null) {
    await new Promise((resolve) => setTimeout(resolve, config.slow * 1000));
    return;
  }
  if (!config.pause) return;
  if (!process.stdin.isTTY) return;
  process.stdout.write("   [Enter for the next act] ");
  await new Promise((resolve) => {
    process.stdin.resume();
    process.stdin.once("data", () => {
      process.stdin.pause();
      resolve();
    });
  });
  console.log();
}

// ---------------------------------------------------------------------------

const inputs = arithmeticInputs();
const workload = lowerArithmeticDemo(inputs);
const m = workload.model;
const p = m.declaredParameters;
const leaves = workload.witnesses;
const usefulLeaves = workload.lowering.unpaddedLeafCount;
const total = workload.lowering.paddedLeafCount;
const rounds = Math.log2(total);

/**
 * The leaf the dishonest operator alters.
 *
 * Reads MANIPULATED_LEAF_INDEX, the SAME variable run-arithmetic-demo.sh passes
 * to the real execution. Before act 7 drew the bisection path this was only a
 * sentence that could diverge from what the run would do; now it would be a
 * wrong DRAWING, showing the search descending into a branch that is not the
 * corrupted one.
 */
const corruptedLeaf = (() => {
  const raw = process.env.MANIPULATED_LEAF_INDEX;
  if (raw === undefined || raw === "") return workload.defaultManipulatedLeafIndex;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0 || value >= total) {
    throw new Error(
      `MANIPULATED_LEAF_INDEX=${raw} is outside the ${total} leaves of this trace`
    );
  }
  return value;
})();

/** The default choice is the only leaf where lying pays; an override is not. */
const corruptedLeafIsDefault = corruptedLeaf === workload.defaultManipulatedLeafIndex;

function printLeaves(from, to) {
  console.log("   idx  operation  left        right     result");
  console.log("   ---  ---------  ---------  --------  ---------");
  for (const l of leaves.slice(from, to)) {
    console.log(
      `   ${String(l.leaf_index).padStart(3)}  ${l.opcode_name.padEnd(9)}  ` +
      `${String(l.lhs).padStart(9)}  ${String(l.rhs).padStart(8)}  ${String(l.claimed).padStart(9)}`
    );
  }
}

// ---------------------------------------------------------------------------
//  DRAWING THE TREES
//
//  There are TWO different trees here, and conflating them would be
//  misleading:
//
//    - the EXPRESSION tree (act 2), which says in what order the operations
//      happen and which operand of each one comes from the previous operation;
//    - the MERKLE tree (acts 4 and 7), which does not describe the calculation
//      at all: it is the published commitment over the LIST of leaves, and it
//      is the one bisection walks.
//
//  The trace of this calculation is a straight list. The only tree bisection
//  knows is the Merkle tree, built ON TOP of that list.
//
//  The primitives below place labels at absolute columns. Columns may be
//  negative while a drawing is being assembled; `printRows` shifts the whole
//  block right at the end.
// ---------------------------------------------------------------------------

/** Center column of a label starting at `start`. */
function centerOf(start, text) {
  return start + Math.floor(text.length / 2);
}

/** A cell whose center falls exactly on `center`. */
function centeredCell(center, text) {
  return { col: center - Math.floor(text.length / 2), text };
}

/** The `┌───┴───┐` line joining two children to their parent. */
function connectorCell(leftCenter, parentCenter, rightCenter) {
  const width = rightCenter - leftCenter + 1;
  const chars = new Array(width).fill("─");
  chars[0] = "┌";
  chars[width - 1] = "┐";
  chars[parentCenter - leftCenter] = "┴";
  return { col: leftCenter, text: chars.join("") };
}

/** Writes one row's cells, left to right. */
function placeRow(cells) {
  let line = "";
  for (const cell of [...cells].sort((a, b) => a.col - b.col)) {
    if (cell.col > line.length) line = line.padEnd(cell.col, " ");
    line = line.slice(0, cell.col) + cell.text + line.slice(cell.col + cell.text.length);
  }
  return line.replace(/\s+$/, "");
}

/** Normalizes a block of rows to the requested margin and prints it. */
function printRows(rows, margin = 3) {
  const occupied = rows.flat();
  if (occupied.length === 0) return;
  const shift = margin - Math.min(...occupied.map((cell) => cell.col));
  for (const cells of rows) {
    console.log(placeRow(cells.map((cell) => ({ ...cell, col: cell.col + shift }))));
  }
}

/**
 * The expression tree. It is a CHAIN leaning to the left: each operator
 * consumes the operator below it as its left operand and one declared value as
 * its right operand. That is exactly what the table in act 2 hides, and the
 * reason the trace is not two unrelated facts.
 */
function drawExpressionTree() {
  const GAP = 6;
  // Read from the trace, not written by hand: if the parameters change the
  // drawing follows, and if the lowering changes shape the drawing fails loud.
  const chain = [
    {
      op: leaves[m.leafIndex.product].opcode_name,
      value: m.product,
      left: `y = ${p.y}`,
      right: `z = ${p.z}`
    },
    {
      op: leaves[m.leafIndex.total].opcode_name,
      value: m.total,
      right: `x = ${p.x}`
    }
  ];

  const rowsBottomUp = [];
  let leftText = chain[0].left;
  let leftStart = 0;
  let rightText = chain[0].right;
  let rightStart = leftStart + leftText.length + GAP;
  rowsBottomUp.push([
    { col: leftStart, text: leftText },
    { col: rightStart, text: rightText }
  ]);

  for (let i = 0; i < chain.length; i += 1) {
    const leftCenter = centerOf(leftStart, leftText);
    const rightCenter = centerOf(rightStart, rightText);
    const parentCenter = Math.floor((leftCenter + rightCenter) / 2);
    const parentText = `${chain[i].op} = ${chain[i].value}`;
    const parentCell = centeredCell(parentCenter, parentText);

    rowsBottomUp.push([connectorCell(leftCenter, parentCenter, rightCenter)]);

    const parentRow = [parentCell];
    const next = chain[i + 1];
    if (next) {
      // This level's parent is the LEFT child of the level above, and that
      // level's right sibling shares the line with it.
      const siblingStart = parentCell.col + parentText.length + GAP;
      parentRow.push({ col: siblingStart, text: next.right });
      leftText = parentText;
      leftStart = parentCell.col;
      rightText = next.right;
      rightStart = siblingStart;
    }
    rowsBottomUp.push(parentRow);
  }

  printRows(rowsBottomUp.reverse());
}

/**
 * The Merkle tree over the trace leaves. The digests are NOT computed here:
 * this narrator contacts no chain and depends on no installed dependency, and
 * keccak256 would come from `ethers`. The nodes are labelled by the interval
 * they cover, which is what bisection uses. The real root comes out of the real
 * execution.
 */
function drawMerkleTree({ markLeaf = null } = {}) {
  const SLOT = 12;
  const rows = [];
  const levelRows = [];

  let centers = Array.from({ length: total }, (_, i) => i * SLOT + Math.floor(SLOT / 2));
  let span = 1;
  while (centers.length > 1) {
    const parents = [];
    const connectors = [];
    for (let i = 0; i < centers.length; i += 2) {
      const parentCenter = Math.floor((centers[i] + centers[i + 1]) / 2);
      parents.push(parentCenter);
      connectors.push(connectorCell(centers[i], parentCenter, centers[i + 1]));
    }
    span *= 2;
    const labels = parents.map((parentCenter, index) =>
      centeredCell(
        parentCenter,
        span === total ? "root" : `n[${index * span},${(index + 1) * span})`
      )
    );
    levelRows.push({ connectors, labels });
    centers = parents;
  }

  for (let level = levelRows.length - 1; level >= 0; level -= 1) {
    rows.push(levelRows[level].labels);
    rows.push(levelRows[level].connectors);
  }

  const leafCenters = Array.from({ length: total }, (_, i) => i * SLOT + Math.floor(SLOT / 2));
  rows.push(leafCenters.map((center, i) => centeredCell(center, `h(f${i})`)));
  rows.push(leafCenters.map((center, i) => centeredCell(center, `leaf ${i}`)));
  rows.push(
    leafCenters.map((center, i) =>
      centeredCell(center, i >= usefulLeaves ? "(no-op)" : leaves[i].opcode_name)
    )
  );
  if (markLeaf !== null) {
    rows.push([centeredCell(leafCenters[markLeaf], "▲ the lie")]);
  }

  printRows(rows);
}

/**
 * One bisection round: the live node and its two children, marking which of
 * them the two parties published differently.
 *
 * The rule drawn here is the contract's, not a paraphrase: `advanceDispute`
 * tests the LEFT child first and descends right only if the left one matches.
 * With a single corrupted leaf only one of the children ever differs, so this
 * example never exercises that tie-break.
 */
function drawBisectionRound(lo, hi, targetLeaf, margin = 5) {
  const mid = lo + (hi - lo) / 2;
  const goesRight = targetLeaf >= mid;
  const GAP = 10;

  const parentText = hi - lo === total ? `root  n[${lo},${hi})` : `n[${lo},${hi})`;
  const leftText = mid - lo === 1 ? `h(f${lo})` : `n[${lo},${mid})`;
  const rightText = hi - mid === 1 ? `h(f${mid})` : `n[${mid},${hi})`;

  const leftStart = 0;
  const rightStart = leftStart + leftText.length + GAP;
  const leftCenter = centerOf(leftStart, leftText);
  const rightCenter = centerOf(rightStart, rightText);
  const parentCenter = Math.floor((leftCenter + rightCenter) / 2);

  const mark = (differs) => (differs ? "✗ DIFFER" : "✓ equal");
  const rows = [
    [centeredCell(parentCenter, parentText)],
    [connectorCell(leftCenter, parentCenter, rightCenter)],
    [
      { col: leftStart, text: leftText },
      { col: rightStart, text: rightText }
    ],
    [
      centeredCell(leftCenter, mark(!goesRight)),
      centeredCell(rightCenter, mark(goesRight))
    ],
    // Anchored to the LEFT at the chosen child's center: centering it would put
    // the `└` far from the node it points at, and the cell would become the
    // leftmost of the block, shifting the whole drawing during normalization.
    [{ col: goesRight ? rightCenter : leftCenter, text: "└─ the contract descends here" }]
  ];
  printRows(rows, margin);

  return { mid, goesRight, newLo: goesRight ? mid : lo, newHi: goesRight ? hi : mid };
}

if (!config.bare) {
  rule();
  console.log(" VC-FHE  |  MINIMAL ARITHMETIC EXAMPLE  |  the whole protocol in two operations");
  rule();
  console.log();
  console.log(`  There is one calculation:   ${m.expression}`);
  console.log();
  console.log("  The three values are arbitrary. Nothing here is measured, nothing is regulated, and");
  console.log("  this example is not part of the evaluation's evaluation. What it shows is the path a");
  console.log("  calculation travels: from expression to instructions, from instructions to");
  console.log("  ciphertexts, and from ciphertexts to a decision nobody can contest without proof.");
}

// ------------------------------------------------------------------- act 0 --
if (head(0, "The problem", "proving the result of a calculation without showing the inputs")) {
  console.log("  Someone runs a calculation over values they cannot reveal and has to publish the");
  console.log("  result. Whoever receives that result wants to be able to contest it.");
  console.log();
  console.log(`     ${m.expression}`);
  console.log();
  console.log(`     x, y, z  are the operator's secrets`);
  console.log(`     w        is part of the agreed program, and may be public`);
  console.log(`     total    is the only number that will become public`);
  console.log();
  console.log("  There are two obvious ways out, and both are bad:");
  console.log();
  console.log("     reveal x, y, z    ->  the receiver learns what it should not");
  console.log("     reveal only total ->  the receiver has to take it on faith");
  console.log();
  console.log("  The protocol exists to escape both. It delivers the result AND a way to contest");
  console.log("  it, without ever opening the inputs.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 1 --
if (head(1, "Everything becomes an integer", "not an engineering limitation — it is what makes the fight decidable")) {
  console.log("  The system works only with 64-bit positive integers, and the reason is legal");
  console.log("  before it is technical: if the two parties can each claim a different rounding,");
  console.log("  there is no objective rule to decide who is right. And the whole protocol depends");
  console.log("  on there being ONE correct answer per operation.");
  console.log();
  console.log("  So there is no floating point anywhere. The three values of this calculation:");
  console.log();
  console.log(`     x = ${p.x}      y = ${p.y}      z = ${p.z}`);
  console.log();
  console.log("  And everything that touches the calculation becomes an integer, not just the");
  console.log("  inputs: the program's constants, every intermediate result, and — in expressions");
  console.log("  that compare — even the answer to \"is it greater?\", which returns not \"yes\" but");
  console.log("  the integer 1.");
  console.log();
  console.log("  The price shows up in act 3, and it is division.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 2 --
if (head(2, "The expression becomes a list of instructions", "precedence fixes the order, and the order is what gets committed")) {
  console.log(`  The calculation:   ${m.expression}`);
  console.log();
  console.log("  Standard precedence decides the order: first the multiplication, then the");
  console.log("  division, then the addition. Each one becomes exactly one instruction, chosen");
  console.log("  from a fixed set of fifteen the contract knows how to verify.");
  console.log();
  console.log("  There is no loop, no conditional, no function. It is a straight list. Each line");
  console.log("  of it is called a leaf.");
  console.log();
  console.log("  The expression tree, which is what precedence produces:");
  console.log();
  drawExpressionTree();
  console.log();
  console.log("  It leans entirely to one side, and that is no accident: each operator consumes the");
  console.log("  operator below it as its LEFT operand and a declared value as its RIGHT operand.");
  console.log("  That is why the tree becomes a list without losing anything — there are no two");
  console.log("  independent branches to choose between.");
  console.log();
  printLeaves(0, usefulLeaves);
  console.log();
  console.log(`  Look at leaf ${m.leafIndex.total}: its left operand is the RESULT of leaf ${m.leafIndex.product}. That is what makes`);
  console.log("  the trace a chain rather than two unrelated facts. Further on the contract checks");
  console.log("  that continuity — over the ciphertexts, not over the integers.");
  console.log();
  console.log("  Here the translation is one-to-one, and it is not always. A function like \"which");
  console.log("  band does this number fall in\" has no instruction of its own: it becomes a count");
  console.log("  of summed comparisons, and costs several leaves. That is what happens in the");
  console.log("  ANATEL examples.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 3 --
if (head(3, "Everything here is encrypted", "and the two rules this short expression no longer shows")) {
  console.log("  This trace has no value in the clear. Both operands of the multiplication are");
  console.log("  ciphertexts, both operands of the addition are ciphertexts, and the result of each");
  console.log("  is a ciphertext. There is no exception to point at.");
  console.log();
  console.log("  That is worth saying out loud because it is NOT the general case, and an expression");
  console.log("  this short hides two rules that matter:");
  console.log();
  console.log(`  RULE 1 — some operations require a CLEARTEXT right operand. ${m.publicScalarOpcodes.length} of the fifteen:`);
  console.log();
  console.log(`     ${m.publicScalarOpcodes.join(", ")}`);
  console.log();
  console.log("  DIV, MOD and SHR take the divisor, the modulus and the shift amount in the clear,");
  console.log("  because the homomorphic operation is the scalar variant — there is no division by an");
  console.log("  encrypted operand on the euint64 surface. ADD_CHAIN is in the list for a different");
  console.log("  reason: its right operand is a repeat count, and encrypting it would make the loop");
  console.log("  bound secret. It costs no privacy, because those are part of the agreed PROGRAM and");
  console.log("  not of the data — but it is a real disclosure, and this trace does not show it.");
  console.log();
  console.log("  RULE 2 — integer division TRUNCATES. It does not round, it discards. A trace that");
  console.log("  divided 42 by 5 would carry 8 and lose 0.40 permanently.");
  console.log();
  console.log("  That mattered more than it looked: integer arithmetic is not a neutral translation");
  console.log("  of the expression, it IS the definition of what will be judged. With another");
  console.log("  precision it would be another expression, another trace and possibly another");
  console.log("  result. Here nothing is lost — x + y*z over integers is exactly x + y*z over the");
  console.log("  rationals — so the point has to be made in words rather than shown.");
  console.log();
  console.log("  Both rules run in ../../Anatel/anatel-rqual-simplificado/, which has DIV and SUB.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 4 --
if (head(4, "The Merkle tree", `${total} leaves, and why no padding was needed`)) {
  console.log("  The search for the wrong leaf, further on, works by splitting the interval in half");
  console.log("  each round. Splitting in half is only exact when the leaf count is a power of two,");
  console.log("  so the protocol pads any trace up to one with leaves that compute nothing.");
  console.log();
  console.log(`  This trace needs none: ${total} is already a power of two. The padding code runs and`);
  console.log("  adds zero leaves. It is worth knowing it is there — a three-leaf trace would be");
  console.log("  padded to four, and the 28-leaf ANATEL trace is padded to 32 — but this expression");
  console.log("  is too short to show it.");
  console.log();
  console.log(`  Cost of ${total} leaves: the search takes exactly ${rounds} round${rounds > 1 ? "s" : ""}, because log2(${total}) = ${rounds}.`);
  console.log("  A trace of a thousand leaves would take ten.");
  console.log();
  console.log(`  And it is over that list of ${total} leaves that the SECOND tree is built — the Merkle`);
  console.log("  tree, which does not describe the calculation and exists only to commit the list:");
  console.log();
  drawMerkleTree();
  console.log();
  console.log("  Do not confuse it with the tree in act 2. That one says in what order the");
  console.log("  operations happen; this one only binds the leaves to a single 32-byte value, the");
  console.log("  root, which is what goes to the chain. An internal node is not an operation: it is");
  console.log("  the digest of an INTERVAL of leaves, and it is by intervals that the search in act");
  console.log("  7 walks.");
  console.log();
  console.log(`  With ${total} leaves the tree is as small as a tree gets: one root and its two children,`);
  console.log("  which are the leaves themselves. That is also why the search below takes a single");
  console.log("  round — there is only one level to descend.");
  console.log();
  console.log("  The digests are deliberately not computed here: this narration contacts no chain");
  console.log("  and needs no installed dependency, and keccak256 would come from one. The real");
  console.log("  root appears in the real execution.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 5 --
if (head(5, "The ciphertexts", "the blockchain stores fingerprints, never values")) {
  console.log("  Up to here the numbers appeared in the clear because the point was to show the");
  console.log("  calculation. In the real execution each leaf runs over values encrypted with");
  console.log("  tfhe-rs, which adds, subtracts, multiplies, divides by a scalar and compares");
  console.log("  encrypted values WITHOUT opening any of them. Two closed padlocks go in, a third");
  console.log("  closed padlock comes out, and whoever operated never knew what was inside.");
  console.log();
  console.log("  Each encrypted value gets a short identifier:");
  console.log();
  console.log("     handle = keccak256( bytes of the encrypted value )");
  console.log();
  console.log(`  That is ${total * 2} leaves under encryption: ${total} from the honest variant and ${total} from the`);
  console.log("  corrupted one.");
  console.log();
  console.log("  Three details worth the time:");
  console.log();
  console.log("  - the operand that comes from the previous leaf REUSES that leaf's ciphertext,");
  console.log("    without re-encrypting, so the chain links ciphertexts and not integers;");
  console.log("  - EVERY operand of this trace is encrypted, so every one of them has a handle.");
  console.log("    A trace with a DIV would have one operand that generates no ciphertext at all,");
  console.log("    because a public scalar has nothing to hide;");
  console.log("  - the handle identifies an EXECUTION, not the operation. Running the same leaf");
  console.log("    twice, with the same key and the same operands, can produce different bytes,");
  console.log("    because the library evaluates in parallel. That was measured, not assumed, and");
  console.log("    it is the reason for the design in act 8.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 6 --
if (head(6, "The normal path", "nobody checks anything, and that is deliberate")) {
  console.log("  The operator publishes on the blockchain its commitment to the trace — the root of");
  console.log("  a tree built over the handles — and the result. If nobody contests within the");
  console.log("  window, the task is accepted without the chain having verified a single operation.");
  console.log();
  console.log("  Why this way: verifying everything on every execution would be expensive even for");
  console.log("  the honest ones, which are the majority. The chain only works when there is");
  console.log("  disagreement.");
  console.log();
  console.log("  The price, unsoftened: acceptance by silence is not proof. The guarantee depends on");
  console.log("  there being at least one attentive auditor, with an economic incentive, inside the");
  console.log("  window.");
  console.log();
  console.log(`  What becomes public on this path: the total, \`${m.releasedValue}\`. That is all. Not x, not y,`);
  console.log("  not z, and not the product. No intermediate value.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 7 --
if (head(7, "The lie and the search", `${rounds} rounds to find one leaf among ${total}`)) {
  const l = leaves[corruptedLeaf];
  console.log("  The demonstration creates two tasks: one with the correct trace, and another in");
  console.log("  which exactly one leaf was altered.");
  console.log();
  if (corruptedLeafIsDefault) {
    console.log(`  The chosen leaf is ${corruptedLeaf}: the one that produces the total, the only value the trace`);
    console.log("  releases. The choice is not random — it is the only leaf where the operator gains");
    console.log(`  anything by lying. It claims a total different from ${l.claimed}. Every other leaf is an`);
    console.log("  intermediate nobody sees, so lying there does it no good.");
  } else {
    console.log(`  The chosen leaf is ${corruptedLeaf} (${l.opcode_name}), because MANIPULATED_LEAF_INDEX was set.`);
    console.log(`  The operator claims a result different from ${l.claimed} on it.`);
    console.log();
    console.log(`  Worth saying what that changes: the default leaf would be ${workload.defaultManipulatedLeafIndex}, the one that`);
    console.log("  produces the total, and it is the only one where lying pays. This one is an");
    console.log("  intermediate nobody sees, so the scenario exercises the detection MECHANISM");
    console.log("  without modelling a real incentive.");
  }
  console.log();
  console.log("  An auditor disagrees and opens the dispute, posting a bond. And here is the");
  console.log("  property that most distinguishes this protocol:");
  console.log();
  console.log("     THE MAJORITY OF AUDITORS DECIDES NOTHING.");
  console.log("     In the real execution two of three auditors back the dishonest operator, and");
  console.log("     that does not change the outcome. One auditor alone, with proof, wins.");
  console.log();
  console.log(`  Before the search begins, the operator is REQUIRED to publish all ${total} leaves on the`);
  console.log("  chain. Per leaf: the operation, the three handles and the provenance of each");
  console.log("  operand. NO VALUE. If it does not publish in time, it loses by omission.");
  console.log();
  console.log("  The search walks the Merkle tree from act 4, and the drawing below is where it");
  console.log("  stands in each round. Only the corrupted leaf differs between the two traces, so");
  console.log("  only ONE of the two children differs each round, and that is the one it descends");
  console.log("  into.");
  console.log();
  console.log("  Where the lie sits, in the whole tree:");
  console.log();
  drawMerkleTree({ markLeaf: corruptedLeaf });
  console.log();

  let lo = 0;
  let hi = total;
  for (let r = 1; r <= rounds; r += 1) {
    console.log(
      `  ── round ${r}/${rounds} ─ live interval [${lo}, ${hi}) ─ ` +
      "both parties publish the TWO children of this node"
    );
    console.log();
    // Each round steps one notch to the right: the drawing descends with the search.
    const step = drawBisectionRound(lo, hi, corruptedLeaf, 5 + (r - 1) * 6);
    console.log();
    console.log(
      `     mid = ${step.mid}; [${step.newLo}, ${step.newHi}) remains` +
      `${step.newHi - step.newLo === 1 ? "  — a single leaf: the search is over" : ""}`
    );
    console.log();
    lo = step.newLo;
    hi = step.newHi;
  }
  console.log("  The rule drawn is the contract's, not a paraphrase: `advanceDispute` tests the");
  console.log("  LEFT child first and descends right only if the left one matches. Since a single");
  console.log("  leaf was altered here, only one of the children differs, and that tie-break is");
  console.log("  never exercised by this example.");
  console.log();
  console.log(`  Leaf ${lo} is what remains. Publishing the trace costs ${total}; finding the leaf costs ${rounds}.`);
  console.log("  That is the difference between N and log2(N) — between 1024 and 10 on a large");
  console.log("  trace — and it is why the protocol is viable. Without it, resolving the dispute");
  console.log("  would cost as much as redoing the whole computation.");
  await waitBetweenActs();
}

// ------------------------------------------------------------------- act 8 --
if (head(8, "The decision, under encryption", "and the settlement")) {
  console.log("  Now only one leaf is at stake. It is recomputed homomorphically from the operands'");
  console.log("  ciphertexts, and each claim is compared against that recomputation:");
  console.log();
  console.log("     recomputed := evaluate( operation, left_ciphertext, right_ciphertext )");
  console.log("     valid      := decrypt( FHE.eq( recomputed, claimed ) )");
  console.log();
  console.log("  Only the equality BIT is decrypted. Never an operand, never a result, never a");
  console.log("  claim. A single yes/no answer leaves the encrypted domain, and it is the answer to");
  console.log("  \"do these two ciphertexts hold the same number?\".");
  console.log();
  console.log("  That bit reaches the chain with t+1 EIP-712 signatures bound to this contract, this");
  console.log("  chain, this task, this leaf and this operation. And every ciphertext judged has to");
  console.log("  match the published handle, or it is not judged.");
  console.log();
  console.log("  Why not compare the ciphertexts' bytes, which would be far simpler: because, as");
  console.log("  act 5 said, the bytes do not reproduce across executions. An HONEST operator would");
  console.log("  be punished for that. The bit reproduces; the bytes do not.");
  console.log();
  console.log("  Outcome: the dishonest operator is punished, the accuser's bond comes back with a");
  console.log("  reward, the honest task is accepted, and the total published alongside the");
  console.log("  corrupted trace falls with it.");
  console.log();
  console.log("  What is MODELLED, said without rounding off: here the recomputation and the single");
  console.log("  decryption run in a local process that holds the key pair. In production the");
  console.log("  recomputation runs on the FHEVM coprocessor and the bits are threshold-decrypted");
  console.log("  by the key management service. The transport, the EIP-712 digest, the t+1 rule and");
  console.log("  the on-chain verification code are the production ones.");
  await waitBetweenActs();
}

if (!config.bare) {
  console.log();
  rule();
  console.log(" Narration complete.");
  rule();
  console.log();
  console.log("  To EXECUTE what acts 5 to 8 describe, against the validator network:");
  console.log("     examples/exemplo-aritmetico/run-arithmetic-demo.sh");
  console.log();
}
