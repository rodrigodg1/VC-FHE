/**
 * Example 03 -- Verified margin against a registered reference (SUB).
 *
 * The contract's SUB weight pattern is FIXED at admission time as
 *   w_0 = +1, w_{i>0} = -1
 * (MKLHS-Verification.sol, admitRecord: the accumulator folds -P(c_i) for
 * every index except 0). The expressible statistic is therefore
 *   x_0 - x_1 - ... - x_{N-1},
 * not an arbitrary difference of two groups.
 *
 * Regulatory reading used here: index 0 is a registered reference (a budget,
 * cap, or contracted allowance, contributed and signed by the party that owns
 * that reference); indices 1..N-1 are encrypted consumption/usage
 * measurements. The verified aggregate is the remaining MARGIN (slack)
 * against the reference.
 *
 * Regime note: plaintexts live in the scalar field, and the demo keeps the
 * true margin non-negative so the decrypted value is directly interpretable.
 * The leveled decryption budget of the linear path applies unchanged.
 */
import { ethers } from "ethers";
import {
  buildScenario, newChain, runHonest, OP_SUB,
} from "../lib/scenario.mjs";

// Index 0: registered monthly allowance. Indices 1..4: encrypted usage reports.
export const ALLOWANCE = 500n;
export const USAGE = [120n, 95n, 143n, 88n];
export const VALUES = [ALLOWANCE, ...USAGE];
export const TAG = ethers.id("linear-app-03-margin/epoch-1");

export function scenario(seed = "margin-demo") {
  return buildScenario({ values: VALUES, op: OP_SUB, tagHex: TAG, seed });
}

async function main() {
  const chain = await newChain();
  const s = scenario();
  console.log(`Reference (index 0): ${ALLOWANCE}`);
  console.log(`Usage reports (indices 1..${USAGE.length}): ${USAGE.join(", ")}`);

  const { bound, plain } = await runHonest({
    chain,
    scenario: s,
    datasetRef: "examples/03-margin-vs-reference",
    taskLabel: "margin-task-1",
  });

  console.log(`On-chain result accepted: ${bound.accepted}`);
  console.log(`Consumer digest+commitment check: OK`);
  console.log(`Decrypted verified margin: ${plain}`);
  const expected = USAGE.reduce((a, u) => a - u, ALLOWANCE);
  console.log(`Expected margin ${ALLOWANCE} - (${USAGE.join(" + ")}) = ${expected}`);
  if (plain !== s.expectedPlain || plain !== expected) throw new Error("margin mismatch");
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
