/**
 * Example 02 -- Verified compliance rate from encrypted 0/1 indicators.
 *
 * Each owner reports an encrypted indicator: 1 if its measurement satisfied a
 * public compliance predicate (evaluated owner-side, e.g. "MOS >= 3"), 0
 * otherwise. The on-chain verified SUM of indicators is the compliance COUNT;
 * the compliance RATE is count / N with N public. A histogram is the same
 * pattern instantiated once per bin (one deployment per bin, or one indicator
 * column per bin).
 *
 * Caveat (inherited from the scheme): the signature authenticates that owner i
 * produced its indicator; it does not prove the indicator was derived honestly
 * from the underlying measurement. A dishonest owner degrades only its own
 * contribution.
 */
import { ethers } from "ethers";
import {
  buildScenario, newChain, runHonest, OP_SUM,
} from "../lib/scenario.mjs";

// Six owners; predicate already evaluated owner-side: 1 = compliant.
export const INDICATORS = [1n, 0n, 1n, 1n, 0n, 1n];
export const TAG = ethers.id("linear-app-02-compliance/epoch-1");

export function scenario(seed = "rate-demo") {
  return buildScenario({ values: INDICATORS, op: OP_SUM, tagHex: TAG, seed });
}

async function main() {
  const chain = await newChain();
  const s = scenario();
  console.log(`Indicators (owner-side only): ${INDICATORS.join(", ")}`);

  const { bound, plain } = await runHonest({
    chain,
    scenario: s,
    datasetRef: "examples/02-compliance-rate",
    taskLabel: "rate-task-1",
  });

  console.log(`On-chain result accepted: ${bound.accepted}`);
  console.log(`Consumer digest+commitment check: OK`);
  const n = BigInt(INDICATORS.length);
  console.log(`Decrypted verified compliance count: ${plain} of ${n}`);
  console.log(`Compliance rate = ${Number(plain) / Number(n)}`);
  if (plain !== s.expectedPlain) throw new Error("count mismatch");
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
