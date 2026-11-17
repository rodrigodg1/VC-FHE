/**
 * Example 01 -- Verified mean over encrypted ratings.
 *
 * What is verified on-chain: the SUM of N owner-signed encrypted ratings
 * (allowedOperation = 0, all weights +1). The mean is derived PUBLICLY after
 * decryption as (verified sum) / N, where N = totalItems is a public contract
 * parameter. The division is not a homomorphic operation and does not need
 * one: the verified object is the sum; the count is public.
 *
 * This mirrors the experiment's QoE MOS pipeline: the MOS mean is the verified
 * encrypted sum divided by the public input count after decryption.
 */
import { ethers } from "ethers";
import {
  buildScenario, newChain, runHonest, OP_SUM,
} from "../lib/scenario.mjs";

// Five owners, MOS-style ratings on the 1..5 domain.
export const RATINGS = [4n, 5n, 3n, 4n, 2n];
export const TAG = ethers.id("linear-app-01-mean/epoch-1");

export function scenario(seed = "mean-demo") {
  return buildScenario({ values: RATINGS, op: OP_SUM, tagHex: TAG, seed });
}

async function main() {
  const chain = await newChain();
  const s = scenario();
  console.log(`Ratings (plaintexts, owner-side only): ${RATINGS.join(", ")}`);

  const { bound, plain } = await runHonest({
    chain,
    scenario: s,
    datasetRef: "examples/01-mean-aggregate",
    taskLabel: "mean-task-1",
  });

  console.log(`On-chain result accepted: ${bound.accepted}`);
  console.log(`Consumer digest+commitment check: OK`);
  console.log(`Decrypted verified sum: ${plain}`);
  const n = BigInt(RATINGS.length);
  console.log(`Public count N: ${n}`);
  console.log(`Mean = ${plain}/${n} = ${Number(plain) / Number(n)}`);
  if (plain !== s.expectedPlain) throw new Error("sum mismatch");
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
