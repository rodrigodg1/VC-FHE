/**
 * Example 04 -- Variance from verified sufficient statistics.
 *
 * The contract verifies only fixed SUM/SUB aggregations, and each deployment
 * carries exactly one accumulator. Variance is still reachable because its
 * sufficient statistics are two sums: S1 = sum x_i and S2 = sum x_i^2. Each
 * owner locally derives and encrypts BOTH terms; the terms are aggregated in
 * TWO independent SUM deployments (one statement per deployment, distinct
 * dataset tags, same enrolled owners). After both verified sums decrypt:
 *
 *   population variance = S2/N - (S1/N)^2,   with N public.
 *
 * The same pattern with owner-side products x_i * y_i yields covariance and
 * least-squares fits from constant-cost verified aggregates.
 *
 * Caveat (owner-side consistency): each MKLHS signature authenticates that
 * owner i produced the submitted term; it does NOT prove that the value
 * signed as x_i^2 is the square of the value signed as x_i. A dishonest owner
 * can submit inconsistent (x_i, x_i^2) and thereby corrupt only its own
 * index's contribution; cross-record consistency proofs are outside the
 * linear path's scope.
 */
import { ethers } from "ethers";
import {
  buildScenario, newChain, runHonest, OP_SUM,
} from "../lib/scenario.mjs";

export const SAMPLES = [4n, 5n, 3n, 4n, 2n];
export const SQUARES = SAMPLES.map((x) => x * x);
export const TAG_S1 = ethers.id("linear-app-04-variance/sum-x/epoch-1");
export const TAG_S2 = ethers.id("linear-app-04-variance/sum-x2/epoch-1");

export function scenarioS1(seed = "variance-s1") {
  return buildScenario({ values: SAMPLES, op: OP_SUM, tagHex: TAG_S1, seed });
}
export function scenarioS2(seed = "variance-s2") {
  return buildScenario({ values: SQUARES, op: OP_SUM, tagHex: TAG_S2, seed });
}

async function main() {
  const chain = await newChain();
  const s1 = scenarioS1();
  const s2 = scenarioS2();
  console.log(`Samples (owner-side only): ${SAMPLES.join(", ")}`);
  console.log(`Owner-derived squares: ${SQUARES.join(", ")}`);

  const r1 = await runHonest({
    chain, scenario: s1,
    datasetRef: "examples/04-variance/sum-x",
    taskLabel: "variance-s1-task",
  });
  const r2 = await runHonest({
    chain, scenario: s2,
    datasetRef: "examples/04-variance/sum-x2",
    taskLabel: "variance-s2-task",
  });

  console.log(`S1 accepted on-chain: ${r1.bound.accepted}; S2 accepted: ${r2.bound.accepted}`);
  const n = Number(SAMPLES.length);
  const S1 = Number(r1.plain);
  const S2 = Number(r2.plain);
  const mean = S1 / n;
  const variance = S2 / n - mean * mean;
  console.log(`Verified S1 = ${S1}, S2 = ${S2}, N = ${n}`);
  console.log(`Mean = ${mean}; population variance = ${variance}`);
  if (r1.plain !== s1.expectedPlain || r2.plain !== s2.expectedPlain) {
    throw new Error("sufficient-statistic mismatch");
  }
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
