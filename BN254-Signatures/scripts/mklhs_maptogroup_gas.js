/**
 * MapToGroup trial distribution and its effect on admission gas.
 *
 * Admission runs the BLS01 MapToGroup on-chain, so its gas depends on the number
 * of trials the message point needed. This script admits a batch of records,
 * recomputes each record's trial count off-chain from the same seed, and reports
 * the distribution, the marginal gas per trial and the base cost. It documents
 * the bounded, input-dependent component of `admitRecord` reported in the experiment.
 *
 * Run: npx hardhat run scripts/mklhs_maptogroup_gas.js
 */
"use strict";

const hre = require("hardhat");
const { keccak256 } = require("ethers");
const L = require("./mklhs-lib.js");
const { sendGroupedBySigner } = require("./tx-batch.js");

const TAG = "0x" + "a7".repeat(32);
const N = Number(process.env.N || 60);
const P = L.Q;

/** Euler criterion over the BN254 base field. */
function isSquare(v) {
  let e = (P - 1n) / 2n;
  let base = v;
  let acc = 1n;
  while (e > 0n) {
    if (e & 1n) acc = (acc * base) % P;
    base = (base * base) % P;
    e >>= 1n;
  }
  return acc === 1n;
}

/** Number of MapToGroup trials the seed needs, matching the contract. */
function trialCount(seed) {
  for (let t = 0; t < 256; t++) {
    const t0 = BigInt(keccak256(new Uint8Array(Buffer.concat([Buffer.from([0x00, t]), L.be32(seed)]))));
    const t1 = BigInt(keccak256(new Uint8Array(Buffer.concat([Buffer.from([0x01, t]), L.be32(seed)]))));
    const x = L.mod(t0 * (1n << 256n) + t1, P);
    if (isSquare(L.mod((((x * x) % P) * x) % P + 3n, P))) return t + 1;
  }
  throw new Error("unhashable seed");
}

function be8(v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(v));
  return b;
}

function contextSeed(pk, index, op, totalItems, commitment) {
  return BigInt(
    keccak256(
      new Uint8Array(
        Buffer.concat([
          Buffer.from("MKLHS_CTX_V1_"),
          L.be32(pk[0]), L.be32(pk[1]), L.be32(pk[2]), L.be32(pk[3]),
          Buffer.from(TAG.slice(2), "hex"),
          be8(index),
          Buffer.from([op & 0xff]),
          be8(totalItems),
          L.be32(commitment[0]), L.be32(commitment[1]),
        ])
      )
    )
  );
}

async function main() {
  const signers = await hre.ethers.getSigners();
  const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "maptogroup-gas" });
  const owners = Array.from({ length: N }, (_, i) => signers[(i % (signers.length - 1)) + 1].address);

  const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
  const contract = await Factory.deploy("maptogroup-gas", 1, N, 0, TAG, owners, {
    value: hre.ethers.parseEther("1"),
  });
  await contract.waitForDeployment();

  const signerFor = (o) => signers[(o.index % (signers.length - 1)) + 1];
  const ownerRecords = scenario.owners;

  // Registrations first, batched by sending account; then admissions, likewise.
  // Both phases must stay separate: an index cannot be admitted before its key
  // is registered. Per-transaction receipts are preserved, which is what the
  // trial-count fit needs.
  await sendGroupedBySigner(ownerRecords, signerFor, (o) =>
    contract.connect(signerFor(o)).registerOwnerKey(o.index, L.g2ToContract(o.pk))
  );

  // Index 0 is admitted ALONE and FIRST, then the rest are batched.
  //
  // This ordering is load-bearing, not cosmetic. The first admission to land
  // initialises the on-chain accumulator and pays two cold SSTOREs (~70k gas)
  // that every later admission avoids. The fit below excludes index 0 on the
  // assumption that index 0 is that transaction. Batching all admissions
  // together breaks the assumption -- whichever transaction the validator
  // happens to order first pays the premium -- and the ~70k outlier then sits
  // inside the fit population and collapses the slope (measured: 2527 gas per
  // trial instead of 4585). Serialising one transaction costs a few seconds and
  // restores the exact semantics of the sequential measurement.
  const admitOne = (o) =>
    contract
      .connect(signerFor(o))
      .admitRecord(o.index, L.g1ToContract(o.commitment), L.g1ToContract(o.signature));

  const firstReceipt = await (await admitOne(ownerRecords[0])).wait();
  const restReceipts = await sendGroupedBySigner(
    ownerRecords.slice(1),
    signerFor,
    admitOne
  );
  const admitReceipts = [firstReceipt, ...restReceipts];

  // Index 0 pays two cold accumulator writes that later indices overwrite, so
  // it is reported but excluded from the marginal-cost fit.
  const rows = ownerRecords.map((o, k) => ({
    index: o.index,
    trials: trialCount(
      contextSeed(L.g2ToContract(o.pk), o.index, 0, N, L.g1ToContract(o.commitment))
    ),
    gas: Number(admitReceipts[k].gasUsed)
  }));

  const fit = rows.filter((r) => r.index !== 0);

  const byTrials = new Map();
  for (const r of fit) byTrials.set(r.trials, [...(byTrials.get(r.trials) || []), r.gas]);
  console.log("trials  records  mean_gas");
  for (const t of [...byTrials.keys()].sort((a, b) => a - b)) {
    const g = byTrials.get(t);
    const mean = g.reduce((a, b) => a + b, 0) / g.length;
    console.log(String(t).padStart(6), String(g.length).padStart(8), mean.toFixed(0).padStart(9));
  }

  const ts = fit.map((r) => r.trials);
  const gs = fit.map((r) => r.gas);
  const mt = ts.reduce((a, b) => a + b, 0) / ts.length;
  const mg = gs.reduce((a, b) => a + b, 0) / gs.length;
  let num = 0;
  let den = 0;
  for (let i = 0; i < ts.length; i++) {
    num += (ts[i] - mt) * (gs[i] - mg);
    den += (ts[i] - mt) ** 2;
  }
  const slope = num / den;
  const first = rows.find((r) => r.index === 0);
  // `rows` holds every admission; `fit` drops index 0, which pays the one-off
  // accumulator-initialization cost and would bias the slope. Both counts are
  // printed so the fit population is unambiguous: the experiment quotes the fitted
  // one, and the trial histogram above sums to it.
  const base = mg - slope * mt;

  // Guard the exclusion rule, AFTER the fit is known.
  //
  // Excluding index 0 is only correct if index 0 is the admission that
  // initialised the accumulator and paid its ~70k cold-SSTORE premium. The
  // robust test is its residual against the fitted line: the initialiser sits
  // tens of thousands of gas above it, every other admission sits within noise.
  //
  // An earlier version of this guard compared index 0 only against records with
  // the SAME trial count. That is vacuous whenever index 0's trial count is
  // unique, which happens routinely in the tail (observed at N = 120, where
  // index 0 needed 5 trials and no other record did). Residuals have no such
  // blind spot.
  const initialiserPremium = 40000; // two cold SSTOREs, conservatively
  {
    const zero = rows.find((r) => r.index === 0);
    const predicted = base + slope * zero.trials;
    const residual = zero.gas - predicted;
    if (residual < initialiserPremium) {
      throw new Error(
        `index 0 (${zero.gas} gas at ${zero.trials} trials) sits only ${Math.round(residual)} ` +
          `gas above the fitted line (${Math.round(predicted)}), so it did not initialise the ` +
          "accumulator. Another admission landed first, the exclusion is removing the wrong " +
          "row, and the fitted slope is biased. Admit index 0 alone and first."
      );
    }
    const worstOther = Math.max(...fit.map((r) => r.gas - (base + slope * r.trials)));
    if (worstOther >= initialiserPremium) {
      throw new Error(
        `a non-excluded admission sits ${Math.round(worstOther)} gas above the fitted line, ` +
          "which is the accumulator-initialisation signature. The fit population is polluted."
      );
    }
  }

  console.log(
    `\nadmissions = ${rows.length}, fitted = ${fit.length} ` +
      `(index 0 excluded from the fit: ${first.gas} gas at ${first.trials} trials)`
  );
  console.log(`mean trials = ${mt.toFixed(3)} (expected 2), max = ${Math.max(...ts)}`);
  console.log(`mean admission gas = ${mg.toFixed(0)}`);
  console.log(`marginal gas per trial = ${slope.toFixed(0)}, base = ${base.toFixed(0)}`);

  // Structured output. The console text above stays for interactive use, but the
  // implementation quotes the slope and the base, and a free-text log is not a
  // machine-readable source: transcribing from it is exactly how the reported
  // marginal cost drifted away from the measured one. Both a long-format CSV
  // (one row per admission, for re-fitting or plotting) and a JSON summary (the
  // fitted coefficients) are now written next to the other linear artifacts.
  const fs = require("node:fs");
  const path = require("node:path");
  const outDir = path.resolve(__dirname, "..");

  const csvRows = ["index,trials,gas_used,in_fit"];
  for (const r of rows) {
    csvRows.push(`${r.index},${r.trials},${r.gas},${r.index === 0 ? "false" : "true"}`);
  }
  const csvPath = path.join(outDir, "mklhs_maptogroup_admissions.csv");
  fs.writeFileSync(csvPath, csvRows.join("\n") + "\n");

  const summary = {
    schemaVersion: 1,
    generator: "scripts/mklhs_maptogroup_gas.js",
    generatedAt: new Date().toISOString(),
    contract: "MKLHSVerification",
    datasetSize: N,
    admissions: rows.length,
    fittedAdmissions: fit.length,
    excludedIndexZero: { index: first.index, trials: first.trials, gasUsed: first.gas },
    meanTrials: Number(mt.toFixed(4)),
    expectedMeanTrials: 2,
    maxTrials: Math.max(...ts),
    meanAdmissionGas: Math.round(mg),
    // Ordinary least squares of gas on trial count over the fitted rows.
    marginalGasPerTrial: Math.round(slope),
    baseGas: Math.round(base),
    trialHistogram: [...byTrials.keys()]
      .sort((a, b) => a - b)
      .map((t) => {
        const g = byTrials.get(t);
        return {
          trials: t,
          records: g.length,
          meanGas: Math.round(g.reduce((a, b) => a + b, 0) / g.length)
        };
      })
  };
  const jsonPath = path.join(outDir, "mklhs_maptogroup_fit.json");
  fs.writeFileSync(jsonPath, JSON.stringify(summary, null, 2) + "\n");

  console.log(`\nwrote: ${path.relative(outDir, csvPath)}`);
  console.log(`wrote: ${path.relative(outDir, jsonPath)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
