/**
 * Gas audit for the MKLHS (per-owner keys, no curator) linear path.
 * Measures, for each N and operation:
 *   - deployment gas (constructor stores N owner addresses; NO O(N) h2c loop)
 *   - registerOwnerKey gas (per owner, G2 subgroup check via pairing)
 *   - admitRecord gas (per record: 2-pair pairing + h2c + accumulator fold)
 *   - submitResultBound gas (O(1): G1 equality + storage)
 * Persists results to mklhs_gas_results.csv (archival requirement).
 *
 * Run: npx hardhat run scripts/mklhs_gas_audit.js
 */
"use strict";

const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const L = require("./mklhs-lib.js");

const TAG = "0x" + "c1".repeat(32);

async function measure(n, op) {
  const signers = await hre.ethers.getSigners();
  const deployer = signers[0];
  const operator = signers[1];
  // Owners cycle over available signers (hardhat default: 20); the admitting
  // sender does not affect gas materially, and authenticity comes from the
  // BLS signature, not msg.sender, so cycling is sound for measurement.
  const ownerSignerFor = (i) => signers[2 + (i % (signers.length - 2))];

  const scenario = L.buildScenario({ n, op, tagHex: TAG, seed: `gas-${n}-${op}` });
  const ownerAddrs = scenario.owners.map((o) => ownerSignerFor(o.index).address);

  const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
  const contract = await Factory.deploy(
    "gas-audit-dataset",
    1,
    n,
    op,
    TAG,
    ownerAddrs,
    { value: hre.ethers.parseEther("1") }
  );
  const deployReceipt = await (await contract.deploymentTransaction()).wait();

  // registerOwnerKey: measure every tx, report mean.
  let regTotal = 0n;
  for (const o of scenario.owners) {
    const tx = await contract
      .connect(ownerSignerFor(o.index))
      .registerOwnerKey(o.index, L.g2ToContract(o.pk));
    regTotal += (await tx.wait()).gasUsed;
  }

  // admitRecord: measure every tx, report mean.
  let admitTotal = 0n;
  for (const o of scenario.owners) {
    const tx = await contract
      .connect(ownerSignerFor(o.index))
      .admitRecord(
        o.index,
        L.g1ToContract(o.commitment),
        L.g1ToContract(o.signature)
      );
    admitTotal += (await tx.wait()).gasUsed;
  }

  // submitResultBound: O(1) result verification.
  const task = hre.ethers.keccak256(
    hre.ethers.solidityPacked(["address", "string"], [contract.target, "gas"])
  );
  await contract.registerTask(task, operator.address);
  await contract
    .connect(operator)
    .depositStake({ value: hre.ethers.parseEther("1") });
  const submitTx = await contract
    .connect(operator)
    .submitResultBound(
      task,
      scenario.outputDigest,
      L.g1ToContract(scenario.outputCommitment)
    );
  const submitGas = (await submitTx.wait()).gasUsed;

  return {
    n,
    op: op === 0 ? "SUM" : "SUB",
    deployment_gas: deployReceipt.gasUsed.toString(),
    register_key_gas_mean: (regTotal / BigInt(n)).toString(),
    admit_record_gas_mean: (admitTotal / BigInt(n)).toString(),
    admission_gas_total: (regTotal + admitTotal).toString(),
    submit_result_gas: submitGas.toString(),
  };
}

async function main() {
  const rows = [];
  for (const n of [10, 50, 100, 200]) {
    for (const op of [0, 1]) {
      const row = await measure(n, op);
      rows.push(row);
      console.log(row);
    }
  }
  const header = Object.keys(rows[0]).join(",");
  const csv = [header, ...rows.map((r) => Object.values(r).join(","))].join("\n");
  const out = path.join(__dirname, "..", "mklhs_gas_results.csv");
  fs.writeFileSync(out, csv + "\n");
  console.log(`\nWrote ${out}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
