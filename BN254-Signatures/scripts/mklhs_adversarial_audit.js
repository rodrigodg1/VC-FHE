/**
 * Adversarial gas audit for the MKLHS (per-owner keys, no curator) path.
 *
 * For each adversarial scenario of the curator-free model (mirroring
 * test/mklhs-adversarial.test.js and test/mklhs.test.js), sends the attack
 * transaction with an explicit gas limit so the revert is MINED, and records
 * the gas actually consumed by the attacker. This quantifies the economic
 * asymmetry of the admission layer: every rejected forgery attempt costs the
 * attacker gas while leaving no state change; honest per-record costs are in
 * mklhs_gas_results.csv.
 *
 * Persists results to mklhs_adversarial_results.csv (archival requirement).
 *
 * Run: npx hardhat run scripts/mklhs_adversarial_audit.js
 */
"use strict";

const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const { bn254 } = require("@noble/curves/bn254");
const L = require("./mklhs-lib.js");

const TAG = "0x" + "c1".repeat(32);
const OTHER_TAG = "0x" + "d2".repeat(32);
const N = 10;
const GAS_LIMIT = 3_000_000n;

const Fp2 = bn254.fields.Fp2;
const G2 = bn254.G2.ProjectivePoint;

function nonSubgroupG2() {
  const base = G2.BASE.toAffine();
  const b2 = Fp2.sub(Fp2.sqr(base.y), Fp2.mul(Fp2.sqr(base.x), base.x));
  for (let k = 1n; k < 256n; k++) {
    const x = { c0: k, c1: 1n };
    let y;
    try {
      y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2));
    } catch (_) {
      continue;
    }
    const P = G2.fromAffine({ x, y });
    if (!P.multiplyUnsafe(L.R - 1n).add(P).equals(G2.ZERO)) {
      return [x.c0, x.c1, y.c0, y.c1];
    }
  }
  throw new Error("no non-subgroup G2 point found");
}

/** Send a transaction expected to revert; return gas actually consumed. */
async function minedRevertGas(txPromiseFactory) {
  try {
    const tx = await txPromiseFactory();
    const receipt = await tx.wait();
    return { reverted: receipt.status === 0, gas: receipt.gasUsed };
  } catch (err) {
    const receipt =
      err.receipt ||
      (err.transactionHash &&
        (await hre.ethers.provider.getTransactionReceipt(err.transactionHash)));
    if (receipt) return { reverted: receipt.status === 0, gas: receipt.gasUsed };
    // Hardhat rejected before mining (estimation path): retry is not
    // meaningful; report the revert without a mined gas figure.
    return { reverted: true, gas: null };
  }
}

async function main() {
  const signers = await hre.ethers.getSigners();
  const operator = signers[1];
  const ownerSigner = (i) => signers[2 + i];
  const attacker = signers[15];

  const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "adv-audit" });
  const ownerAddrs = scenario.owners.map((o) => ownerSigner(o.index).address);

  const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
  const contract = await Factory.deploy("adv-audit-dataset", 1, N, 0, TAG, ownerAddrs, {
    value: hre.ethers.parseEther("1"),
  });
  await contract.waitForDeployment();

  // Setup transactions must be CONFIRMED before the attack that depends on
  // them is submitted. On an auto-mining in-process EVM `await tx` suffices;
  // on a real network (2 s blocks) it only awaits submission, so an attack
  // could otherwise race ahead of the state it is meant to violate.
  for (const o of scenario.owners) {
    await (
      await contract.connect(ownerSigner(o.index)).registerOwnerKey(o.index, L.g2ToContract(o.pk))
    ).wait();
  }

  const o0 = scenario.owners[0];
  const o1 = scenario.owners[1];
  const rows = [];
  const record = async (scenarioName, expectedError, factory) => {
    const { reverted, gas } = await minedRevertGas(factory);
    rows.push({
      scenario: scenarioName,
      expected_error: expectedError,
      reverted,
      attacker_gas_used: gas === null ? "unmined" : gas.toString(),
    });
    console.log(rows[rows.length - 1]);
  };

  const opts = { gasLimit: GAS_LIMIT };

  // Key layer.
  await record("register_non_subgroup_key", "InvalidPublicKey", () =>
    contract.connect(ownerSigner(0)).registerOwnerKey(0, nonSubgroupG2(), opts)
  );
  await record("register_not_on_curve_key", "InvalidPublicKey", () =>
    contract.connect(ownerSigner(0)).registerOwnerKey(0, [1n, 2n, 3n, 4n], opts)
  );

  // Admission layer.
  const forged = L.sign(L.keygen(L.makeRng("adv-forger")).sk, o0.commitment, TAG, 0, { pk: o0.pk, op: 0, totalItems: N });
  await record("admit_forged_signature", "InvalidSignature", () =>
    contract
      .connect(attacker)
      .admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(forged), opts)
  );

  const other = L.commit(L.heEnc(scenario.he, 999n, L.makeRng("adv-other")), scenario.gens);
  await record("admit_substituted_commitment", "InvalidSignature", () =>
    contract
      .connect(attacker)
      .admitRecord(0, L.g1ToContract(other), L.g1ToContract(o0.signature), opts)
  );

  await record("admit_cross_index_replay", "InvalidSignature", () =>
    contract
      .connect(attacker)
      .admitRecord(1, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature), opts)
  );

  const crossTag = L.sign(o1.sk, o1.commitment, OTHER_TAG, 1, { pk: o1.pk, op: 0, totalItems: N });
  await record("admit_cross_tag_signature", "InvalidSignature", () =>
    contract
      .connect(attacker)
      .admitRecord(1, L.g1ToContract(o1.commitment), L.g1ToContract(crossTag), opts)
  );

  await record("admit_mauled_signature", "InvalidSignature", () =>
    contract
      .connect(attacker)
      .admitRecord(
        0,
        L.g1ToContract(o0.commitment),
        L.g1ToContract(o0.signature.add(L.G1.BASE)),
        opts
      )
  );

  // Honest admission of record 0, then a duplication attempt.
  await (
    await contract.admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
  ).wait();
  await record("admit_double_admission", "AlreadyAdmitted", () =>
    contract
      .connect(attacker)
      .admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature), opts)
  );

  // Finalization layer: premature submission (records 1..N-1 not admitted).
  const task = hre.ethers.keccak256(
    hre.ethers.solidityPacked(["address", "string"], [contract.target, "adv"])
  );
  await (await contract.registerTask(task, operator.address)).wait();
  await (
    await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })
  ).wait();
  await record("submit_before_full_admission", "IncompleteAdmission", () =>
    contract
      .connect(operator)
      .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment), opts)
  );

  // Admit the rest, then a deviating output and an unauthorized task.
  for (const o of scenario.owners.slice(1)) {
    await (
      await contract
        .connect(ownerSigner(o.index))
        .admitRecord(o.index, L.g1ToContract(o.commitment), L.g1ToContract(o.signature))
    ).wait();
  }
  await record("submit_deviating_output", "InvalidResult", () =>
    contract
      .connect(operator)
      .submitResultBound(
        task,
        scenario.outputDigest,
        L.g1ToContract(scenario.outputCommitment.add(L.G1.BASE)),
        opts
      )
  );
  await record("register_task_unauthorized", "Unauthorized", () =>
    contract.connect(attacker).registerTask(hre.ethers.keccak256("0x01"), attacker.address, opts)
  );

  const header = Object.keys(rows[0]).join(",");
  const csv = [header, ...rows.map((r) => Object.values(r).join(","))].join("\n");
  const out = path.join(__dirname, "..", "mklhs_adversarial_results.csv");
  fs.writeFileSync(out, csv + "\n");
  console.log(`\nWrote ${out}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
