/**
 * Real-TFHE payloads through the multi-key (curator-free) MKLHS admission flow,
 * on-chain, using the SAME Hardhat toolchain as scripts/mklhs_gas_audit.js so
 * that the reported gas is directly comparable to Table `tab:mklhs-gas` in the
 * experiment. The measurement settings are pinned in hardhat.config.js and are all
 * priced into the table: solc 0.8.20, evmVersion london, optimizer DISABLED,
 * runtime hardfork london (the rules the validator genesis activates at block
 * zero). Enabling the optimizer lowers deployment gas by 18-39% over the
 * evaluated range of N without changing any acceptance outcome, so the setting
 * must not be changed without regenerating this CSV and the experiment table.
 *
 * Consumes the JSON emitted by the Rust generator:
 *
 *   cargo run --release --bin output_binding_tfhe -- emit-onchain-mk \
 *       onchain_proofs_tfhe_mk.json 10 50 100 200
 *
 * in which every record is a REAL leveled TFHE-LWE ciphertext vector
 * (tfhe-rs core_crypto, k = 742, D = 743) committed as P(c_i) = sum_d c_d G_d
 * and signed by its OWN data owner: sigma_i = sk_i (P(c_i) + H(tag, i)). There
 * is no curator; no central signing authority exists.
 *
 * For each (N, op) entry:
 *   1. deploy MKLHSVerification with the payload dataset tag and one enrolled
 *      address per index (cycling over Hardhat accounts);
 *   2. registerOwnerKey for every index;
 *   3. admitRecord for every record (on-chain two-pairing BLS check);
 *   4. three adversarial rejections (all must revert / reject):
 *        a. wrong-key admission, b. replayed admission, c. substituted output;
 *   5. registerTask + submitResultBound of the honest output (accepted);
 *   6. consumer verification OFF-chain: recompute digest and P(A') from the
 *      delivered lifted coordinates and the emitted generators, compare with
 *      the on-chain record.
 *
 * Run:
 *   PAYLOAD=onchain_proofs_tfhe_mk.json CSV_OUT=mklhs_tfhe_gas_results.csv \
 *     npx hardhat run scripts/mklhs_tfhe_onchain.js
 * (Defaults: onchain_proofs_tfhe_mk.json, mklhs_tfhe_gas_results.csv.)
 *
 * Accepts the schema-identical pseudorandom payload (scheme
 * "output_binding_demo_multikey") for wiring regression; the scheme is recorded
 * in every CSV row so real and demo runs are never conflated.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const { sendGroupedBySigner } = require("./tx-batch.js");
const W = require("./workflow-steps.js");
const { bn254 } = require("@noble/curves/bn254");

const root = path.join(__dirname, "..");
const payloadPath = process.env.PAYLOAD
  ? path.resolve(process.env.PAYLOAD)
  : path.join(root, "onchain_proofs_tfhe_mk.json");
const csvPath = process.env.CSV_OUT
  ? path.resolve(process.env.CSV_OUT)
  : path.join(root, "mklhs_tfhe_gas_results.csv");

const KNOWN_SCHEMES = [
  "output_binding_tfhe_multikey", // real TFHE-LWE ciphertext vectors (Rust emitter)
  "output_binding_demo_multikey", // pseudorandom coords, wiring regression only
];

// --- consumer-side recomputation (mirrors the Rust digest and commitment) ---
function coordsDigest(coordsDec) {
  const bytes = new Uint8Array(coordsDec.length * 32);
  coordsDec.forEach((c, i) => {
    let v = BigInt(c);
    for (let j = 31; j >= 0; j--) {
      bytes[i * 32 + j] = Number(v & 0xffn);
      v >>= 8n;
    }
  });
  return hre.ethers.keccak256(bytes);
}

const G1 = bn254.G1.ProjectivePoint;
const g1FromDec = ([x, y]) => G1.fromAffine({ x: BigInt(x), y: BigInt(y) });
function recomputeCommitment(liftedDec, gensDec) {
  const R = bn254.fields.Fr.ORDER;
  let acc = G1.ZERO;
  for (let d = 0; d < liftedDec.length; d++) {
    const s = ((BigInt(liftedDec[d]) % R) + R) % R;
    if (s === 0n) continue;
    acc = acc.add(g1FromDec(gensDec[d]).multiply(s));
  }
  const a = acc.toAffine();
  return [a.x.toString(), a.y.toString()];
}

async function measure(entry, gens, scheme, signers) {
  const { n, allowed_op: op, records } = entry;
  const opName = op === 0 ? "SUM" : "SUB";
  const deployer = signers[0];
  const operator = signers[1];
  const ownerSignerFor = (i) => signers[2 + (i % (signers.length - 2))];
  const ownerAddrs = records.map((r) => ownerSignerFor(r.index).address);

  W.step("W1", `deploying for N=${n}, op=${opName}, tag=${entry.dataset_tag.slice(0, 10)}...`);
  const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
  const contract = await Factory.connect(deployer).deploy(
    "tfhe-mk-dataset",
    1,
    n,
    op,
    entry.dataset_tag,
    ownerAddrs,
    { value: hre.ethers.parseEther("1") }
  );
  const deployReceipt = await (await contract.deploymentTransaction()).wait();

  W.step(
    "W2",
    `${n} owner keys to self-register, then ${n} TFHE-LWE records to admit ` +
      "(the ciphertexts and signatures were produced off-chain by the Rust emitter)"
  );
  // Registrations are independent across indices; batch them by sending
  // account so the round trips overlap without ever racing a nonce.
  let regTotal = 0n;
  await sendGroupedBySigner(
    records,
    (r) => ownerSignerFor(r.index),
    (r) =>
      contract.connect(ownerSignerFor(r.index)).registerOwnerKey(r.index, r.pubkey.map(BigInt)),
    (_r, receipt) => {
      regTotal += receipt.gasUsed;
    }
  );

  // Adversarial (a): wrong-key admission before any honest admission consumes index 0.
  let adversarial = 0;
  if (n > 1) {
    let rejected = false;
    try {
      await (
        await contract
          .connect(ownerSignerFor(records[0].index))
          .admitRecord(0, records[0].commitment.map(BigInt), entry.wrong_key_signature.map(BigInt))
      ).wait();
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error(`n=${n} ${opName}: wrong-key admission accepted`);
    adversarial++;
  }

  // Admissions are independent too: the contract folds each commitment into
  // the accumulator by point addition, which is commutative, so the order in
  // which they land cannot change P_agg.
  let admitTotal = 0n;
  await sendGroupedBySigner(
    records,
    (r) => ownerSignerFor(r.index),
    (r) =>
      contract
        .connect(ownerSignerFor(r.index))
        .admitRecord(r.index, r.commitment.map(BigInt), r.signature.map(BigInt)),
    (_r, receipt) => {
      admitTotal += receipt.gasUsed;
    }
  );

  // Adversarial (b): replayed admission of a consumed index.
  {
    let rejected = false;
    try {
      const r = records[0];
      await (
        await contract
          .connect(ownerSignerFor(r.index))
          .admitRecord(r.index, r.commitment.map(BigInt), r.signature.map(BigInt))
      ).wait();
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error(`n=${n} ${opName}: replayed admission accepted`);
    adversarial++;
  }

  // Adversarial (c): substituted output commitment rejected by verifyBound.
  if (await contract.verifyBound(entry.attack.commitment.map(BigInt))) {
    throw new Error(`n=${n} ${opName}: substituted output accepted by verifyBound`);
  }
  adversarial++;

  W.step("W4", "assigning the one-shot task, then submitting (taskId, d_out, P(A))");
  const taskId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(`tfhe-mk-${n}-${opName}`));
  await (await contract.connect(deployer).registerTask(taskId, operator.address)).wait();
  await (await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })).wait();
  const submitReceipt = await (
    await contract
      .connect(operator)
      .submitResultBound(taskId, entry.honest.output_digest, entry.honest.commitment.map(BigInt))
  ).wait();

  W.step(
    "W5",
    "recomputing d_out and P(A) from the delivered 743-coordinate vector and " +
      "comparing both against the on-chain record"
  );
  const digestMatch = coordsDigest(entry.honest.lifted) === entry.honest.output_digest;
  const recomputed = recomputeCommitment(entry.honest.lifted, gens);
  const commitmentMatch =
    recomputed[0] === entry.honest.commitment[0] && recomputed[1] === entry.honest.commitment[1];
  if (!digestMatch) throw new Error(`n=${n} ${opName}: consumer digest mismatch`);
  if (!commitmentMatch) throw new Error(`n=${n} ${opName}: consumer commitment mismatch`);

  return {
    scheme,
    n,
    operation: opName,
    deployment_gas: deployReceipt.gasUsed.toString(),
    register_key_gas_mean: (regTotal / BigInt(n)).toString(),
    admit_record_gas_mean: (admitTotal / BigInt(n)).toString(),
    submit_result_gas: submitReceipt.gasUsed.toString(),
    adversarial_checks: `${adversarial}/3`,
    consumer_digest_match: digestMatch,
    consumer_commitment_match: commitmentMatch,
  };
}

async function main() {
  if (!fs.existsSync(payloadPath)) {
    throw new Error(
      `Payload not found: ${payloadPath}\n` +
        `Generate it first:\n` +
        `  cargo run --release --bin output_binding_tfhe -- emit-onchain-mk onchain_proofs_tfhe_mk.json 10 50 100 200\n` +
        `or, without the Rust toolchain, a schema-identical demo payload:\n` +
        `  node scripts/mklhs_make_demo_payload.mjs onchain_proofs_demo_mk.json 10 50 100 200`
    );
  }
  const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
  if (!KNOWN_SCHEMES.includes(payload.scheme)) {
    throw new Error(`unexpected scheme: ${payload.scheme}`);
  }
  const realTfhe = payload.scheme === "output_binding_tfhe_multikey";
  console.log(
    realTfhe
      ? "Payload: REAL TFHE-LWE ciphertext-vector commitments."
      : "Payload: DEMO encoding (wiring regression; gas is representative, correctness semantics are not)."
  );

  const signers = await hre.ethers.getSigners();
  if (signers.length < 4) throw new Error("need at least 4 Hardhat accounts");

  const rows = [];
  for (const entry of payload.sizes) {
    const row = await measure(entry, payload.commit_generators, payload.scheme, signers);
    rows.push(row);
    console.log(
      `n=${row.n} ${row.operation}: deploy=${row.deployment_gas} keyReg(mean)=${row.register_key_gas_mean} ` +
        `admit(mean)=${row.admit_record_gas_mean} submit=${row.submit_result_gas} ` +
        `adversarial=${row.adversarial_checks} consumer digest/commitment=OK`
    );
  }

  const header = Object.keys(rows[0]).join(",");
  const csv = [header, ...rows.map((r) => Object.values(r).join(","))].join("\n");
  fs.writeFileSync(csvPath, csv + "\n");
  console.log(`\nWrote ${csvPath}`);
  console.log(
    realTfhe
      ? "All admissions carried REAL TFHE-LWE commitments; no curator key exists in this pipeline."
      : "Wiring regression complete. Re-run against the Rust-emitted payload for the real-TFHE claim."
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
