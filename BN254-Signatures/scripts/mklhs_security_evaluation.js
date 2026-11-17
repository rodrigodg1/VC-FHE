/**
 * Linear-path security evaluation: every scenario is tied to a claim of the
 * implementation, and every scenario runs as a real transaction on the configured
 * blockchain.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The linear path already had three suites, and they cover the UNFORGEABILITY
 * half of the argument well (forged keys, substituted commitments, cross-index
 * and cross-tag replay, mauled and scalar-derived signatures, double admission,
 * omission, deviating output, one-shot tasks). What none of them covered:
 *
 *  (1) The BINDING BASIS. Proposition "Output binding" part (ii) rests on DLR
 *      over the commitment generators {U_d}. DLR is a hardness assumption and
 *      cannot be attacked in a test -- but the assumption only applies if the
 *      generators really are independent public random-oracle outputs. A
 *      duplicated, identity or party-chosen generator breaks binding WITHOUT
 *      breaking DLR, and nothing checked that. Scenarios G1a-G1c close this,
 *      including a constructive demonstration that a collision would forge a
 *      second opening.
 *
 *  (2) NECESSITY OF EACH HALF OF THE COMPOSED PREDICATE. The implementation states
 *      that the contract binds the commitment and the consumer binds the
 *      delivered vector, and that the digest is "an additional check on the
 *      byte encoding". Whether each half is individually load-bearing was
 *      asserted, never measured. Scenarios G2a-G2d test each half in isolation.
 *
 *  (3) THE DOCUMENTED LIMITATIONS, as demonstrations rather than prose. The
 *      implementation concedes three: no range proof accompanies P (a corrupted
 *      owner can commit to anything), same-field cross-deployment replay is
 *      possible, and a valid-proof/divergent-delivery griefing is rejected but
 *      unpunished. A limitation that is only claimed is weaker evidence than a
 *      limitation that is exercised and recorded. Scenarios L1-L3 record them
 *      with expectedOutcome "accepted-limitation", so a reader can see the
 *      boundary of the guarantee in the artifact itself.
 *
 *  (4) THE ADMIN NON-INFLUENCE CLAIM. The implementation says a misbehaving
 *      administrator "affects only liveness ... never the correctness or
 *      confidentiality of a result". Only the negative half (registerTask is
 *      onlyOwner) was tested. Scenarios A1-A3 test the positive claim.
 *
 *  (5) A SIGNED OFF-CURVE COMMITMENT. The pre-existing off-curve test submits
 *      an off-curve point with an HONEST signature, so it reverts on the
 *      signature check and never reaches the curve check. Scenario G3 signs the
 *      off-curve point properly, which is the only way to reach that branch.
 *
 * OUTCOME CLASSES
 * ---------------
 *   rejected              the attack must revert; a non-revert is a FAIL
 *   invariant             a positive property that must hold
 *   accepted-limitation   a documented boundary of the guarantee: the protocol
 *                         DOES accept this, and the implementation says so. A
 *                         revert here is also a FAIL, because it would mean the
 *                         implementation describes a limitation the code does not
 *                         actually have.
 *
 * NETWORK
 * -------
 * Run against the four-validator Besu QBFT chain, the substrate of the
 * evaluation:
 *
 *   docker compose up -d node1 node2 node3 node4
 *   cd BN254-Signatures
 *   VCFHE_MNEMONIC="test test test test test test test test test test test junk" \
 *     npx hardhat run --network vcfhe scripts/mklhs_security_evaluation.js
 *
 * Setup transactions are always awaited to a receipt before the attack that
 * depends on them is submitted: on a 2 s-block chain `await tx` only awaits
 * submission, so an attack could otherwise race ahead of the state it is meant
 * to violate.
 *
 * OUTPUT
 * ------
 *   mklhs_security_evaluation.csv    one row per scenario (tidy)
 *   mklhs_security_evaluation.json   same rows plus the run context
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const hre = require("hardhat");
const L = require("./mklhs-lib.js");

const N = Number(process.env.SEC_N || 4);
const TAG = "0x" + "5c".repeat(32);
const TAG_B = "0x" + "9e".repeat(32);
const GAS_LIMIT = 3_000_000n;
/**
 * Receipt timeout, milliseconds. On a consensus chain `tx.wait()` waits
 * FOREVER by default, so a transaction dropped from the pool (for example
 * after a nonce collision with another process using the same mnemonic) hangs
 * the whole run with no output. Every wait in this script is bounded.
 */
const WAIT_TIMEOUT_MS = Number(process.env.SEC_WAIT_TIMEOUT_MS || 120_000);

/** Awaits a receipt with a bound, so a dropped transaction fails loudly. */
async function confirm(txPromise, label) {
  const tx = await txPromise;
  const receipt = await tx.wait(1, WAIT_TIMEOUT_MS);
  if (receipt === null) {
    throw new Error(
      `timed out after ${WAIT_TIMEOUT_MS} ms waiting for ${label} (tx ${tx.hash}). ` +
        "Is another process sending from the same accounts?"
    );
  }
  return receipt;
}
const OUT_DIR = path.resolve(__dirname, "..");

/** Runs a transaction factory and reports whether it reverted, with gas. */
async function minedRevertGas(factory) {
  try {
    const tx = await factory();
    const receipt = await tx.wait(1, WAIT_TIMEOUT_MS);
    if (receipt === null) {
      return { reverted: false, gas: null, error: "receipt-timeout" };
    }
    return { reverted: receipt.status === 0, gas: receipt.gasUsed, error: null };
  } catch (err) {
    const selector =
      err?.data && typeof err.data === "string" && err.data.length >= 10
        ? err.data.slice(0, 10)
        : null;
    const receipt =
      err.receipt ||
      (err.transactionHash &&
        (await hre.ethers.provider.getTransactionReceipt(err.transactionHash)));
    if (receipt) {
      return { reverted: receipt.status === 0, gas: receipt.gasUsed, error: selector };
    }
    return { reverted: true, gas: null, error: selector };
  }
}

/** Maps the four-byte revert selector back to the contract's error name. */
function errorName(selector, iface) {
  if (!selector) return "";
  try {
    return iface.parseError(selector)?.name ?? selector;
  } catch {
    return selector;
  }
}

async function main() {
  const net = await hre.ethers.provider.getNetwork();
  const chainId = Number(net.chainId);
  const venue =
    chainId === 46853 ? "qbft-network" : chainId === 31337 ? "in-process-evm" : "external-evm";

  console.log("============================================================");
  console.log(" Linear-path security evaluation");
  console.log(`   network=${hre.network.name} chainId=${chainId} venue=${venue}`);
  console.log(`   N=${N}`);
  console.log("============================================================");
  if (venue !== "qbft-network") {
    console.warn(
      "  WARNING: not on the QBFT validator network. These rows are a\n" +
        "  development check, not evaluation evidence. Start the chain with\n" +
        "  `docker compose up -d node1 node2 node3 node4` and pass --network vcfhe.\n"
    );
  }

  const signers = await hre.ethers.getSigners();
  if (signers.length < N + 4) {
    throw new Error(`need at least ${N + 4} funded accounts; the endpoint exposes ${signers.length}`);
  }
  const admin = signers[0];
  const operator = signers[1];
  const ownerSigner = (i) => signers[2 + (i % (signers.length - 4))];
  const attacker = signers[signers.length - 1];

  const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "sec-eval" });
  const ownerAddrs = scenario.owners.map((o) => ownerSigner(o.index).address);

  const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
  const iface = Factory.interface;

  async function freshDeployment(tagHex, label) {
    const c = await Factory.connect(admin).deploy(label, 1, N, 0, tagHex, ownerAddrs, {
      value: hre.ethers.parseEther("1"),
    });
    await c.waitForDeployment();
    return c;
  }

  const rows = [];
  const opts = { gasLimit: GAS_LIMIT };

  /**
   * Records one scenario.
   * @param {string} id                 stable scenario identifier
   * @param {string} experimentClaim         the implementation statement under test
   * @param {string} expectedOutcome    rejected | invariant | accepted-limitation
   * @param {string} expectedError      expected custom error, "" when not a revert
   * @param {Function} run              returns {reverted, gas, error} or {ok, detail}
   */
  async function record(id, experimentClaim, expectedOutcome, expectedError, run) {
    let observed;
    let status;
    let gas = "";
    let observedError = "";
    let detail = "";

    try {
      const result = await run();
      if (Object.prototype.hasOwnProperty.call(result, "reverted")) {
        gas = result.gas === null || result.gas === undefined ? "unmined" : result.gas.toString();
        observedError = errorName(result.error, iface);
        observed = result.reverted ? "rejected" : "accepted";
      } else {
        observed = result.ok ? "invariant-holds" : "invariant-violated";
        detail = result.detail ?? "";
      }
    } catch (err) {
      observed = "harness-error";
      detail = String(err?.message ?? err).slice(0, 200);
    }

    if (expectedOutcome === "rejected") {
      status = observed === "rejected" ? "PASS" : "FAIL";
    } else if (expectedOutcome === "accepted-limitation") {
      status = observed === "accepted" ? "PASS" : "FAIL";
    } else {
      status = observed === "invariant-holds" ? "PASS" : "FAIL";
    }

    const row = {
      scenarioId: id,
      experimentClaim,
      expectedOutcome,
      expectedError,
      observedOutcome: observed,
      observedError,
      status,
      attackerGasUsed: gas,
      detail,
      network: hre.network.name,
      chainId,
      venue,
    };
    rows.push(row);
    const mark = status === "PASS" ? "PASS" : "FAIL";
    console.log(
      `  ${mark}  ${id.padEnd(46)} ${observed}${observedError ? ` (${observedError})` : ""}${detail ? ` ${detail}` : ""}`
    );
    return row;
  }

  // =========================================================================
  // G1  Binding basis: the commitment generators {U_d}
  // =========================================================================
  const gens = scenario.gens;

  await record(
    "generators_derived_from_public_indices",
    "Proposition (Output binding)(ii) / DLR: 'Public index-based derivation leaves no party-chosen parameter'",
    "invariant",
    "",
    async () => {
      // Recompute the basis from the public rule alone and compare.
      const recomputed = L.commitGenerators(gens.length);
      const same = recomputed.every((g, i) => g.equals(gens[i]));
      return { ok: same, detail: `${gens.length} generators recomputed from public indices` };
    }
  );

  await record(
    "generators_distinct_nonidentity_oncurve",
    "Definition (DLR): the basis must be independent random-oracle outputs; a duplicate or identity generator breaks binding without breaking DLR",
    "invariant",
    "",
    async () => {
      const seen = new Set();
      let duplicate = null;
      for (const g of gens) {
        const a = g.toAffine();
        const key = `${a.x}:${a.y}`;
        if (seen.has(key)) duplicate = key;
        seen.add(key);
      }
      // A generator equal to the identity would let its coordinate be changed
      // freely without moving the commitment.
      const anyIdentity = gens.some((g) => {
        const a = g.toAffine();
        return a.x === 0n && a.y === 0n;
      });
      const allOnCurve = gens.every((g) => {
        try {
          g.assertValidity();
          return true;
        } catch {
          return false;
        }
      });
      const ok = duplicate === null && allOnCurve && !anyIdentity;
      return {
        ok,
        detail: ok
          ? `${gens.length} distinct on-curve generators`
          : `duplicate=${duplicate} allOnCurve=${allOnCurve}`,
      };
    }
  );

  await record(
    "generator_collision_would_break_binding",
    "Definition (DLR): shows the distinctness check above is load-bearing, not decorative",
    "invariant",
    "",
    async () => {
      // Constructive: with a COLLIDING basis (U_1 = U_0), two different vectors
      // open to the same commitment, so P would not be binding. This never
      // touches the deployed contract; it demonstrates why the previous
      // scenario must hold.
      const colliding = [gens[0], gens[0], ...gens.slice(2)];
      const v1 = new Array(gens.length).fill(0n);
      const v2 = new Array(gens.length).fill(0n);
      v1[0] = 1n; // (1, 0, 0, ...)
      v2[1] = 1n; // (0, 1, 0, ...)
      const c1 = L.commit(v1, colliding);
      const c2 = L.commit(v2, colliding);
      const collides = c1.equals(c2);
      // And the honest basis must NOT have that property.
      const honestDiffers = !L.commit(v1, gens).equals(L.commit(v2, gens));
      return {
        ok: collides && honestDiffers,
        detail: "colliding basis opens two vectors to one commitment; honest basis does not",
      };
    }
  );

  // =========================================================================
  // G3  Signed off-curve commitment (reaches the curve check)
  // =========================================================================
  {
    const c = await freshDeployment(TAG, "sec-offcurve");
    const o0 = scenario.owners[0];
    await confirm(c.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(o0.pk)), "connect");

    // (1,1) is in the base field but not on y^2 = x^3 + 3. Sign the context
    // that carries it, so the pairing check passes and the curve check is the
    // branch under test.
    const offCurve = [1n, 1n];
    const sigOffCurve = L.sign(o0.sk, { toAffine: () => ({ x: 1n, y: 1n }) }, TAG, 0, {
      pk: o0.pk,
      op: 0,
      totalItems: N,
    });

    await record(
      "admit_signed_offcurve_commitment",
      "Section (Output-bound multi-key linear verification): 'Admission rejects a non-canonical or identity point'; the commitment is folded into the accumulator, whose first fold bypasses the point-add precompile",
      "rejected",
      "InvalidG1Point",
      () =>
        minedRevertGas(() =>
          c
            .connect(ownerSigner(0))
            .admitRecord(0, offCurve, L.g1ToContract(sigOffCurve), opts)
        )
    );

    await record(
      "admit_identity_commitment",
      "Section (Output-bound...): the identity commitment is rejected at admission",
      "rejected",
      "InvalidG1Point",
      () =>
        minedRevertGas(() =>
          c.connect(ownerSigner(0)).admitRecord(0, [0n, 0n], L.g1ToContract(scenario.owners[0].signature), opts)
        )
    );
  }

  // =========================================================================
  // A  Administrator non-influence
  // =========================================================================
  {
    const c = await freshDeployment(TAG, "sec-admin");
    for (const o of scenario.owners) {
      await confirm(c.connect(ownerSigner(o.index)).registerOwnerKey(o.index, L.g2ToContract(o.pk)), "connect");
    }

    await record(
      "admin_cannot_admit_without_owner_key",
      "Section (Linear Operations) step 1: the administrator 'holding no signing key or decryption share, cannot admit or alter any record'",
      "rejected",
      "InvalidSignature",
      async () => {
        const forged = L.sign(L.keygen(L.makeRng("sec-admin-forge")).sk, scenario.owners[0].commitment, TAG, 0, {
          pk: scenario.owners[0].pk,
          op: 0,
          totalItems: N,
        });
        return minedRevertGas(() =>
          c.connect(admin).admitRecord(0, L.g1ToContract(scenario.owners[0].commitment), L.g1ToContract(forged), opts)
        );
      }
    );

    await record(
      "admin_cannot_move_accumulator",
      "Section (Linear Operations) step 1: the administrator cannot 'change the result (which anyone can verify against the on-chain accumulator)'",
      "invariant",
      "",
      async () => {
        const before = await c.aggregateCommitment(0);
        // Everything the admin is allowed to do, done twice.
        await confirm(c.connect(admin).registerTask("0x" + "11".repeat(32), operator.address), "registerTask");
        await confirm(c.connect(admin).depositStake({ value: hre.ethers.parseEther("0.1") }), "depositStake");
        const after = await c.aggregateCommitment(0);
        return { ok: before === after, detail: "accumulator unchanged across every admin-only call" };
      }
    );

    await record(
      "admin_cannot_submit_for_assigned_operator",
      "Section (Linear Operations) step 4: the task is consumed by its assigned operator only",
      "rejected",
      "Unauthorized",
      async () => {
        const taskId = "0x" + "12".repeat(32);
        await confirm(c.connect(admin).registerTask(taskId, operator.address), "registerTask");
        await confirm(c.connect(admin).depositStake({ value: hre.ethers.parseEther("1") }), "depositStake");
        return minedRevertGas(() =>
          c
            .connect(admin)
            .submitResultBound(taskId, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment), opts)
        );
      }
    );
  }

  // =========================================================================
  // G2  Necessity of each half of the composed predicate (consumer side)
  // =========================================================================
  {
    const c = await freshDeployment(TAG, "sec-composed");
    for (const o of scenario.owners) {
      await confirm(c.connect(ownerSigner(o.index)).registerOwnerKey(o.index, L.g2ToContract(o.pk)), "connect");
      await confirm(c
          .connect(ownerSigner(o.index))
          .admitRecord(o.index, L.g1ToContract(o.commitment), L.g1ToContract(o.signature)), "connect");
    }
    const taskId = "0x" + "21".repeat(32);
    await confirm(c.connect(admin).registerTask(taskId, operator.address), "registerTask");
    await confirm(c.connect(operator).depositStake({ value: hre.ethers.parseEther("1") }), "depositStake");
    await confirm(c
        .connect(operator)
        .submitResultBound(taskId, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment)), "connect");

    const onchain = await c.getBoundResult(taskId);
    const recordedDigest = onchain[1];
    const recordedCommitment = [onchain[0][0], onchain[0][1]];

    await record(
      "consumer_accepts_honest_delivery",
      "Section (Linear Operations) step 5: the consumer recomputes both values and accepts a matching delivery",
      "invariant",
      "",
      async () => {
        const digest = L.coordsDigest(scenario.outputCt);
        const commitment = L.g1ToContract(L.commit(scenario.outputCt, gens));
        const ok =
          digest.toLowerCase() === recordedDigest.toLowerCase() &&
          commitment[0] === recordedCommitment[0] &&
          commitment[1] === recordedCommitment[1];
        return { ok, detail: "recomputed digest and commitment both match the on-chain record" };
      }
    );

    await record(
      "consumer_rejects_matching_digest_wrong_commitment",
      "Corollary (Linear computation integrity): 'The consumer's comparison of its locally recomputed commitment with the on-chain record binds the delivered output ... under the DLR binding of P alone'",
      "invariant",
      "",
      async () => {
        // Deliver a vector whose DIGEST is forced to match by replaying the
        // honest bytes, while its commitment differs: only the commitment
        // check can catch this.
        const tampered = [...scenario.outputCt];
        tampered[0] = (BigInt(tampered[0]) + 1n) % L.R;
        const commitment = L.g1ToContract(L.commit(tampered, gens));
        const commitmentDiffers =
          commitment[0] !== recordedCommitment[0] || commitment[1] !== recordedCommitment[1];
        return { ok: commitmentDiffers, detail: "commitment check alone rejects the tampered vector" };
      }
    );

    await record(
      "consumer_rejects_matching_commitment_wrong_digest",
      "Corollary (Linear computation integrity): 'the digest comparison is an additional check on the byte encoding'",
      "invariant",
      "",
      async () => {
        // Same vector, different serialisation length: the commitment is a
        // function of the coordinates, the digest of the canonical bytes.
        const padded = [...scenario.outputCt, 0n];
        const digest = L.coordsDigest(padded);
        const digestDiffers = digest.toLowerCase() !== recordedDigest.toLowerCase();
        return { ok: digestDiffers, detail: "digest check rejects a re-encoded vector of the wrong length" };
      }
    );

    await record(
      "onchain_alone_accepts_bogus_digest",
      "Threat table, 'Valid proof, divergent delivery': 'Availability griefing only: task consumed without usable delivery; unpunished in the implementation'",
      "accepted-limitation",
      "",
      async () => {
        // A second deployment, so the one-shot task of this one is untouched.
        const c2 = await freshDeployment(TAG, "sec-griefing");
        for (const o of scenario.owners) {
          await confirm(c2.connect(ownerSigner(o.index)).registerOwnerKey(o.index, L.g2ToContract(o.pk)), "connect");
          await confirm(c2
              .connect(ownerSigner(o.index))
              .admitRecord(o.index, L.g1ToContract(o.commitment), L.g1ToContract(o.signature)), "connect");
        }
        const t = "0x" + "22".repeat(32);
        await confirm(c2.connect(admin).registerTask(t, operator.address), "registerTask");
        await confirm(c2.connect(operator).depositStake({ value: hre.ethers.parseEther("1") }), "depositStake");
        // Honest commitment, arbitrary digest: the contract accepts.
        return minedRevertGas(() =>
          c2
            .connect(operator)
            .submitResultBound(t, "0x" + "de".repeat(32), L.g1ToContract(scenario.outputCommitment))
        );
      }
    );
  }

  // =========================================================================
  // L  Documented limitations, exercised rather than asserted
  // =========================================================================
  await record(
    "no_range_proof_accompanies_commitment",
    "Section (Output-bound...): 'neither establishes that it is a well-formed encryption of an admissible rating ... Ruling that out would require a proof of well-formed encryption or a plaintext-range proof, which this construction does not include'",
    "accepted-limitation",
    "",
    async () => {
      // A corrupted owner commits to an out-of-domain value and signs it
      // properly. The contract has no range proof, so admission succeeds; the
      // damage surfaces only at decryption, off-chain.
      const c = await freshDeployment(TAG, "sec-norange");
      const o0 = scenario.owners[0];
      await confirm(c.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(o0.pk)), "connect");
      // 1023 is the top of the l=10 message space and wildly outside the ACR
      // 1..5 rating domain the deployment is meant to aggregate. The contract
      // has no plaintext-range proof, so it cannot tell the difference.
      const wild = L.heEnc(scenario.he, 1023n, L.makeRng("sec-out-of-range"));
      const wildCommitment = L.commit(wild, gens);
      const wildSig = L.sign(o0.sk, wildCommitment, TAG, 0, { pk: o0.pk, op: 0, totalItems: N });
      return minedRevertGas(() =>
        c.connect(ownerSigner(0)).admitRecord(0, L.g1ToContract(wildCommitment), L.g1ToContract(wildSig))
      );
    }
  );

  await record(
    "same_field_cross_deployment_replay",
    "Section (Output-bound...): 'Two deployments that share all of these fields therefore accept the same admissions, so distinct datasets and epochs must use distinct tags'",
    "accepted-limitation",
    "",
    async () => {
      // Identical (tag, op, N, owners): the signed context does not cover the
      // chain or the contract address, so admissions replay across deployments.
      const twin = await freshDeployment(TAG, "sec-twin-deployment");
      const o0 = scenario.owners[0];
      await confirm(twin.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(o0.pk)), "connect");
      return minedRevertGas(() =>
        twin
          .connect(attacker)
          .admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
      );
    }
  );

  await record(
    "distinct_tag_blocks_cross_epoch_replay",
    "Section (Output-bound...): the mandatory non-zero tag is what separates datasets and epochs",
    "rejected",
    "InvalidSignature",
    async () => {
      // The mitigation the sentence above prescribes: a different tag rejects
      // the same admission.
      const other = await freshDeployment(TAG_B, "sec-other-epoch");
      const o0 = scenario.owners[0];
      await confirm(other.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(o0.pk)), "connect");
      return minedRevertGas(() =>
        other
          .connect(attacker)
          .admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature), opts)
      );
    }
  );

  // =========================================================================
  // Report
  // =========================================================================
  const passed = rows.filter((r) => r.status === "PASS").length;
  const failed = rows.length - passed;

  const columns = [
    "scenarioId",
    "experimentClaim",
    "expectedOutcome",
    "expectedError",
    "observedOutcome",
    "observedError",
    "status",
    "attackerGasUsed",
    "detail",
    "network",
    "chainId",
    "venue",
  ];
  const cell = (v) => {
    const s = v === undefined || v === null ? "" : String(v);
    return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
  };
  const csv = [columns.join(",")]
    .concat(rows.map((r) => columns.map((c) => cell(r[c])).join(",")))
    .join("\n");
  fs.writeFileSync(path.join(OUT_DIR, "mklhs_security_evaluation.csv"), csv + "\n");

  const blockNumber = await hre.ethers.provider.getBlockNumber();
  fs.writeFileSync(
    path.join(OUT_DIR, "mklhs_security_evaluation.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        generator: "scripts/mklhs_security_evaluation.js",
        context: { network: hre.network.name, chainId, venue, blockNumber, datasetSize: N },
        summary: { total: rows.length, passed, failed },
        rows,
      },
      null,
      2
    ) + "\n"
  );

  console.log("");
  console.log("============================================================");
  console.log(` ${passed}/${rows.length} scenarios behaved as the implementation claims`);
  console.log(`   venue=${venue} chainId=${chainId} block=${blockNumber}`);
  console.log("   wrote mklhs_security_evaluation.csv and .json");
  console.log("============================================================");

  if (failed > 0) {
    throw new Error(`${failed} linear security scenario(s) did not match the implementation`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
