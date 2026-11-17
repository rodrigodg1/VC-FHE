/**
 * Adversarial battery for the MKLHS (per-owner keys, no curator) linear path.
 *
 * Complements test/mklhs.test.js by exercising the CURATOR-FREE adversary
 * model end-to-end, one scenario per contract-layer capability of
 * Definition 1 (static corruption, no curator exclusion):
 *
 *   Enrollment/key layer
 *     A1  index out of range on key registration
 *     A2  key duplication: registering ANOTHER owner's public key yields no
 *         forgery capability (per-record verification + hashed (tag,i) label;
 *         rogue-key style aggregation attacks do not apply because keys are
 *         never aggregated)
 *     A3  G2 point ON the twist curve but OUTSIDE the r-order subgroup is
 *         rejected (EIP-197 subgroup check surfaced as InvalidPublicKey)
 *     A4  G2 coordinates not on the curve are rejected
 *     A5  key misregistration is self-harm only: the misregistered index
 *         cannot admit, other owners are unaffected
 *
 *   Admission layer
 *     B1  index out of range / admission before key registration
 *     B2  relayer/front-runner submission of an HONEST record is harmless
 *         (authenticity from the signature, not msg.sender)
 *     B3  signature mauling (sigma + G, -sigma) is rejected
 *     B4  same-tag cross-deployment replay IS accepted: documents the
 *         residual that sigma_i binds (tag, i) but NOT the deployment or its
 *         authorized operation; tag uniqueness per deployment is a
 *         governance requirement (see experiment, Sec. multi-key trade-offs)
 *     B5  a corrupted owner degrades only its own index: the fabricated
 *         record is admitted (it is validly signed by its owner), the honest
 *         aggregate no longer verifies, and the aggregate including the
 *         fabricated record verifies (plaintext fabrication is out of scope
 *         by Definition 1)
 *     B6  scalar-derived admission is REJECTED: the message point is
 *         M_i = H2C(context || P_i), so a scaled signature is not valid for a
 *         scaled commitment
 *     B7  cross-index combination under one key is REJECTED
 *     B10 two signatures for the same (tag, index) cannot be blended into a
 *         valid third record. Without context binding an affine blend with
 *         alpha + beta = 1 produced a commitment the attacker could open,
 *         which broke integrity, not just liveness
 *     B8  off-curve G1 points (commitment and signature) are rejected: the
 *         canonical check only bounds coordinates, so curve membership is
 *         enforced by the EVM precompiles that the proof assumes
 *     B9  the SUB deployment (negation branch) behaves as the SUM one under
 *         a derived admission
 *     C4  finalization gates: stake requirement, operator binding, and the
 *         one-shot task (a second submission for the same task reverts)
 *     B7  cross-index span: when one key is enrolled at two indices, a
 *         combination a*M_i + b*M_j of the points signed under that key is
 *         admissible at index i. The accumulator again carries unopenable
 *         label terms, so no output is accepted. This is why the experiment
 *         states the span over the points signed under the key registered
 *         for the index, not only those signed for that index
 *
 *   Finalization layer
 *     C1  submitResultBound (not just verifyBound) reverts while any record
 *         is missing (aggregator omission/censorship is impossible)
 *     C2  task assignment is admin-only
 *     C3  accumulator cancellation edge (P_agg = point at infinity) fails
 *         closed: no output commitment can be accepted
 *
 *   Off-chain certificate
 *     D1  the Aranha--Pagnin aggregate certificate rejects swapped owner
 *         keys and wrong weights
 *
 * Run: npx hardhat test test/mklhs-adversarial.test.js
 */
"use strict";

const { expect } = require("chai");
const hre = require("hardhat");
const { bn254 } = require("@noble/curves/bn254");
const L = require("../scripts/mklhs-lib.js");
const { sendGroupedBySigner } = require("../scripts/tx-batch.js");

const TAG = "0x" + "c1".repeat(32);
const N = 10;

const Fp2 = bn254.fields.Fp2;
const G2 = bn254.G2.ProjectivePoint;

/** [r]P without the multiply() torsion precondition. */
function mulByGroupOrder(point) {
  return point.multiplyUnsafe(L.R - 1n).add(point);
}

/**
 * Deterministically find a point on the G2 twist curve that is NOT in the
 * r-order subgroup (cofactor h2 >> 1, so low-x candidates suffice).
 */
function nonSubgroupG2() {
  const base = G2.BASE.toAffine();
  const b2 = Fp2.sub(Fp2.sqr(base.y), Fp2.mul(Fp2.sqr(base.x), base.x));
  for (let k = 1n; k < 256n; k++) {
    const x = { c0: k, c1: 1n };
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2);
    let y;
    try {
      y = Fp2.sqrt(rhs);
    } catch (_) {
      continue;
    }
    // On-curve by construction; keep only non-subgroup candidates.
    const P = G2.fromAffine({ x, y });
    if (!mulByGroupOrder(P).equals(G2.ZERO)) {
      return [x.c0, x.c1, y.c0, y.c1]; // contract layout [x0, x1, y0, y1]
    }
  }
  throw new Error("no non-subgroup G2 point found (unexpected)");
}

describe("MKLHSVerification adversarial battery (curator-free model)", function () {
  // Every setup transaction below is confirmed (mined) before the attack that
  // depends on it; on a real network (2 s blocks) that costs one block per
  // transaction, well beyond Mocha's 40 s default.
  this.timeout(600000);

  let signers;
  let deployer;
  let operator;
  let attacker;

  before(async function () {
    signers = await hre.ethers.getSigners();
    deployer = signers[0];
    operator = signers[1];
    attacker = signers[12 + N] || signers[signers.length - 1];
  });

  function ownerSigner(i) {
    return signers[2 + i];
  }

  async function deploy({ op = 0, tag = TAG, n = N } = {}) {
    const ownerAddrs = Array.from({ length: n }, (_, i) => ownerSigner(i).address);
    const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
    const contract = await Factory.deploy(
      "adversarial-dataset",
      1,
      n,
      op,
      tag,
      ownerAddrs,
      { value: hre.ethers.parseEther("1") }
    );
    await contract.waitForDeployment();
    return contract;
  }

  // Setup transactions must be CONFIRMED before the attack that depends on
  // them is submitted. On an auto-mining in-process EVM `await tx` suffices;
  // on a real network (2 s blocks) it only awaits submission, so an attack
  // could otherwise race ahead of the state it is meant to violate.
  async function registerAllKeys(contract, scenario) {
    // Batched by sending account: distinct owners have independent nonce
    // spaces, so the round trips overlap on a real chain without racing.
    await sendGroupedBySigner(
      scenario.owners,
      (o) => ownerSigner(o.index),
      (o) => contract.connect(ownerSigner(o.index)).registerOwnerKey(o.index, L.g2ToContract(o.pk))
    );
  }

  async function admitAll(contract, scenario, { skip = [] } = {}) {
    // Admissions commute, so batching by sending account cannot change P_agg;
    // `skip` still removes an index entirely, which is what the omission and
    // corrupted-owner scenarios rely on.
    const pending = scenario.owners.filter((o) => !skip.includes(o.index));
    await sendGroupedBySigner(
      pending,
      (o) => ownerSigner(o.index),
      (o) =>
        contract
          .connect(ownerSigner(o.index))
          .admitRecord(o.index, L.g1ToContract(o.commitment), L.g1ToContract(o.signature))
    );
  }

  function taskId(contract, label) {
    return hre.ethers.keccak256(
      hre.ethers.solidityPacked(["address", "string"], [contract.target, label])
    );
  }

  // === Enrollment / key layer ===============================================

  it("A1: rejects key registration for an out-of-range index", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "a1" });
    const contract = await deploy();
    await expect(
      contract
        .connect(ownerSigner(0))
        .registerOwnerKey(N, L.g2ToContract(scenario.owners[0].pk))
    ).to.be.revertedWithCustomError(contract, "InvalidIndex");
  });

  it("A2: duplicating another owner's public key yields no forgery capability", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "a2" });
    const contract = await deploy();
    const o0 = scenario.owners[0];
    const o1 = scenario.owners[1];

    // Owner 1 (acting maliciously) registers owner 0's public key for index 1.
    await (
      await contract.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(o0.pk))
    ).wait();
    await (
      await contract.connect(ownerSigner(1)).registerOwnerKey(1, L.g2ToContract(o0.pk))
    ).wait();

    // Owner 0's signature admits index 0 as usual ...
    await (
      await contract.admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
    ).wait();

    // ... but cannot be replayed at index 1 (H(tag,1) != H(tag,0)) ...
    await expect(
      contract.admitRecord(1, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");

    // ... and owner 1 cannot sign under the copied key (it lacks sk_0).
    const attempt = L.sign(o1.sk, o1.commitment, TAG, 1, { pk: o1.pk, op: 0, totalItems: N });
    await expect(
      contract.admitRecord(1, L.g1ToContract(o1.commitment), L.g1ToContract(attempt))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("A3: rejects a G2 key on the twist curve but outside the r-order subgroup", async function () {
    const contract = await deploy();
    const badKey = nonSubgroupG2();
    await expect(
      contract.connect(ownerSigner(0)).registerOwnerKey(0, badKey)
    ).to.be.revertedWithCustomError(contract, "InvalidPublicKey");
  });

  it("A4: rejects G2 coordinates that are not on the curve", async function () {
    const contract = await deploy();
    await expect(
      contract.connect(ownerSigner(0)).registerOwnerKey(0, [1n, 2n, 3n, 4n])
    ).to.be.revertedWithCustomError(contract, "InvalidPublicKey");
  });

  it("A5: key misregistration harms only the misregistering owner", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "a5" });
    const contract = await deploy();
    const o0 = scenario.owners[0];
    const o1 = scenario.owners[1];

    // Owner 0 registers a key that does not match its signing key.
    const foreign = L.keygen(L.makeRng("a5-foreign"));
    await (
      await contract.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(foreign.pk))
    ).wait();
    await (
      await contract.connect(ownerSigner(1)).registerOwnerKey(1, L.g2ToContract(o1.pk))
    ).wait();

    // Its own honest signature is now rejected (self-harm, no key rotation).
    await expect(
      contract.admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");

    // Other owners are unaffected.
    await (
      await contract.admitRecord(1, L.g1ToContract(o1.commitment), L.g1ToContract(o1.signature))
    ).wait();
    expect(await contract.admitted(1)).to.equal(true);
  });

  // === Admission layer ======================================================

  it("B1: rejects out-of-range and key-less admissions", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b1" });
    const contract = await deploy();
    const o0 = scenario.owners[0];

    await expect(
      contract.admitRecord(N, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
    ).to.be.revertedWithCustomError(contract, "InvalidIndex");

    await expect(
      contract.admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
    ).to.be.revertedWithCustomError(contract, "KeyNotRegistered");
  });

  it("B2: relayer submission of an honest record is harmless and the flow completes", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b2" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    const o0 = scenario.owners[0];

    // A third party (front-runner/relayer) submits owner 0's honest record.
    await (
      await contract
        .connect(attacker)
        .admitRecord(0, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
    ).wait();
    const stored = await contract.getAdmittedCommitment(0);
    const expected = L.g1ToContract(o0.commitment);
    expect(stored[0]).to.equal(expected[0]);
    expect(stored[1]).to.equal(expected[1]);

    // The remaining owners admit and the honest result still verifies.
    await admitAll(contract, scenario, { skip: [0] });
    expect(
      await contract.verifyBound(L.g1ToContract(scenario.outputCommitment))
    ).to.equal(true);
  });

  it("B3: rejects mauled signatures (sigma + G, -sigma)", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b3" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    const o0 = scenario.owners[0];

    await expect(
      contract.admitRecord(
        0,
        L.g1ToContract(o0.commitment),
        L.g1ToContract(o0.signature.add(L.G1.BASE))
      )
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");

    await expect(
      contract.admitRecord(
        0,
        L.g1ToContract(o0.commitment),
        L.g1ToContract(o0.signature.negate())
      )
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("B4: documents same-tag cross-deployment replay (tag uniqueness is a governance requirement)", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b4" });

    // Deployment A: SUM, the deployment the owners intended to sign for.
    const sumContract = await deploy({ op: 0 });
    await registerAllKeys(sumContract, scenario);
    await admitAll(sumContract, scenario);
    expect(
      await sumContract.verifyBound(L.g1ToContract(scenario.outputCommitment))
    ).to.equal(true);

    // Deployment B: a SECOND SUM deployment with the SAME tag, operation, size
    // and enrollment. The signed context covers (pk, tag, i, op, N) but not the
    // chain or the contract address, so every admission replays here.
    const twinContract = await deploy({ op: 0 });
    await registerAllKeys(twinContract, scenario);
    await admitAll(twinContract, scenario);
    expect(
      await twinContract.verifyBound(L.g1ToContract(scenario.outputCommitment))
    ).to.equal(true);

    // Deployment C: SUB, same tag and enrollment. The authorized operation is
    // inside the signed context, so the SUM signatures do NOT replay here.
    const subContract = await deploy({ op: 1 });
    await registerAllKeys(subContract, scenario);
    const victim = scenario.owners[0];
    await expect(
      subContract.admitRecord(
        0,
        L.g1ToContract(victim.commitment),
        L.g1ToContract(victim.signature)
      )
    ).to.be.revertedWithCustomError(subContract, "InvalidSignature");

    // Consequence documented in the experiment's multi-key trade-offs: two
    // deployments sharing tag, operation and size accept the same admissions,
    // so distinct datasets and epochs MUST use distinct tags (cross-tag test in
    // mklhs.test.js). Binding the chain and contract address is not possible
    // for records emitted offline before deployment.
  });

  it("B5: a corrupted owner degrades only its own index", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b5" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);

    // Owner 3 fabricates a different record and validly signs it.
    const corrupt = scenario.owners[3];
    const fabricatedCt = L.heEnc(scenario.he, 999n, L.makeRng("b5-fab"));
    const fabricatedCommitment = L.commit(fabricatedCt, scenario.gens);
    const fabricatedSig = L.sign(corrupt.sk, fabricatedCommitment, TAG, 3, { pk: corrupt.pk, op: 0, totalItems: N });

    await (
      await contract.admitRecord(
        3,
        L.g1ToContract(fabricatedCommitment),
        L.g1ToContract(fabricatedSig)
      )
    ).wait();
    await admitAll(contract, scenario, { skip: [3] });

    // The honest aggregate no longer verifies (the fabricated record is in
    // the accumulator) ...
    expect(
      await contract.verifyBound(L.g1ToContract(scenario.outputCommitment))
    ).to.equal(false);

    // ... and the aggregate that includes the fabricated vector verifies:
    // integrity holds over ADMITTED records; plaintext fabrication for the
    // owner's own index is out of scope (Definition 1) and confined to it.
    const cts = scenario.owners.map((o) => (o.index === 3 ? fabricatedCt : o.ct));
    const actualOutput = L.heCombine(cts, scenario.weights);
    expect(
      await contract.verifyBound(L.g1ToContract(L.commit(actualOutput, scenario.gens)))
    ).to.equal(true);

    // Decryption confirms the degradation is exactly owner 3's delta.
    // Both values are real decryptions, so they live in the l-bit message
    // space; the difference must be taken there, not in F_r.
    const honest = scenario.expectedPlain;
    const degraded = L.heDec(scenario.he, actualOutput);
    expect(L.mod(degraded - honest, L.MSG_SPACE)).to.equal(
      L.mod(999n - corrupt.m, L.MSG_SPACE)
    );
  });

  // === Finalization layer ===================================================

  it("B6: scalar-derived admission is rejected (the signature binds the commitment)", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b6" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);

    // Under the context-bound message point M_i = H2C(ctx || P_i), scaling a
    // signature no longer yields a valid pair for a scaled commitment: the
    // hash output is not linear in P_i.
    const victim = scenario.owners[2];
    const a = 7n;
    await expect(
      contract
        .connect(attacker)
        .admitRecord(
          2,
          L.g1ToContract(victim.commitment.multiply(a)),
          L.g1ToContract(victim.signature.multiply(a))
        )
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");

    // The honest record for the same index is unaffected.
    await (
      await contract
        .connect(attacker)
        .admitRecord(2, L.g1ToContract(victim.commitment), L.g1ToContract(victim.signature))
    ).wait();
    expect(await contract.admitted(2)).to.equal(true);
  });

  it("B7: cross-index combination under one key is rejected", async function () {
    // Indices 0 and 1 are enrolled to the SAME address with the SAME key, so
    // the attacker holds two signatures under that key. With context binding,
    // no combination of them is valid for any commitment it can open.
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b7" });
    // Index 1 is enrolled to the address that already owns index 0; every other
    // index keeps its own address, so the array length still matches N.
    const ownerAddrs = Array.from({ length: N }, (_, i) =>
      i === 1 ? ownerSigner(0).address : ownerSigner(i).address
    );
    const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
    const contract = await Factory.deploy("adversarial-dataset", 1, N, 0, TAG, ownerAddrs, {
      value: hre.ethers.parseEther("1"),
    });
    await contract.waitForDeployment();

    const sk = scenario.owners[0].sk;
    const pk = scenario.owners[0].pk;
    await (await contract.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(pk))).wait();
    await (await contract.connect(ownerSigner(0)).registerOwnerKey(1, L.g2ToContract(pk))).wait();

    const gens = L.commitGenerators();
    const P0 = L.commit(scenario.owners[0].ct, gens);
    const P1 = L.commit(scenario.owners[1].ct, gens);
    const s0 = L.sign(sk, P0, TAG, 0, { pk, op: 0, totalItems: N });
    const s1 = L.sign(sk, P1, TAG, 1, { pk, op: 0, totalItems: N });

    const a = 3n;
    const b = 5n;
    await expect(
      contract
        .connect(attacker)
        .admitRecord(
          0,
          L.g1ToContract(P0.multiply(a).add(P1.multiply(b))),
          L.g1ToContract(s0.multiply(a).add(s1.multiply(b)))
        )
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("B10: two signatures for the same label cannot be blended into a third record", async function () {
    // The critical case: if an owner ever signs two commitments for the same
    // (tag, index), an affine blend with alpha + beta = 1 used to produce a
    // valid signature for a commitment the attacker could open, which broke
    // integrity. Context binding removes it.
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b10" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);

    const gens = L.commitGenerators();
    const owner = scenario.owners[2];
    const ctB = owner.ct.map((x, d) => (x + BigInt(d + 1) * 7n) % L.R);
    const PB = L.commit(ctB, gens);
    const sigB = L.sign(owner.sk, PB, TAG, 2, { pk: owner.pk, op: 0, totalItems: N });

    const alpha = 2n;
    const beta = (L.R - 1n) % L.R; // alpha + beta = 1, so the blend stays in-regime
    const blendCt = owner.ct.map((x, d) => (((alpha * x + beta * ctB[d]) % L.R) + L.R) % L.R);

    await expect(
      contract
        .connect(attacker)
        .admitRecord(
          2,
          L.g1ToContract(L.commit(blendCt, gens)),
          L.g1ToContract(owner.signature.multiply(alpha).add(sigB.multiply(beta)))
        )
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("B8: off-curve G1 commitment and signature are rejected", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "b8" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);

    // (1, 1) is inside the base field but not on y^2 = x^3 + 3. The canonical
    // check only bounds the coordinates; curve membership is enforced by the
    // bn256 add and pairing precompiles.
    const offCurve = [1n, 1n];
    await expect(
      contract
        .connect(attacker)
        .admitRecord(0, offCurve, L.g1ToContract(scenario.owners[0].signature))
    ).to.be.reverted;
    await expect(
      contract
        .connect(attacker)
        .admitRecord(0, L.g1ToContract(scenario.owners[0].commitment), offCurve)
    ).to.be.reverted;
  });

  it("B9: the SUB deployment rejects the derived admission of the additive scheme", async function () {
    const scenario = L.buildScenario({ n: N, op: 1, tagHex: TAG, seed: "b9" });
    const contract = await deploy({ op: 1 });
    await registerAllKeys(contract, scenario);

    // Under the earlier additive-label scheme sigma = sk (P(c) + H(tag,i)), the
    // pair below verified for a commitment the owner never signed. With the
    // commitment inside the hash preimage, the derived pair is a forgery.
    const victim = scenario.owners[2];
    const label = L.indexPoint(TAG, 2);
    const a = 9n;
    await expect(
      contract
        .connect(attacker)
        .admitRecord(
          2,
          L.g1ToContract(victim.commitment.add(label).multiply(a).subtract(label)),
          L.g1ToContract(victim.signature.multiply(a))
        )
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");

    // The honest admissions still complete and bind the authorized aggregate.
    await admitAll(contract, scenario);
    expect(await contract.verifyBound(L.g1ToContract(scenario.outputCommitment))).to.equal(true);
  });

  it("C4: stake, operator binding and the one-shot task are enforced", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "c4" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    await admitAll(contract, scenario);

    const task = taskId(contract, "c4");
    await (await contract.registerTask(task, operator.address)).wait();

    // no stake yet
    await expect(
      contract
        .connect(operator)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).to.be.reverted;

    await (
      await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })
    ).wait();
    await (
      await contract.connect(attacker).depositStake({ value: hre.ethers.parseEther("1") })
    ).wait();

    // staked, but not the assigned operator
    await expect(
      contract
        .connect(attacker)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).to.be.revertedWithCustomError(contract, "Unauthorized");

    await (
      await contract
        .connect(operator)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).wait();

    // one-shot: the same task cannot be submitted twice
    await expect(
      contract
        .connect(operator)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).to.be.revertedWithCustomError(contract, "TaskAlreadyConsumed");
  });

  it("C1: submitResultBound reverts while any record is missing", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "c1" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    await admitAll(contract, scenario, { skip: [N - 1] });

    const task = taskId(contract, "c1");
    await (await contract.registerTask(task, operator.address)).wait();
    await (
      await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })
    ).wait();
    await expect(
      contract
        .connect(operator)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).to.be.revertedWithCustomError(contract, "IncompleteAdmission");
  });

  it("C2: task assignment is admin-only", async function () {
    const contract = await deploy();
    await expect(
      contract.connect(attacker).registerTask(taskId(contract, "c2"), attacker.address)
    ).to.be.revertedWithCustomError(contract, "Unauthorized");
  });

  it("C3: accumulator cancellation (P_agg at infinity) fails closed", async function () {
    // SUB with two owners admitting the SAME ciphertext: P_agg = P(c) - P(c) = O.
    const n = 2;
    const rng = L.makeRng("c3");
    const gens = L.commitGenerators();
    const he = L.heKeygen(rng);
    const ct = L.heEnc(he, 5n, rng);
    const commitment = L.commit(ct, gens);

    const owners = [L.keygen(rng), L.keygen(rng)];
    const contract = await deploy({ op: 1, n });
    for (let i = 0; i < n; i++) {
      await (
        await contract.connect(ownerSigner(i)).registerOwnerKey(i, L.g2ToContract(owners[i].pk))
      ).wait();
      await (
        await contract
          .connect(ownerSigner(i))
          .admitRecord(
            i,
            L.g1ToContract(commitment),
            L.g1ToContract(L.sign(owners[i].sk, commitment, TAG, i, { pk: owners[i].pk, op: 1, totalItems: n }))
          )
      ).wait();
    }

    expect(await contract.admittedCount()).to.equal(n);
    // The point at infinity is not a submittable commitment ...
    await expect(contract.verifyBound([0n, 0n])).to.be.revertedWithCustomError(
      contract,
      "InvalidG1Point"
    );
    // ... and no canonical point matches the infinity accumulator.
    expect(await contract.verifyBound(L.g1ToContract(L.G1.BASE))).to.equal(false);
  });

  // === Off-chain certificate ================================================

  it("D1: the aggregate certificate rejects swapped keys and wrong weights", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "d1" });
    const sigma = L.aggregate(
      scenario.owners.map((o) => o.signature),
      scenario.weights
    );
    const commitments = scenario.owners.map((o) => o.commitment);
    const pubkeys = scenario.owners.map((o) => o.pk);

    expect(L.verifyAggregate(sigma, commitments, pubkeys, TAG, scenario.weights, 0)).to.equal(true);

    const swapped = pubkeys.slice();
    [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    expect(L.verifyAggregate(sigma, commitments, swapped, TAG, scenario.weights, 0)).to.equal(false);

    const wrongWeights = L.weightsFor(1, N); // SUB weights against a SUM certificate
    expect(
      L.verifyAggregate(sigma, commitments, pubkeys, TAG, wrongWeights, 0)
    ).to.equal(false);
  });
});
