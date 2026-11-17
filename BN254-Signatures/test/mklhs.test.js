const { expect } = require("chai");
const hre = require("hardhat");
const L = require("../scripts/mklhs-lib.js");
const { sendGroupedBySigner } = require("../scripts/tx-batch.js");

const TAG = "0x" + "c1".repeat(32);
const N = 10;

describe("MKLHSVerification (per-owner keys, no curator)", function () {
  // Every setup transaction below is confirmed (mined) before the assertion
  // that depends on it; on a real network (2 s blocks) that costs one block
  // per transaction, well beyond Mocha's 40 s default.
  this.timeout(600000);

  let signers;
  let deployer;
  let operator;

  before(async function () {
    signers = await hre.ethers.getSigners();
    deployer = signers[0];
    operator = signers[1];
  });

  function ownerSigner(i) {
    // signers[2..] play the N data owners
    return signers[2 + i];
  }

  async function deploy({ op = 0, tag = TAG, n = N } = {}) {
    const ownerAddrs = Array.from({ length: n }, (_, i) =>
      ownerSigner(i).address
    );
    const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
    const contract = await Factory.deploy(
      "test-dataset",
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

  // Setup transactions must be CONFIRMED before anything that depends on them
  // is submitted. On an auto-mining in-process EVM `await tx` suffices; on a
  // real network (2 s blocks) it only awaits submission, so a dependent call
  // would race ahead of the state it needs.
  async function registerAllKeys(contract, scenario) {
    // Batched by sending account: distinct owners have independent nonce
    // spaces, so the round trips overlap on a real chain without racing.
    await sendGroupedBySigner(
      scenario.owners,
      (o) => ownerSigner(o.index),
      (o) => contract.connect(ownerSigner(o.index)).registerOwnerKey(o.index, L.g2ToContract(o.pk))
    );
  }

  async function admitAll(contract, scenario) {
    // Admissions commute: the contract folds each commitment into the
    // accumulator by point addition, so batching cannot change P_agg.
    await sendGroupedBySigner(
      scenario.owners,
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

  it("runs the honest end-to-end flow (SUM): register, admit, submit, consumer check", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "e2e-sum" });
    const contract = await deploy({ op: 0 });
    await registerAllKeys(contract, scenario);
    await admitAll(contract, scenario);

    expect(await contract.admittedCount()).to.equal(N);
    expect(await contract.verifyBound(L.g1ToContract(scenario.outputCommitment))).to.equal(true);

    const task = taskId(contract, "honest");
    await (await contract.registerTask(task, operator.address)).wait();
    await expect(
      contract
        .connect(operator)
        .submitResultBound(
          task,
          scenario.outputDigest,
          L.g1ToContract(scenario.outputCommitment)
        )
    ).to.be.revertedWith("Insufficient Stake");

    await (
      await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })
    ).wait();
    // `.to.emit` reads the receipt without waiting for a block, which fails on
    // real networks (2 s blocks); wait for the receipt and check its logs.
    const submitReceipt = await (
      await contract
        .connect(operator)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).wait();
    expect(
      submitReceipt.logs.some(
        (log) =>
          log.address.toLowerCase() === String(contract.target).toLowerCase() &&
          log.topics[0] === contract.interface.getEvent("ResultBound").topicHash
      )
    ).to.equal(true);

    // Consumer check: recompute digest and commitment from the delivered artifact.
    const stored = await contract.getBoundResult(task);
    expect(stored.outputDigest).to.equal(L.coordsDigest(scenario.outputCt));
    const recomputed = L.g1ToContract(L.commit(scenario.outputCt, scenario.gens));
    expect(stored.outputCommitment[0]).to.equal(recomputed[0]);
    expect(stored.outputCommitment[1]).to.equal(recomputed[1]);
    // Decryption sanity (leveled stand-in).
    expect(L.heDec(scenario.he, scenario.outputCt)).to.equal(scenario.expectedPlain);
  });

  it("runs the honest end-to-end flow (SUB)", async function () {
    const scenario = L.buildScenario({ n: N, op: 1, tagHex: TAG, seed: "e2e-sub" });
    const contract = await deploy({ op: 1 });
    await registerAllKeys(contract, scenario);
    await admitAll(contract, scenario);
    expect(await contract.verifyBound(L.g1ToContract(scenario.outputCommitment))).to.equal(true);
  });

  it("rejects key registration from a non-enrolled address and double registration", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "keys" });
    const contract = await deploy();
    const o0 = scenario.owners[0];

    await expect(
      contract.connect(operator).registerOwnerKey(0, L.g2ToContract(o0.pk))
    ).to.be.revertedWithCustomError(contract, "NotEnrolled");

    await (
      await contract.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(o0.pk))
    ).wait();
    await expect(
      contract.connect(ownerSigner(0)).registerOwnerKey(0, L.g2ToContract(o0.pk))
    ).to.be.revertedWithCustomError(contract, "KeyAlreadyRegistered");
  });

  it("rejects admission with a forged signature (wrong secret key)", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "forge" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    const o = scenario.owners[0];
    const rng = L.makeRng("forger");
    const forged = L.sign(
      L.keygen(rng).sk, // attacker key, not the registered one
      o.commitment,
      TAG,
      0,
      { pk: o.pk, op: 0, totalItems: N }
    );
    await expect(
      contract.admitRecord(0, L.g1ToContract(o.commitment), L.g1ToContract(forged))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("rejects curator-style substitution: valid signature over a DIFFERENT commitment", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "subst" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    const o = scenario.owners[0];
    // Substituted record: commitment of another ciphertext, signature of the honest one.
    const other = L.commit(
      L.heEnc(scenario.he, 999n, L.makeRng("other")),
      scenario.gens
    );
    await expect(
      contract.admitRecord(0, L.g1ToContract(other), L.g1ToContract(o.signature))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("rejects cross-index and cross-tag replay of a valid signature", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "replay" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    const o0 = scenario.owners[0];
    const o1 = scenario.owners[1];

    // Signature of owner 0 presented at index 1 (owner 1's slot).
    await expect(
      contract.admitRecord(1, L.g1ToContract(o0.commitment), L.g1ToContract(o0.signature))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");

    // Signature produced under a different dataset tag.
    const otherTag = "0x" + "d2".repeat(32);
    const crossTag = L.sign(o1.sk, o1.commitment, otherTag, 1, { pk: o1.pk, op: 0, totalItems: N });
    await expect(
      contract.admitRecord(1, L.g1ToContract(o1.commitment), L.g1ToContract(crossTag))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("rejects double admission of the same index", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "double" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    const o = scenario.owners[0];
    await (
      await contract.admitRecord(0, L.g1ToContract(o.commitment), L.g1ToContract(o.signature))
    ).wait();
    await expect(
      contract.admitRecord(0, L.g1ToContract(o.commitment), L.g1ToContract(o.signature))
    ).to.be.revertedWithCustomError(contract, "AlreadyAdmitted");
  });

  it("rejects non-canonical points and the point at infinity", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "canon" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    const o = scenario.owners[0];
    const c = L.g1ToContract(o.commitment);

    await expect(
      contract.admitRecord(0, c, [0n, 0n])
    ).to.be.revertedWithCustomError(contract, "InvalidG1Point");
    await expect(
      contract.admitRecord(0, c, [0n, L.Q])
    ).to.be.revertedWithCustomError(contract, "InvalidG1Point");
    await expect(
      contract.admitRecord(0, [0n, 0n], L.g1ToContract(o.signature))
    ).to.be.revertedWithCustomError(contract, "InvalidG1Point");
  });

  it("refuses result submission before every record is admitted (no omission)", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "partial" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    // Admit all but the last record.
    for (const o of scenario.owners.slice(0, N - 1)) {
      await (
        await contract.admitRecord(
          o.index,
          L.g1ToContract(o.commitment),
          L.g1ToContract(o.signature)
        )
      ).wait();
    }
    await expect(
      contract.verifyBound(L.g1ToContract(scenario.outputCommitment))
    ).to.be.revertedWithCustomError(contract, "IncompleteAdmission");
  });

  it("rejects an output commitment that deviates from the accumulator", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "deviate" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    await admitAll(contract, scenario);

    const mutated = L.g1ToContract(scenario.outputCommitment.add(L.G1.BASE));
    expect(await contract.verifyBound(mutated)).to.equal(false);

    const task = taskId(contract, "deviate");
    await (await contract.registerTask(task, operator.address)).wait();
    await (
      await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })
    ).wait();
    await expect(
      contract.connect(operator).submitResultBound(task, scenario.outputDigest, mutated)
    ).to.be.revertedWithCustomError(contract, "InvalidResult");
  });

  it("enforces one-shot task assignment and operator identity", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "tasks" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    await admitAll(contract, scenario);

    const task = taskId(contract, "oneshot");
    await (await contract.registerTask(task, operator.address)).wait();
    await expect(
      contract.registerTask(task, deployer.address)
    ).to.be.revertedWithCustomError(contract, "TaskAlreadyConsumed");

    // Unassigned sender cannot submit.
    await (await contract.depositStake({ value: hre.ethers.parseEther("1") })).wait();
    await expect(
      contract.submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).to.be.revertedWithCustomError(contract, "Unauthorized");

    await (
      await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })
    ).wait();
    await (
      await contract
        .connect(operator)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).wait();

    // Replay of the consumed task.
    await expect(
      contract
        .connect(operator)
        .submitResultBound(task, scenario.outputDigest, L.g1ToContract(scenario.outputCommitment))
    ).to.be.revertedWithCustomError(contract, "TaskAlreadyConsumed");
  });

  it("consumer detects delivery griefing: digest mismatch against delivered artifact", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "grief" });
    const contract = await deploy();
    await registerAllKeys(contract, scenario);
    await admitAll(contract, scenario);

    // Valid commitment recorded with an inconsistent digest is accepted on-chain
    // (availability griefing residual, unchanged from the LHS path) ...
    const wrongDigest = hre.ethers.keccak256("0xdeadbeef");
    const task = taskId(contract, "grief");
    await (await contract.registerTask(task, operator.address)).wait();
    await (
      await contract.connect(operator).depositStake({ value: hre.ethers.parseEther("1") })
    ).wait();
    await (
      await contract
        .connect(operator)
        .submitResultBound(task, wrongDigest, L.g1ToContract(scenario.outputCommitment))
    ).wait();

    // ... and the consumer comparison rejects the delivery.
    const stored = await contract.getBoundResult(task);
    expect(stored.outputDigest).to.not.equal(L.coordsDigest(scenario.outputCt));
  });

  it("verifies the off-chain Aranha--Pagnin aggregate certificate and rejects mutations", async function () {
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "cert" });
    const sigma = L.aggregate(
      scenario.owners.map((o) => o.signature),
      scenario.weights
    );
    const commitments = scenario.owners.map((o) => o.commitment);
    const pubkeys = scenario.owners.map((o) => o.pk);
    expect(L.verifyAggregate(sigma, commitments, pubkeys, TAG, scenario.weights, 0)).to.equal(true);

    const mutated = commitments.slice();
    mutated[4] = mutated[4].add(L.G1.BASE);
    expect(L.verifyAggregate(sigma, mutated, pubkeys, TAG, scenario.weights, 0)).to.equal(false);
  });
});
