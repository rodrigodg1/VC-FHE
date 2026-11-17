/**
 * MapToGroup agreement across the three implementations.
 *
 * Solidity is checked against JavaScript by admitting a record whose signature
 * was produced from the JS map: the contract derives its own message point, so a
 * successful pairing check means both maps returned the same point, and a
 * signature over the other square root must be rejected.
 *
 * Rust is checked against JavaScript through the emitted payload, when present:
 * the commitment generators and one Rust-produced signature are recomputed with
 * the JS map. Run `npm run emit:tfhe-mk` to produce the payload.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { expect } = require("chai");
const hre = require("hardhat");
const { bn254 } = require("@noble/curves/bn254");
const L = require("../scripts/mklhs-lib.js");

const TAG = "0x" + "5e".repeat(32);
const N = 3;
// Either emitter proves the same thing: that the Rust map, the JS map and the
// Solidity map agree. The real-TFHE payload needs the tfhe-rs toolchain; the
// field-level mirror (output-binding-lhs, `emit-onchain-mk`) runs anywhere.
const PAYLOAD = [
  path.join(__dirname, "..", "onchain_proofs_tfhe_mk.json"),
  path.join(__dirname, "..", "onchain_proofs_mirror_mk.json"),
].find((p) => fs.existsSync(p)) ?? path.join(__dirname, "..", "onchain_proofs_tfhe_mk.json");

describe("MapToGroup agreement", function () {
  this.timeout(600000);

  it("Solidity derives the same message point as the JS map", async function () {
    const signers = await hre.ethers.getSigners();
    const scenario = L.buildScenario({ n: N, op: 0, tagHex: TAG, seed: "agreement" });
    const owners = Array.from({ length: N }, (_, i) => signers[i + 1].address);
    const Factory = await hre.ethers.getContractFactory("MKLHSVerification");
    const contract = await Factory.deploy("agreement", 1, N, 0, TAG, owners, {
      value: hre.ethers.parseEther("1"),
    });
    await contract.waitForDeployment();

    for (const owner of scenario.owners) {
      await (
        await contract
          .connect(signers[owner.index + 1])
          .registerOwnerKey(owner.index, L.g2ToContract(owner.pk))
      ).wait();
    }
    const o = scenario.owners[0];

    // The signature is sk * M_i with M_i from the JS map; the contract recomputes
    // M_i itself, so acceptance means the two maps agree on this preimage.
    await (
      await contract
        .connect(signers[1])
        .admitRecord(0, L.g1ToContract(o.commitment), L.g1ToContract(o.signature))
    ).wait();
    expect(await contract.admitted(0)).to.equal(true);

    // Signing the mirror point of M_i, the other square root, must be rejected.
    const mirror = L.contextPoint(scenario.owners[1].pk, TAG, 1, 0, N, scenario.owners[1].commitment).negate();
    await expect(
      contract
        .connect(signers[2])
        .admitRecord(1, L.g1ToContract(scenario.owners[1].commitment), L.g1ToContract(mirror.multiply(scenario.owners[1].sk)))
    ).to.be.revertedWithCustomError(contract, "InvalidSignature");
  });

  it("Rust and JS agree on the generators and the context point", async function () {
    if (!fs.existsSync(PAYLOAD)) {
      this.skip();
    }
    const payload = JSON.parse(fs.readFileSync(PAYLOAD, "utf8"));
    const rustGens = payload.commit_generators;
    const jsGens = L.commitGenerators(rustGens.length);
    for (let d = 0; d < rustGens.length; d++) {
      const [x, y] = L.g1ToContract(jsGens[d]);
      expect(x, `generator ${d} x`).to.equal(BigInt(rustGens[d][0]));
      expect(y, `generator ${d} y`).to.equal(BigInt(rustGens[d][1]));
    }

    const size = payload.sizes[0];
    const rec = size.records[0];
    const pk = bn254.G2.ProjectivePoint.fromAffine({
      x: { c0: BigInt(rec.pubkey[0]), c1: BigInt(rec.pubkey[1]) },
      y: { c0: BigInt(rec.pubkey[2]), c1: BigInt(rec.pubkey[3]) },
    });
    const commitment = bn254.G1.ProjectivePoint.fromAffine({
      x: BigInt(rec.commitment[0]),
      y: BigInt(rec.commitment[1]),
    });
    const signature = bn254.G1.ProjectivePoint.fromAffine({
      x: BigInt(rec.signature[0]),
      y: BigInt(rec.signature[1]),
    });
    const tag = "0x" + String(payload.dataset_tag).replace(/^0x/, "");
    const M = L.contextPoint(pk, tag, Number(rec.index), size.allowed_op, size.n, commitment);
    const gt = bn254.pairingBatch([
      { g1: signature.negate(), g2: bn254.G2.ProjectivePoint.BASE },
      { g1: M, g2: pk },
    ]);
    expect(bn254.fields.Fp12.eql(gt, bn254.fields.Fp12.ONE)).to.equal(true);
  });
});
