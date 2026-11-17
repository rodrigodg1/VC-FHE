/**
 * Sharding experiment for the linear-path deployment gas ceiling.
 *
 * Question: the deployed contract enrolls all N owners in its constructor, so
 * deployment gas grows as ~3.59M + 23.24k*N and hits the 30M block gas limit
 * near N ~ 1,135. Does splitting one logical dataset across K shard contracts
 * (each enrolling N/K owners under its own dataset tag) lift that ceiling
 * without losing the output binding?
 *
 * Three parts:
 *   A. Reproduce the deployment-gas line at the experiment's sizes (10/50/100/200)
 *      and probe the empirical ceiling under the 30M block gas limit.
 *   B. Show one monolithic deployment above the ceiling fails, while K shards
 *      covering the same total N deploy (each in its own block).
 *   C. End-to-end composition on two shards with a SHARED HE key and DISTINCT
 *      dataset tags: register, admit, submit and verify each partial result
 *      on-chain, then check the consumer-side composition
 *          P(A1 + A2) == P_agg1 (+) P_agg2
 *      (Pedersen commitments are additively homomorphic), decrypt the composed
 *      vector, and confirm a tampered shard output breaks the composition.
 *
 * Run (from BN254-Signatures/): npx hardhat run scripts/mklhs_shard_experiment.js
 * (or: npm run shard:experiment)
 *
 * Gas is protocol-defined under the pinned compiler settings (solc 0.8.20,
 * evmVersion london, optimizer off, runtime hardfork london, 30M block gas
 * limit), so the printed figures do not depend on the executing machine;
 * calldata byte pricing moves them by a few tens of gas across runs with
 * different tags and addresses.
 */
const hre = require("hardhat");
const L = require("./mklhs-lib.js");

const { ethers } = hre;

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT FAILED: ${msg}`);
}

function tag(label) {
  return ethers.id(`shard-experiment/${label}`); // non-zero bytes32
}

function synthAddress(i) {
  return ethers.getAddress(
    "0x" + ethers.keccak256(ethers.toBeHex(BigInt(i) + 1n, 32)).slice(26)
  );
}

async function main() {
  const signers = await ethers.getSigners();
  const deployer = signers[0];
  const operator = signers[1];
  const Factory = await ethers.getContractFactory("MKLHSVerification", deployer);

  // ------------------------------------------------------------ Part A ----
  console.log("== Part A: deployment gas vs N (monolithic) ==");
  async function tryDeploy(n, label) {
    const owners = Array.from({ length: n }, (_, i) => synthAddress(i));
    const deployTx = await Factory.getDeployTransaction(
      "shard-experiment", 1, n, 0, tag(label), owners,
      { value: ethers.parseEther("1") }
    );
    try {
      const sent = await deployer.sendTransaction({
        ...deployTx,
        gasLimit: 30_000_000n,
      });
      const rc = await sent.wait();
      return { ok: true, gasUsed: rc.gasUsed };
    } catch (err) {
      return { ok: false, error: String(err.message).slice(0, 120) };
    }
  }

  const fit = (n) => 3_589_454 + 23_240 * n;
  const experiment = { 10: 3_821_851n, 50: 4_751_443n, 100: 5_913_421n, 200: 8_237_389n };
  const results = [];
  for (const n of [10, 50, 100, 200, 400, 800, 1000, 1100, 1130, 1135, 1136, 1137, 1140, 1200]) {
    const r = await tryDeploy(n, `A-${n}`);
    results.push([n, r]);
    const fitStr = `fit ${fit(n).toLocaleString("en-US")}`;
    if (r.ok) {
      const match = experiment[n] !== undefined ? (r.gasUsed === experiment[n] ? "  == experiment table" : `  != experiment table (${experiment[n]})`) : "";
      console.log(`  N=${String(n).padStart(4)}  deploy OK   gas=${r.gasUsed.toLocaleString("en-US").padStart(12)}  (${fitStr})${match}`);
    } else {
      console.log(`  N=${String(n).padStart(4)}  deploy FAIL (${fitStr})  ${r.error}`);
    }
  }

  // ------------------------------------------------------------ Part B ----
  console.log("\n== Part B: N_total=1600, monolithic vs 2 shards of 800 ==");
  const mono = await tryDeploy(1600, "B-mono");
  console.log(`  monolithic N=1600: ${mono.ok ? `OK gas=${mono.gasUsed}` : `FAIL  ${mono.error}`}`);
  const shardGas = [];
  for (const s of [0, 1]) {
    const r = await tryDeploy(800, `B-shard-${s}`);
    assert(r.ok, `shard ${s} of 800 must deploy`);
    shardGas.push(r.gasUsed);
    console.log(`  shard ${s} N=800:    OK gas=${r.gasUsed.toLocaleString("en-US")}`);
  }
  console.log(`  total shard deployment gas: ${(shardGas[0] + shardGas[1]).toLocaleString("en-US")} across 2 transactions/blocks`);

  // ------------------------------------------------------------ Part C ----
  console.log("\n== Part C: composition across 2 shards (shared HE key, distinct tags) ==");
  const rng = L.makeRng("shard-compose");
  const gens = L.commitGenerators();
  const he = L.heKeygen(rng); // ONE shared encryption key across both shards
  const nShard = 8;

  function buildShard(tagHex, ratingOffset) {
    const weights = L.weightsFor(0, nShard); // SUM
    const owners = [];
    for (let i = 0; i < nShard; i++) {
      const { sk, pk } = L.keygen(rng);
      const m = BigInt(1 + ((ratingOffset + i) % 5)); // ratings 1..5
      const ct = L.heEnc(he, m, rng);
      const commitment = L.commit(ct, gens);
      const signature = L.sign(sk, commitment, tagHex, i, { pk, op: 0, totalItems: nShard });
      owners.push({ index: i, sk, pk, m, ct, commitment, signature });
    }
    const outputCt = L.heCombine(owners.map((o) => o.ct), weights);
    return {
      owners,
      outputCt,
      outputCommitment: L.commit(outputCt, gens),
      outputDigest: L.coordsDigest(outputCt),
    };
  }

  async function runShard(label, shard, tagHex) {
    const ownerAddrs = shard.owners.map((o) => signers[2 + o.index].address);
    const contract = await Factory.deploy(
      `dataset-${label}`, 1, nShard, 0, tagHex, ownerAddrs,
      { value: ethers.parseEther("1") }
    );
    await contract.waitForDeployment();
    for (const o of shard.owners) {
      const asOwner = contract.connect(signers[2 + o.index]);
      await (await asOwner.registerOwnerKey(o.index, L.g2ToContract(o.pk))).wait();
      await (
        await asOwner.admitRecord(o.index, L.g1ToContract(o.commitment), L.g1ToContract(o.signature))
      ).wait();
    }
    assert((await contract.admittedCount()) === BigInt(nShard), `${label}: all admitted`);
    assert(
      await contract.verifyBound(L.g1ToContract(shard.outputCommitment)),
      `${label}: honest partial aggregate matches the on-chain accumulator`
    );
    const taskId = ethers.id(`task/${label}`);
    await (await contract.registerTask(taskId, operator.address)).wait();
    await (await contract.connect(operator).depositStake({ value: ethers.parseEther("1") })).wait();
    await (
      await contract
        .connect(operator)
        .submitResultBound(taskId, shard.outputDigest, L.g1ToContract(shard.outputCommitment))
    ).wait();
    const stored = await contract.getBoundResult(taskId);
    return { contract, stored };
  }

  const shard1 = buildShard(tag("C-shard-1"), 0);
  const shard2 = buildShard(tag("C-shard-2"), 3);
  const run1 = await runShard("C-shard-1", shard1, tag("C-shard-1"));
  const run2 = await runShard("C-shard-2", shard2, tag("C-shard-2"));
  console.log("  both shards: admissions verified, partial results bound on-chain");

  // Consumer-side composition of the two accepted partial results.
  const aTotal = shard1.outputCt.map((x, j) => L.mod(x + shard2.outputCt[j], L.R));
  const pTotal = L.commit(aTotal, gens);

  const affine1 = { x: BigInt(run1.stored.outputCommitment[0]), y: BigInt(run1.stored.outputCommitment[1]) };
  const affine2 = { x: BigInt(run2.stored.outputCommitment[0]), y: BigInt(run2.stored.outputCommitment[1]) };
  const onChainSum = L.G1.fromAffine(affine1).add(L.G1.fromAffine(affine2));
  const pTotalContract = L.g1ToContract(pTotal);
  const sumContract = L.g1ToContract(onChainSum);
  assert(
    pTotalContract[0] === sumContract[0] && pTotalContract[1] === sumContract[1],
    "P(A1 + A2) equals the sum of the two on-chain bound commitments"
  );
  console.log("  composition: P(A1+A2) == P_agg1 (+) P_agg2  -> holds");

  // Decryption of the composed vector equals the sum over BOTH shards.
  const expected = L.mod(
    [...shard1.owners, ...shard2.owners].reduce((acc, o) => acc + o.m, 0n),
    L.MSG_SPACE
  );
  const decrypted = L.heDec(he, aTotal);
  assert(decrypted === expected, `composed decryption: got ${decrypted}, expected ${expected}`);
  console.log(`  composed decryption over 16 records across shards: ${decrypted} (expected ${expected})  -> exact`);

  // Tampering one shard's delivered output breaks the composition.
  const tampered = shard2.outputCt.slice();
  tampered[0] = L.mod(tampered[0] + 1n, L.R);
  const aTampered = shard1.outputCt.map((x, j) => L.mod(x + tampered[j], L.R));
  const pTampered = L.g1ToContract(L.commit(aTampered, gens));
  assert(
    !(pTampered[0] === sumContract[0] && pTampered[1] === sumContract[1]),
    "a tampered shard output must NOT compose to the on-chain commitments"
  );
  console.log("  tampered shard output: composition check rejects  -> holds");

  console.log("\nAll assertions passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
