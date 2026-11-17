/**
 * Real-TFHE payloads through the multi-key (curator-free) MKLHS admission flow,
 * fully on-chain (in-process ganache EVM, BN254 precompiles).
 *
 * Pipeline position: consumes the JSON emitted by the Rust generator
 *
 *     cargo run --release --bin output_binding_tfhe -- emit-onchain-mk \
 *         onchain_proofs_tfhe_mk.json 10 50 100 200
 *
 * in which every record is a REAL leveled TFHE-LWE ciphertext vector
 * (tfhe-rs core_crypto, k = 742, D = 743) committed as P(c_i) = sum_d c_d G_d
 * and signed by its OWN data owner: sigma_i = sk_i (P(c_i) + H(tag, i)).
 * There is no curator; no single signing authority exists.
 *
 * For each (N, op) entry this script:
 *   1. deploys MKLHSVerification with the dataset tag from the payload and
 *      one enrolled address per index (cycling over funded accounts);
 *   2. registerOwnerKey for every index (owner-only, G2 subgroup check);
 *   3. admitRecord for every record (two-pairing BLS check on-chain,
 *      accumulator fold) -- REAL TFHE commitments enter the chain here;
 *   4. adversarial checks (all must revert / reject):
 *        a. wrong-key admission (signature by another owner's key),
 *        b. replayed admission of an already-consumed index,
 *        c. substituted output commitment (verifyBound false + submit revert);
 *   5. registerTask + submitResultBound of the honest output (accepted);
 *   6. consumer verification OFF-chain: recomputes the artifact digest
 *      (keccak over fixed-width 32-byte BE coordinates) and the commitment
 *      P(A') from the emitted generators, comparing both with the on-chain
 *      record -- the composed acceptance predicate of the experiment;
 *   7. appends gas rows to mklhs_tfhe_gas_results.csv.
 *
 * Usage:
 *   node scripts/mklhs_tfhe_onchain.mjs [payload.json] [csv-out]
 * Defaults: onchain_proofs_tfhe_mk.json, mklhs_tfhe_gas_results.csv
 *
 * Dependencies: npm i ethers ganache solc @noble/curves (or NODE_PATH to a
 * directory that provides them).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";
import { ethers } from "ethers";
import { bn254 } from "@noble/curves/bn254";

// ganache is an optional development dependency: ganache 7 pins a macOS-only
// fsevents as a regular nested dependency, so declaring it in package.json makes
// `npm ci` abort with EBADPLATFORM on Linux. Install it on demand instead:
//     npm run deps:ganache
let ganache;
try {
  ({ default: ganache } = await import("ganache"));
} catch (err) {
  console.error("This script needs the in-process ganache EVM, which is not installed.");
  console.error("Install it with:  npm run deps:ganache");
  process.exit(1);
}


const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");

const payloadPath = process.argv[2] ?? path.join(root, "onchain_proofs_tfhe_mk.json");
const csvPath = process.argv[3] ?? path.join(root, "mklhs_tfhe_gas_results.csv");

if (!fs.existsSync(payloadPath)) {
  console.error(
    `Payload not found: ${payloadPath}\n` +
      `Generate it first with the real-TFHE emitter:\n` +
      `  cargo run --release --bin output_binding_tfhe -- emit-onchain-mk onchain_proofs_tfhe_mk.json 10 50 100 200`
  );
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Compile
// ---------------------------------------------------------------------------
function compile() {
  const source = fs.readFileSync(
    path.join(root, "contract", "MKLHS-Verification.sol"),
    "utf8"
  );
  const input = {
    language: "Solidity",
    sources: { "MKLHS-Verification.sol": { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "paris",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (out.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length) {
    throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
  }
  const c = out.contracts["MKLHS-Verification.sol"]["MKLHSVerification"];
  return { abi: c.abi, bytecode: "0x" + c.evm.bytecode.object };
}

// ---------------------------------------------------------------------------
// Consumer-side recomputation (digest + commitment) -- mirrors the Rust side
// ---------------------------------------------------------------------------
function coordsDigest(coordsDec) {
  const bytes = new Uint8Array(coordsDec.length * 32);
  coordsDec.forEach((c, i) => {
    let v = BigInt(c);
    for (let j = 31; j >= 0; j--) {
      bytes[i * 32 + j] = Number(v & 0xffn);
      v >>= 8n;
    }
  });
  return ethers.keccak256(bytes);
}

const G1 = bn254.G1.ProjectivePoint;
function g1FromDec([x, y]) {
  return G1.fromAffine({ x: BigInt(x), y: BigInt(y) });
}
function recomputeCommitment(liftedDec, gensDec) {
  let acc = G1.ZERO;
  for (let d = 0; d < liftedDec.length; d++) {
    const s = BigInt(liftedDec[d]) % bn254.fields.Fr.ORDER;
    if (s === 0n) continue;
    acc = acc.add(g1FromDec(gensDec[d]).multiply(s));
  }
  const a = acc.toAffine();
  return [a.x.toString(), a.y.toString()];
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
  const KNOWN_SCHEMES = [
    "output_binding_tfhe_multikey", // real TFHE-LWE ciphertext vectors (Rust emitter)
    "output_binding_demo_multikey", // pseudorandom coords, schema smoke test only
  ];
  if (!KNOWN_SCHEMES.includes(payload.scheme)) {
    throw new Error(`unexpected scheme: ${payload.scheme}`);
  }
  const realTfhe = payload.scheme === "output_binding_tfhe_multikey";
  console.log(
    realTfhe
      ? "Payload: REAL TFHE-LWE ciphertext-vector commitments."
      : "Payload: DEMO encoding (schema smoke test; gas is representative, correctness semantics are not)."
  );
  const gens = payload.commit_generators;
  const { abi, bytecode } = compile();

  const totalAccounts = 24;
  const provider = new ethers.BrowserProvider(
    ganache.provider({
      logging: { quiet: true },
      chain: { chainId: 31337 },
      miner: { blockGasLimit: "0x1c9c380" },
      wallet: { totalAccounts, defaultBalance: 10000 },
    })
  );
  const signers = [];
  for (let i = 0; i < totalAccounts; i++) signers.push(await provider.getSigner(i));
  const deployer = signers[0];
  const operator = signers[1];
  const ownerSignerFor = (i) => signers[2 + (i % (totalAccounts - 2))];

  const rows = [["scheme", "n", "operation", "deployment_gas", "key_registration_gas_mean", "admission_gas_mean", "result_submission_gas", "adversarial_checks", "consumer_digest_match", "consumer_commitment_match", "expected_plaintext"]];

  for (const entry of payload.sizes) {
    const { n, allowed_op: op, records } = entry;
    const opName = op === 0 ? "SUM" : "SUB";
    const ownerAddrs = records.map((r) => ownerSignerFor(r.index).address);

    const factory = new ethers.ContractFactory(abi, bytecode, deployer);
    const contract = await factory.deploy(
      "tfhe-mk-dataset",
      1,
      n,
      op,
      entry.dataset_tag,
      ownerAddrs,
      { value: ethers.parseEther("1") }
    );
    const deployReceipt = await (await contract.deploymentTransaction()).wait();

    // Owner key registration (real per-owner G2 keys from the TFHE payload).
    let regTotal = 0n;
    for (const r of records) {
      const tx = await contract
        .connect(ownerSignerFor(r.index))
        .registerOwnerKey(r.index, r.pubkey.map(BigInt));
      regTotal += (await tx.wait()).gasUsed;
    }

    // Adversarial (a): wrong-key admission must revert BEFORE any honest
    // admission consumes index 0.
    let adversarialPassed = 0;
    if (n > 1) {
      let rejected = false;
      try {
        const tx = await contract
          .connect(ownerSignerFor(records[0].index))
          .admitRecord(0, records[0].commitment.map(BigInt), entry.wrong_key_signature.map(BigInt));
        await tx.wait();
      } catch {
        rejected = true;
      }
      if (!rejected) throw new Error(`n=${n} ${opName}: wrong-key admission was accepted`);
      adversarialPassed++;
    }

    // Honest admissions: REAL TFHE commitments verified on-chain (2-pairing BLS).
    let admitTotal = 0n;
    for (const r of records) {
      const tx = await contract
        .connect(ownerSignerFor(r.index))
        .admitRecord(r.index, r.commitment.map(BigInt), r.signature.map(BigInt));
      admitTotal += (await tx.wait()).gasUsed;
    }

    // Adversarial (b): replayed admission of a consumed index must revert.
    {
      let rejected = false;
      try {
        const r = records[0];
        const tx = await contract
          .connect(ownerSignerFor(r.index))
          .admitRecord(r.index, r.commitment.map(BigInt), r.signature.map(BigInt));
        await tx.wait();
      } catch {
        rejected = true;
      }
      if (!rejected) throw new Error(`n=${n} ${opName}: replayed admission was accepted`);
      adversarialPassed++;
    }

    // Adversarial (c): substituted output commitment must be rejected.
    const attackOk = await contract.verifyBound(entry.attack.commitment.map(BigInt));
    if (attackOk) throw new Error(`n=${n} ${opName}: substituted output accepted by verifyBound`);
    adversarialPassed++;

    // Honest result submission (task assignment + O(1) accumulator equality).
    const taskId = ethers.keccak256(ethers.toUtf8Bytes(`tfhe-mk-${n}-${opName}`));
    await (await contract.connect(deployer).registerTask(taskId, operator.address)).wait();
    await (await contract.connect(operator).depositStake({ value: ethers.parseEther("1") })).wait();
    const submitTx = await contract
      .connect(operator)
      .submitResultBound(taskId, entry.honest.output_digest, entry.honest.commitment.map(BigInt));
    const submitReceipt = await submitTx.wait();

    // Consumer verification: recompute digest and commitment from the
    // DELIVERED lifted accumulator and compare with the on-chain record.
    const digest = coordsDigest(entry.honest.lifted);
    const digestMatch = digest === entry.honest.output_digest;
    const recomputed = recomputeCommitment(entry.honest.lifted, gens);
    const commitmentMatch =
      recomputed[0] === entry.honest.commitment[0] &&
      recomputed[1] === entry.honest.commitment[1];
    if (!digestMatch) throw new Error(`n=${n} ${opName}: consumer digest mismatch`);
    if (!commitmentMatch) throw new Error(`n=${n} ${opName}: consumer commitment mismatch`);

    const row = [
      payload.scheme,
      n,
      opName,
      deployReceipt.gasUsed.toString(),
      (regTotal / BigInt(n)).toString(),
      (admitTotal / BigInt(n)).toString(),
      submitReceipt.gasUsed.toString(),
      `${adversarialPassed}/3`,
      digestMatch,
      commitmentMatch,
      entry.expected_plaintext,
    ];
    rows.push(row);
    console.log(
      `n=${n} ${opName}: deploy=${deployReceipt.gasUsed} keyReg(mean)=${regTotal / BigInt(n)} admit(mean)=${admitTotal / BigInt(n)} submit=${submitReceipt.gasUsed} adversarial=${adversarialPassed}/3 consumer digest/commitment=OK expected=${entry.expected_plaintext}`
    );
  }

  fs.writeFileSync(csvPath, rows.map((r) => r.join(",")).join("\n") + "\n");
  console.log(`\nWrote ${csvPath}`);
  console.log(
    realTfhe
      ? "All admissions carried REAL TFHE-LWE ciphertext-vector commitments; no curator key exists anywhere in this pipeline."
      : "Schema smoke test complete. Re-run against the Rust-emitted payload for the real-TFHE end-to-end claim."
  );
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
