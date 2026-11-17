/**
 * LINEAR QoE examples, end to end, with nothing abstracted:
 *
 *   task definition   toolkit front end classifies the aggregation statement
 *   TFHE              per-owner ciphertexts are REAL leveled TFHE-LWE vectors
 *                     (tfhe-rs core_crypto, k = 742), emitted with exact
 *                     decryption asserted by the Rust emitter
 *                     (`emit-onchain-mk-cases`, payload in ../data/)
 *   Solidity          the PRODUCTION contract MKLHS-Verification.sol
 *   blockchain        a standalone Hardhat JSON-RPC node (fhe-pod toolchain);
 *                     every step is a signed transaction
 *   verification      on-chain: per-record two-pairing admission + O(1)
 *                     accumulator equality; off-chain: consumer recomputation
 *                     of the canonical digest and commitment P(A')
 *
 * Cases (both derived from real datasets; see ../data/generate-linear-cases.mjs):
 *   1. stav360-session-mos-mean   verified SUM of 16 real ACR ratings; the
 *                                 session MOS mean is sum/16 after decryption.
 *   2. drivetest-compliance-rate  verified SUM of 16 real 0/1 good-session
 *                                 indicators; the regulator checks
 *                                 count*1000 >= 16*950.
 *
 * Usage:  node linear/run-onchain.mjs          (spawns its own Hardhat node)
 *         HARDHAT_RPC=http://127.0.0.1:8545 node linear/run-onchain.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import solc from "solc";
import { ethers } from "ethers";
import { bn254 } from "@noble/curves/bn254";

const here = path.dirname(fileURLToPath(import.meta.url));
const exampleRoot = path.join(here, "..");
const vcfheRoot = path.join(exampleRoot, "..", "..", "..");
const fhePodDir = path.join(vcfheRoot, "fhe-pod");
const contractPath = path.join(vcfheRoot, "BN254-Signatures", "contract", "MKLHS-Verification.sol");
const payloadPath = path.join(exampleRoot, "data", "onchain_proofs_qoe_mk.json");

export const HARDHAT_PORT = Number(process.env.HARDHAT_PORT ?? 8571);

// ---------------------------------------------------------------------------
// Hardhat node lifecycle
// ---------------------------------------------------------------------------
export async function startHardhatNode(port = HARDHAT_PORT) {
  const bin = path.join(fhePodDir, "node_modules", ".bin", "hardhat");
  if (!fs.existsSync(bin)) {
    throw new Error(`Hardhat not installed; run "npm install" in VC-FHE/fhe-pod first (${bin})`);
  }
  const child = spawn(bin, ["node", "--port", String(port)], {
    cwd: fhePodDir,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const url = `http://127.0.0.1:${port}`;
  const provider = new ethers.JsonRpcProvider(url, undefined, { polling: true, pollingInterval: 50 });
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      await provider.send("eth_chainId", []);
      break;
    } catch {
      if (Date.now() > deadline) {
        child.kill("SIGKILL");
        throw new Error(`Hardhat node did not come up on ${url} within 60s`);
      }
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  return { child, provider, url };
}

// ---------------------------------------------------------------------------
// Compile the production contract
// ---------------------------------------------------------------------------
let compiledCache = null;
export function compileContract() {
  if (compiledCache) return compiledCache;
  const source = fs.readFileSync(contractPath, "utf8");
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
  const errs = (out.errors ?? []).filter((e) => e.severity === "error");
  if (errs.length) throw new Error(errs.map((e) => e.formattedMessage).join("\n"));
  const c = out.contracts["MKLHS-Verification.sol"]["MKLHSVerification"];
  compiledCache = { abi: c.abi, bytecode: "0x" + c.evm.bytecode.object };
  return compiledCache;
}

// ---------------------------------------------------------------------------
// Consumer-side recomputation (digest + commitment), mirroring the Rust side
// ---------------------------------------------------------------------------
const G1 = bn254.G1.ProjectivePoint;
const FR_ORDER = bn254.fields.Fr.ORDER;

export function coordsDigest(coordsDec) {
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

export function recomputeCommitment(liftedDec, gensDec) {
  let acc = G1.ZERO;
  for (let d = 0; d < liftedDec.length; d++) {
    const s = BigInt(liftedDec[d]) % FR_ORDER;
    if (s === 0n) continue;
    acc = acc.add(
      G1.fromAffine({ x: BigInt(gensDec[d][0]), y: BigInt(gensDec[d][1]) }).multiply(s)
    );
  }
  const a = acc.toAffine();
  return [a.x.toString(), a.y.toString()];
}

export function loadPayload() {
  if (!fs.existsSync(payloadPath)) {
    throw new Error(
      `Real-TFHE payload not found: ${payloadPath}\n` +
        `Generate it first (Rust, real TFHE-LWE):\n` +
        `  npm run cases:generate && npm run emit:tfhe`
    );
  }
  const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
  if (payload.scheme !== "output_binding_tfhe_multikey") {
    throw new Error(`unexpected payload scheme: ${payload.scheme}`);
  }
  return payload;
}

async function reverts(promise) {
  try {
    await (await promise).wait();
    return false;
  } catch {
    return true;
  }
}

// ---------------------------------------------------------------------------
// Full on-chain flow for one real-TFHE case
// ---------------------------------------------------------------------------
export async function runCaseOnChain({ provider, entry, gens, log = () => {} }) {
  const { abi, bytecode } = compileContract();
  const accounts = await provider.listAccounts();
  if (accounts.length < entry.n + 2) {
    throw new Error(`need ${entry.n + 2} accounts, node exposes ${accounts.length}`);
  }
  const deployer = accounts[0];
  const operator = accounts[1];
  const ownerSigner = (i) => accounts[2 + (i % (accounts.length - 2))];
  const gas = {};

  // 1. Deploy the production contract with the case's dataset tag and one
  //    enrolled owner address per index.
  const factory = new ethers.ContractFactory(abi, bytecode, deployer);
  const contract = await factory.deploy(
    entry.label,
    1,
    entry.n,
    entry.allowed_op,
    entry.dataset_tag,
    await Promise.all(entry.records.map((r) => ownerSigner(r.index).getAddress())),
    { value: ethers.parseEther("1") }
  );
  const depRcpt = await contract.deploymentTransaction().wait();
  gas.deployment = depRcpt.gasUsed.toString();
  log(`deployed MKLHSVerification at ${await contract.getAddress()} (gas ${gas.deployment})`);

  // 2. Each owner self-registers its BLS G2 key from its enrolled address.
  let regTotal = 0n;
  for (const r of entry.records) {
    const rc = await (await contract
      .connect(ownerSigner(r.index))
      .registerOwnerKey(r.index, r.pubkey.map(BigInt))).wait();
    regTotal += rc.gasUsed;
  }
  gas.keyRegistrationMean = (regTotal / BigInt(entry.n)).toString();
  log(`registered ${entry.n} owner keys (mean gas ${gas.keyRegistrationMean})`);

  // 3. Adversarial: admission signed under the WRONG owner key must revert
  //    (before index 0 is consumed by the honest admission).
  const wrongKeyRejected = await reverts(
    contract.connect(ownerSigner(0)).admitRecord(
      0,
      entry.records[0].commitment.map(BigInt),
      entry.wrong_key_signature.map(BigInt)
    )
  );
  log(`wrong-key admission rejected: ${wrongKeyRejected}`);

  // 4. Honest admissions: real TFHE ciphertext-vector commitments enter the
  //    chain here, one two-pairing BLS check each. The LAST admission is
  //    deferred to exercise the omission rejection first.
  let admitTotal = 0n;
  for (const r of entry.records.slice(0, entry.n - 1)) {
    const rc = await (await contract
      .connect(ownerSigner(r.index))
      .admitRecord(r.index, r.commitment.map(BigInt), r.signature.map(BigInt))).wait();
    admitTotal += rc.gasUsed;
  }

  // 5. Adversarial: submission with one record missing must revert.
  const omissionTaskId = ethers.keccak256(ethers.toUtf8Bytes(`${entry.label}-omission-probe`));
  await (await contract.connect(deployer).registerTask(omissionTaskId, await operator.getAddress())).wait();
  await (await contract.connect(operator).depositStake({ value: ethers.parseEther("1") })).wait();
  const omissionRejected = await reverts(
    contract.connect(operator).submitResultBound(
      omissionTaskId,
      entry.honest.output_digest,
      entry.honest.commitment.map(BigInt)
    )
  );
  log(`omission (n-1 of n admitted) rejected: ${omissionRejected}`);

  const last = entry.records[entry.n - 1];
  const rcLast = await (await contract
    .connect(ownerSigner(last.index))
    .admitRecord(last.index, last.commitment.map(BigInt), last.signature.map(BigInt))).wait();
  admitTotal += rcLast.gasUsed;
  gas.admissionMean = (admitTotal / BigInt(entry.n)).toString();
  log(`admitted ${entry.n} real-TFHE records (mean gas ${gas.admissionMean})`);

  // 6. Adversarial: replayed admission of a consumed index must revert.
  const replayRejected = await reverts(
    contract.connect(ownerSigner(0)).admitRecord(
      0,
      entry.records[0].commitment.map(BigInt),
      entry.records[0].signature.map(BigInt)
    )
  );
  log(`replayed admission rejected: ${replayRejected}`);

  // 7. Adversarial: substituted output commitment must be rejected.
  const tamperAccepted = await contract.verifyBound(entry.attack.commitment.map(BigInt));
  const tamperTaskId = ethers.keccak256(ethers.toUtf8Bytes(`${entry.label}-tamper-probe`));
  await (await contract.connect(deployer).registerTask(tamperTaskId, await operator.getAddress())).wait();
  const tamperSubmitRejected = await reverts(
    contract.connect(operator).submitResultBound(
      tamperTaskId,
      entry.attack.output_digest,
      entry.attack.commitment.map(BigInt)
    )
  );
  log(`substituted output: verifyBound=${tamperAccepted}, submit rejected: ${tamperSubmitRejected}`);

  // 8. Honest result: one-shot task, O(1) accumulator equality.
  const taskId = ethers.keccak256(ethers.toUtf8Bytes(`${entry.label}-task-1`));
  await (await contract.connect(deployer).registerTask(taskId, await operator.getAddress())).wait();
  const submitRcpt = await (await contract.connect(operator).submitResultBound(
    taskId,
    entry.honest.output_digest,
    entry.honest.commitment.map(BigInt)
  )).wait();
  gas.resultSubmission = submitRcpt.gasUsed.toString();
  const bound = await contract.getBoundResult(taskId);
  log(`honest result accepted on-chain (gas ${gas.resultSubmission})`);

  // 9. Consumer verification of the DELIVERED artifact (the lifted
  //    accumulator emitted by the Rust pipeline): recompute digest and P(A').
  const digest = coordsDigest(entry.honest.lifted);
  const recomputed = recomputeCommitment(entry.honest.lifted, gens);
  const digestMatch = digest === bound[1];
  const commitmentMatch =
    recomputed[0] === bound[0][0].toString() && recomputed[1] === bound[0][1].toString();
  log(`consumer digest match: ${digestMatch}; commitment match: ${commitmentMatch}`);

  return {
    label: entry.label,
    n: entry.n,
    accepted: bound[3],
    wrongKeyRejected,
    omissionRejected,
    replayRejected,
    tamperAccepted,
    tamperSubmitRejected,
    digestMatch,
    commitmentMatch,
    expectedPlaintext: Number(entry.expected_plaintext),
    decryptChecked: entry.decrypt_checked === true,
    gas,
  };
}

export function interpret(entry, result) {
  if (entry.label === "stav360-session-mos-mean") {
    const mean = result.expectedPlaintext / entry.n;
    return `session MOS mean = ${result.expectedPlaintext}/${entry.n} = ${mean.toFixed(4)} (ACR 1..5)`;
  }
  if (entry.label === "drivetest-compliance-rate") {
    const target = 950;
    const permille = Math.round((result.expectedPlaintext * 1000) / entry.n);
    const compliant = result.expectedPlaintext * 1000 >= entry.n * target;
    return `good sessions = ${result.expectedPlaintext}/${entry.n} (${permille} permille); target ${target} permille => ${compliant ? "COMPLIANT" : "VIOLATION"}`;
  }
  return `verified aggregate = ${result.expectedPlaintext}`;
}

async function main() {
  // Step 0 -- toolkit front end: the aggregation statement is classified by
  // the production classifier before anything touches the chain.
  const { inspectExpression } = await import(
    `file://${path.join(vcfheRoot, "toolkit", "src", "index.mjs")}`
  );
  const payload = loadPayload();
  console.log("== Step 0: toolkit classification of the task statement ==");
  for (const entry of payload.sizes) {
    const expr = Array.from({ length: entry.n }, (_, i) => `x${i + 1}`).join(" + ");
    const info = inspectExpression(expr);
    console.log(`  ${entry.label}: "${`x1 + ... + x${entry.n}`}" -> pipeline=${info.pipeline} (${info.operation ?? "SUM"})`);
  }

  let node = null;
  let provider;
  if (process.env.HARDHAT_RPC) {
    provider = new ethers.JsonRpcProvider(process.env.HARDHAT_RPC);
    console.log(`\n== Using external Hardhat node at ${process.env.HARDHAT_RPC} ==`);
  } else {
    node = await startHardhatNode();
    provider = node.provider;
    console.log(`\n== Started Hardhat JSON-RPC node at ${node.url} ==`);
  }

  const results = [];
  try {
    for (const entry of payload.sizes) {
      console.log(`\n== Case: ${entry.label} (n=${entry.n}, real TFHE-LWE, source: ${entry.source}) ==`);
      const result = await runCaseOnChain({
        provider,
        entry,
        gens: payload.commit_generators,
        log: (m) => console.log(`  ${m}`),
      });
      const checks = [
        result.accepted, result.wrongKeyRejected, result.omissionRejected,
        result.replayRejected, !result.tamperAccepted, result.tamperSubmitRejected,
        result.digestMatch, result.commitmentMatch, result.decryptChecked,
      ];
      if (!checks.every(Boolean)) throw new Error(`${entry.label}: verification matrix failed: ${JSON.stringify(result)}`);
      console.log(`  TFHE decryption (asserted at emission): ${result.expectedPlaintext}`);
      console.log(`  interpretation: ${interpret(entry, result)}`);
      results.push(result);
    }
  } finally {
    if (node) node.child.kill("SIGKILL");
  }

  const artifactDir = path.join(exampleRoot, "artifacts");
  fs.mkdirSync(artifactDir, { recursive: true });
  const artifactPath = path.join(artifactDir, "linear_onchain_result.json");
  fs.writeFileSync(artifactPath, JSON.stringify({ payloadPath, results }, null, 2) + "\n");
  console.log(`\nAll linear QoE cases verified end to end. Artifact: ${artifactPath}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
