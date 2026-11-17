#!/usr/bin/env node
/**
 * Records REAL Zama KMS threshold decryptions of ebool verdict bits in a form
 * the on-chain protocol consumes, and verifies them against the deployed
 * ZamaKMSVerdictVerifier.
 *
 * Pipeline per entry (mode `record`):
 *   1. `kms-core-client encrypt` produces an ebool ciphertext file under the
 *      KMS threshold key (real TFHE encryption by the production client);
 *   2. handle := keccak256(ciphertext file bytes) — the bytes32 the auditor
 *      commits as `verdictCommit` in `submitAudit`;
 *   3. `kms-core-client public-decrypt from-file` runs the real n-party MPC
 *      threshold decryption; the patched client (see
 *      patches/kms-core-client-v0.13.20-external-signatures.patch) places the
 *      target EIP-712 domain (your verifier contract, your chain id) in the
 *      request and prints each core's `external_signature` as JSON;
 *   4. each signature is checked locally (recovered address must be one of
 *      the registered core identities) and the entry is archived.
 *
 * The resulting artifact drives the dispute pipeline on any EVM chain:
 *   FHE_POD_KMS_OPENING=artifact \
 *   FHE_POD_KMS_ARTIFACT=<artifact.json> \
 *   FHE_POD_KMS_VERIFIER=<verifier addr> \
 *   FHE_POD_NETWORK=vcfhe VCFHE_RPC_URL=... npm run demo:hardhat
 *
 * Modes:
 *   record  --kms-repo <patched checkout> --key-id <id> --domain-file
 *           <deploy-kms-verifier output> [--ones 8] [--zeros 4]
 *           [--client-config <toml>] [--out <artifact.json>] [--mode cargo|docker]
 *   verify  --artifact <artifact.json> --rpc-url <url>   (eth_call gate)
 *
 * Latency: wall-clock per public decryption (encryption excluded) is recorded
 * per entry and summarized (mean/median/std/95% CI), comparable with the
 * measurement-only harness `run-kms-verdict-opening.mjs`.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { latencyStats, parseClientConfig } from "./run-kms-verdict-opening.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const moduleRoot = path.resolve(scriptDir, "..");
const fhePodDir = path.resolve(moduleRoot, "..", "fhe-pod");
const require = createRequire(path.join(fhePodDir, "package.json"));
const { ethers } = require("ethers");

const PUBLIC_DECRYPT_TYPES = {
  PublicDecryptVerification: [
    { name: "ctHandles", type: "bytes32[]" },
    { name: "decryptedResult", type: "bytes" },
    { name: "extraData", type: "bytes" }
  ]
};

function arg(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}
const has = (name) => process.argv.includes(name);

function buildClientCommand(mode, kmsRepo, clientConfig, clientArgs, extraEnv) {
  if (mode === "cargo") {
    return {
      command: "cargo",
      argv: ["run", "--release", "--bin", "kms-core-client", "--", "-f", clientConfig, ...clientArgs],
      options: { cwd: path.join(kmsRepo, "core-client"), env: { ...process.env, ...extraEnv } }
    };
  }
  const configDir = path.dirname(path.resolve(clientConfig));
  const configName = path.basename(clientConfig);
  const envFlags = Object.entries(extraEnv).flatMap(([key, value]) => ["-e", `${key}=${value}`]);
  return {
    command: "docker",
    argv: [
      "run", "--rm", "--network", "host",
      ...envFlags,
      "-v", `${configDir}:/config`,
      "-v", `${workDir}:/work`,
      "ghcr.io/zama-ai/kms/core-client:latest",
      "kms-core-client", "-f", `/config/${configName}`, ...clientArgs
    ],
    options: { env: process.env }
  };
}

function runClient(mode, kmsRepo, clientConfig, clientArgs, extraEnv, label) {
  const { command, argv, options } = buildClientCommand(mode, kmsRepo, clientConfig, clientArgs, extraEnv);
  const started = process.hrtime.bigint();
  const result = spawnSync(command, argv, { ...options, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${label} failed (exit ${result.status}):\n${result.stderr}\n${result.stdout}`);
  }
  return { stdout: result.stdout, stderr: result.stderr, elapsedMs };
}

function parseExtSigLines(stdout) {
  const entries = [];
  for (const line of stdout.split(/\r?\n/)) {
    const match = line.match(/^KMS_CC_EXT_SIG\s+(\{.*\})\s*$/);
    if (match) entries.push(JSON.parse(match[1]));
  }
  return entries;
}

const workDir = arg("--work-dir", path.join(os.tmpdir(), "vcfhe-kms-openings"));

async function recordMode() {
  const mode = arg("--mode", "cargo");
  const kmsRepo = arg("--kms-repo", process.env.KMS_REPO ?? null);
  const keyId = arg("--key-id", process.env.KMS_KEY_ID ?? null);
  const domainFile = arg("--domain-file");
  const ones = Number.parseInt(arg("--ones", "8"), 10);
  const zeros = Number.parseInt(arg("--zeros", "4"), 10);
  const outPath = arg(
    "--out",
    path.join(fhePodDir, "artifacts", "evaluations", `kms-onchain-openings-${stamp()}.json`)
  );
  let clientConfig = arg("--client-config");
  if (!clientConfig) {
    if (!kmsRepo) throw new Error("--client-config or --kms-repo required");
    clientConfig = path.join(kmsRepo, "core-client", "config", "client_local_threshold.toml");
  }
  if (mode === "cargo" && !kmsRepo) throw new Error("--kms-repo required in cargo mode (patched checkout)");
  if (!keyId) throw new Error("--key-id (or KMS_KEY_ID) required");
  if (!domainFile) throw new Error("--domain-file required (output of deploy-kms-verifier.mjs)");

  const domainManifest = JSON.parse(fs.readFileSync(domainFile, "utf8"));
  const { domain, signers, threshold } = domainManifest;
  const domainEnvBase = {
    KMS_CC_EIP712_NAME: domain.name,
    KMS_CC_EIP712_VERSION: domain.version,
    KMS_CC_EIP712_CHAIN_ID: String(domain.chainId),
    KMS_CC_EIP712_VERIFYING_CONTRACT: domain.verifyingContract
  };

  let deployment = null;
  try {
    deployment = parseClientConfig(fs.readFileSync(clientConfig, "utf8"));
  } catch {
    console.warn(`[warn] could not read ${clientConfig}; deployment metadata will be missing`);
  }

  fs.mkdirSync(workDir, { recursive: true });
  const plan = [
    ...Array.from({ length: ones }, () => 1),
    ...Array.from({ length: zeros }, () => 0)
  ];
  const openings = [];
  const signerSet = new Set(signers.map((s) => s.toLowerCase()));

  // Execution binding (see VerifiableFHEDisputeGame.openVerdictViaKMS). The
  // on-chain opener now requires the KMS `extraData` to equal
  // keccak256(abi.encode(taskId, auditor, game)). A bit-indexed pre-recorded
  // pool cannot satisfy that binding, because (taskId, auditor, game) are not
  // known at recording time — which is the whole point of the anti-replay
  // guard. To record BINDABLE openings, drive this online per (taskId,
  // auditor) with KMS_CC_EXTERNAL_EXTRADATA set to the game's
  // verdictOpeningBinding(taskId, auditor); the patched kms-core-client signs
  // whatever extraData the request carries. Default "0x" keeps the legacy
  // (unbound, non-openable-on-chain) recording behaviour for offline tooling.
  const boundExtraData = process.env.KMS_CC_EXTERNAL_EXTRADATA ?? "0x";

  for (const [index, bit] of plan.entries()) {
    const ctFile = path.join(workDir, `verdict-${index}-bit${bit}.bin`);
    const ctFileClient = mode === "docker" ? `/work/${path.basename(ctFile)}` : ctFile;
    runClient(
      mode, kmsRepo, clientConfig,
      [
        "encrypt",
        "--to-encrypt", bit ? "01" : "00",
        "--data-type", "ebool",
        "--key-id", keyId,
        "--ciphertext-output-path", ctFileClient
      ],
      {},
      `encrypt[${index}]`
    );
    const ciphertextBytes = fs.readFileSync(ctFile);
    const handle = ethers.keccak256(ciphertextBytes);

    const decrypt = runClient(
      mode, kmsRepo, clientConfig,
      ["public-decrypt", "from-file", "--input-path", ctFileClient],
      { ...domainEnvBase, KMS_CC_EXTERNAL_HANDLE: handle },
      `public-decrypt[${index}]`
    );
    const responses = parseExtSigLines(decrypt.stdout);
    if (responses.length === 0) {
      throw new Error(
        `public-decrypt[${index}] printed no KMS_CC_EXT_SIG lines; is the patched kms-core-client in use?`
      );
    }
    // ebool plaintext bytes are little-endian; bit value is byte[0].
    const plaintextHex = responses[0].plaintexts?.[0] ?? "";
    const decryptedBit = plaintextHex.length >= 2 && plaintextHex.slice(0, 2) !== "00" ? 1 : 0;
    if (decryptedBit !== bit) {
      throw new Error(`entry ${index}: threshold decryption returned bit ${decryptedBit}, expected ${bit}`);
    }
    const decryptedResult = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [BigInt(bit)]);

    const valid = [];
    const recoveredAddresses = [];
    for (const response of responses) {
      const signature = response.external_signature;
      if (!signature || signature === "0x") continue;
      let recovered;
      try {
        recovered = ethers.verifyTypedData(domain, PUBLIC_DECRYPT_TYPES, {
          ctHandles: [handle],
          decryptedResult,
          extraData: boundExtraData
        }, signature);
      } catch {
        continue;
      }
      if (signerSet.has(recovered.toLowerCase()) &&
          !recoveredAddresses.includes(recovered.toLowerCase())) {
        recoveredAddresses.push(recovered.toLowerCase());
        valid.push(signature);
      }
    }
    if (valid.length < threshold) {
      throw new Error(
        `entry ${index}: only ${valid.length}/${threshold} external signatures recovered to registered ` +
        `core identities. Check that --signers of deploy-kms-verifier.mjs are the cores' VerfAddress ` +
        `objects and that the patched client env overrides are active.`
      );
    }
    openings.push({
      index,
      verdictBit: bit,
      handle,
      extraData: boundExtraData,
      ciphertextFile: ctFile,
      ciphertextSha256: ethers.sha256(ciphertextBytes),
      decryptedResult,
      signatures: valid,
      recoveredCores: recoveredAddresses,
      latencyMs: Math.round(decrypt.elapsedMs * 100) / 100
    });
    console.log(
      `[${index + 1}/${plan.length}] bit=${bit} handle=${handle.slice(0, 10)}… ` +
      `signatures=${valid.length} latency=${decrypt.elapsedMs.toFixed(0)}ms`
    );
  }

  const artifact = {
    tool: "VC-FHE/threshold-kms run-kms-onchain-opening",
    backend:
      "zama-ai/kms threshold MPC public decryption (real protocol) with external EIP-712 signatures " +
      "bound to the deployed ZamaKMSVerdictVerifier domain",
    kmsClientPin: "v0.13.20 + patches/kms-core-client-v0.13.20-external-signatures.patch",
    domain,
    cores: signers,
    threshold,
    keyId,
    clientConfig,
    deployment,
    openings,
    latencySummary: latencyStats(openings.map((o) => o.latencyMs)),
    note:
      "Each entry is one real ebool ciphertext under the KMS threshold key and one real n-party MPC " +
      "public decryption; `signatures` are the cores' external EIP-712 signatures over " +
      "(ctHandles=[handle], decryptedResult, extraData=0x). latencyMs covers the full public-decrypt " +
      "client invocation (request fan-out, MPC, response verification), not encryption.",
    generatedAt: new Date().toISOString()
  };
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`\nWrote ${outPath}`);
  console.log(JSON.stringify(artifact.latencySummary, null, 1));
  console.log(
    "\nNext: FHE_POD_KMS_OPENING=artifact FHE_POD_KMS_ARTIFACT=" + outPath +
    " FHE_POD_KMS_VERIFIER=" + domain.verifyingContract +
    " (plus FHE_POD_NETWORK/VCFHE_* for the target chain) npm run demo:hardhat / eval:applications"
  );
}

async function verifyMode() {
  const artifactPath = arg("--artifact");
  const rpcUrl = arg("--rpc-url", "http://127.0.0.1:8550");
  if (!artifactPath) throw new Error("--artifact required");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const verifier = new ethers.Contract(
    artifact.domain.verifyingContract,
    [
      "function verifyDecryptionEIP712KMSSignatures(bytes32[] handlesList, bytes decryptedResult, bytes decryptionProof) view returns (bool)"
    ],
    provider
  );
  let ok = 0;
  for (const opening of artifact.openings) {
    const proof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes[]", "bytes"],
      [opening.signatures, opening.extraData ?? "0x"]
    );
    const accepted = await verifier.verifyDecryptionEIP712KMSSignatures(
      [opening.handle],
      opening.decryptedResult,
      proof
    );
    console.log(`entry ${opening.index} bit=${opening.verdictBit}: ${accepted ? "ACCEPT" : "REJECT"}`);
    if (accepted) ok += 1;
  }
  console.log(`\n${ok}/${artifact.openings.length} recorded openings verified on-chain (eth_call)`);
  if (ok !== artifact.openings.length) process.exit(1);
}

const stamp = () => new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");

const mode = process.argv[2];
if (mode === "record") {
  await recordMode();
} else if (mode === "verify") {
  await verifyMode();
} else {
  console.error("Usage: run-kms-onchain-opening.mjs record|verify [options] (see file header)");
  process.exit(1);
}
