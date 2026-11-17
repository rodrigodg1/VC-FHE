#!/usr/bin/env node
/**
 * Historical verdict-decryption regression tooling only. The current
 * CanonicalFHEDisputeGame has no setter or audit-decryption backend.
 * --game must refer to a LegacyConfigurableDisputeGame regression deployment.
 *
 * Deploys ZamaKMSVerdictVerifier (fhe-pod/contracts/src/ZamaKMSVerdictVerifier.sol)
 * to any EVM JSON-RPC endpoint (e.g. the Besu QBFT network of
 * network/validators-besu) and prints the EIP-712 domain the KMS relayer must
 * place in every public-decryption request.
 *
 * The signer set is the KMS cores' Ethereum-style identity addresses: each
 * core publishes its address as the public storage object
 * `VerfAddress/<signing-key-id>` (MinIO/S3 bucket PUB-p<i> in the stock
 * threshold deployment); fetch them, e.g.:
 *   curl http://localhost:9000/kms/PUB-p1/VerfAddress/<key-id>
 * and pass them here. threshold must be t+1 (= num_majority of the
 * kms-core-client config; 2 for the stock n=4, t=1 deployment).
 *
 * Usage:
 *   node scripts/deploy-kms-verifier.mjs \
 *     --rpc-url http://127.0.0.1:8550 \
 *     --signers 0xA...,0xB...,0xC...,0xD... --threshold 2 \
 *     [--game 0xDisputeGame]        # also wires setKmsVerdictVerifier
 *     [--out kms-verifier.json]
 *
 * Signing: uses VCFHE_PRIVATE_KEYS / VCFHE_MNEMONIC, else the standard dev
 * mnemonic prefunded by the repository's genesis files.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const fhePodDir = path.resolve(scriptDir, "..", "..", "fhe-pod");
const require = createRequire(path.join(fhePodDir, "package.json"));
const { ethers } = require("ethers");

const DEV_MNEMONIC = "test test test test test test test test test test test junk";

function arg(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const rpcUrl = arg("--rpc-url", "http://127.0.0.1:8550");
const signersRaw = arg("--signers");
const signersFile = arg("--signers-file");
const threshold = Number.parseInt(arg("--threshold", "2"), 10);
const domainName = arg("--name", "VCFHE-Verdict-Opening");
const domainVersion = arg("--version", "1");
const gameAddress = arg("--game");
const outPath = arg("--out");

let signers = [];
if (signersRaw) {
  signers = signersRaw.split(",").map((s) => ethers.getAddress(s.trim()));
} else if (signersFile) {
  const parsed = JSON.parse(fs.readFileSync(signersFile, "utf8"));
  const list = Array.isArray(parsed) ? parsed : parsed.addresses ?? parsed.signers;
  signers = list.map((s) => ethers.getAddress(String(s).trim()));
}
if (signers.length === 0) {
  console.error("Provide --signers 0x..,0x.. or --signers-file <json>");
  process.exit(1);
}
if (!Number.isInteger(threshold) || threshold < 1 || threshold > signers.length) {
  console.error(`--threshold must be in [1, ${signers.length}] (use t+1 = num_majority)`);
  process.exit(1);
}

const artifactPath = path.join(fhePodDir, "contracts", "out", "ZamaKMSVerdictVerifier.json");
if (!fs.existsSync(artifactPath)) {
  console.error(
    `Missing ${artifactPath}. Run \`npm run compile:contracts\` inside VC-FHE/fhe-pod first.`
  );
  process.exit(1);
}
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

const provider = new ethers.JsonRpcProvider(rpcUrl);
const keys = (process.env.VCFHE_PRIVATE_KEYS ?? "")
  .split(/[\s,]+/)
  .map((k) => k.trim())
  .filter(Boolean);
const wallet = keys.length > 0
  ? new ethers.Wallet(keys[0], provider)
  : ethers.HDNodeWallet.fromPhrase(process.env.VCFHE_MNEMONIC ?? DEV_MNEMONIC).connect(provider);

const network = await provider.getNetwork();
const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
const verifier = await factory.deploy(
  domainName,
  domainVersion,
  0,
  ethers.ZeroAddress,
  signers,
  threshold
);
await verifier.waitForDeployment();
const verifierAddress = await verifier.getAddress();

if (gameAddress) {
  const game = new ethers.Contract(
    ethers.getAddress(gameAddress),
    ["function setKmsVerdictVerifier(address verifier) external"],
    wallet
  );
  await (await game.setKmsVerdictVerifier(verifierAddress)).wait();
}

const manifest = {
  rpcUrl,
  chainId: Number(network.chainId),
  verifier: verifierAddress,
  wiredDisputeGame: gameAddress ?? null,
  signers,
  threshold,
  domain: {
    name: domainName,
    version: domainVersion,
    chainId: Number(network.chainId),
    verifyingContract: verifierAddress
  },
  relayerEnv: {
    KMS_CC_EIP712_NAME: domainName,
    KMS_CC_EIP712_VERSION: domainVersion,
    KMS_CC_EIP712_CHAIN_ID: String(Number(network.chainId)),
    KMS_CC_EIP712_VERIFYING_CONTRACT: verifierAddress
  },
  deployedAt: new Date().toISOString()
};

console.log(JSON.stringify(manifest, null, 2));
if (outPath) {
  fs.writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.error(`\nWrote ${outPath}`);
}
