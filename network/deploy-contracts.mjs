/**
 * Step-by-step deployment of the NON-LINEAR contract stack to any EVM
 * JSON-RPC endpoint (single dev node, the multi-validator PoA chain in
 * ./validators, or a remote network).
 *
 * Default: constructor-fixed CanonicalFHEDisputeGame with authenticated
 * availability and a fixed quorum of canonical recomputation signers. No
 * administrator approves registration or changes the modules/committee.
 * --legacy deploys the historical, configurable LocalFhevm regression stack.
 *
 * The linear contract (MKLHS-Verification.sol) is intentionally NOT deployed
 * here: its statement (dataset tag, N, operation, enrolled owners) is fixed
 * per dataset at deployment, which is the job of the linear admin client
 * (toolkit/examples/qoe/clients/01-deploy.mjs).
 *
 * Signing: unlocked node accounts when available (hardhat/ganache), else
 * VCFHE_PRIVATE_KEYS (comma-separated) or VCFHE_MNEMONIC — the same
 * variables the rest of the tooling uses. The PoA genesis in ./validators
 * prefunds the standard hardhat mnemonic, so
 *   VCFHE_MNEMONIC="test test test test test test test test test test test junk"
 * works out of the box there.
 *
 * Usage:
 *   node deploy-contracts.mjs --rpc-url <url> --profile-digest <bytes32> \
 *     --adjudicators <address,address,address> --adjudicator-threshold 2
 *   node deploy-contracts.mjs --legacy --rpc-url http://127.0.0.1:8546 --register-roles
 *
 * Options:
 *   --rpc-url <url>      JSON-RPC endpoint (default: $VCFHE_RPC_URL or http://127.0.0.1:8545)
 *   --register-roles     also register 2 operators, 4 auditors, 4 decryptors
 *                        (stakes: 2/1/1 ETH) from the next accounts
 *   --out <file>         manifest path (default: deployment.<chainId>.json)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const here = path.dirname(fileURLToPath(import.meta.url));
const fhePod = path.join(here, "..", "fhe-pod");
const require = createRequire(path.join(fhePod, "scripts", "evm-lib.mjs"));
const { ethers } = require("ethers");
const { compileContracts } = await import(
  `file://${path.join(fhePod, "scripts", "evm-lib.mjs")}`
);

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const RPC_URL = arg("--rpc-url", process.env.VCFHE_RPC_URL ?? "http://127.0.0.1:8545");
const REGISTER_ROLES = process.argv.includes("--register-roles");
const LEGACY = process.argv.includes("--legacy");
const profileDigest = arg("--profile-digest");
const adjudicators = (arg("--adjudicators", "")).split(",").filter(Boolean).map(a => ethers.getAddress(a.trim()));
const adjudicatorThreshold = Number(arg("--adjudicator-threshold", "2"));
if (!LEGACY && (!ethers.isHexString(profileDigest, 32) || profileDigest === ethers.ZeroHash ||
    adjudicators.length < 2 || new Set(adjudicators).size !== adjudicators.length ||
    adjudicators.includes(ethers.ZeroAddress) || !Number.isInteger(adjudicatorThreshold) ||
    adjudicatorThreshold < 2 || adjudicatorThreshold > adjudicators.length)) {
  throw new Error("Canonical deployment requires --profile-digest, distinct nonzero --adjudicators and a threshold in [2, committee size]");
}

const WINDOWS = {
  commit: Number(process.env.DEMO_COMMIT_WINDOW_SECONDS ?? 3600),
  open: Number(process.env.DEMO_OPEN_WINDOW_SECONDS ?? 3600),
  challenge: Number(process.env.DEMO_CHALLENGE_WINDOW_SECONDS ?? 3600),
};

async function signers(provider) {
  const keys = (process.env.VCFHE_PRIVATE_KEYS ?? "").split(/[\s,]+/).filter(Boolean);
  if (keys.length) {
    return keys.map((k) => new ethers.NonceManager(new ethers.Wallet(k, provider)));
  }
  if (process.env.VCFHE_MNEMONIC) {
    const n = Number(process.env.VCFHE_ACCOUNT_COUNT ?? 20);
    return Array.from({ length: n }, (_, i) =>
      new ethers.NonceManager(
        ethers.HDNodeWallet.fromPhrase(
          process.env.VCFHE_MNEMONIC, undefined, `m/44'/60'/0'/0/${i}`
        ).connect(provider)
      ));
  }
  return provider.listAccounts();
}

const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, {
  polling: true, pollingInterval: 500,
});
const chainId = Number((await provider.getNetwork()).chainId);
const accs = await signers(provider);
const deployer = accs[0];
console.log(`rpc      : ${RPC_URL} (chainId ${chainId})`);
console.log(`deployer : ${await deployer.getAddress()} (balance ${ethers.formatEther(await provider.getBalance(deployer))} ETH)`);

const artifacts = await compileContracts();
async function deploy(name, args = [], overrides = {}) {
  const f = new ethers.ContractFactory(artifacts[name].abi, artifacts[name].bytecode, deployer);
  const c = await f.deploy(...args, overrides);
  const rcpt = await c.deploymentTransaction().wait();
  console.log(`deployed : ${name.padEnd(31)} ${await c.getAddress()} (gas ${rcpt.gasUsed})`);
  return c;
}

const verifier = await deploy("ObjectiveMicroVerifier");
let game, availability, canonicalVerifier;
const legacyContracts = {};
if (LEGACY) {
  game = await deploy("LegacyConfigurableDisputeGame", [
    verifier.target, WINDOWS.commit, WINDOWS.open, WINDOWS.challenge, true,
  ]);
  availability = await deploy("AuthenticatedTraceAvailability", [game.target, WINDOWS.challenge]);
  await (await game.setAvailabilityModule(availability.target)).wait();
  const acl = await deploy("LocalFhevmACL");
  const executor = await deploy("LocalFhevmExecutor");
  const kms = await deploy("LocalFhevmKMSVerifier", [acl.target, executor.target]);
  const fhevmVerifier = await deploy("FhevmObjectiveMicroVerifier", [acl.target, executor.target, kms.target]);
  await (await game.setFhevmVerifier(fhevmVerifier.target)).wait();
  Object.assign(legacyContracts, { LocalFhevmACL: acl.target, LocalFhevmExecutor: executor.target,
    LocalFhevmKMSVerifier: kms.target, FhevmObjectiveMicroVerifier: fhevmVerifier.target });
} else {
  const from = await deployer.getAddress();
  const nonce = BigInt(await provider.send("eth_getTransactionCount", [from, "pending"]));
  const gameAddress = ethers.getCreateAddress({ from, nonce: nonce + 2n });
  availability = await deploy("AuthenticatedTraceAvailability", [gameAddress, WINDOWS.challenge]);
  canonicalVerifier = await deploy("CanonicalLeafVerifier", [gameAddress, profileDigest, adjudicators, adjudicatorThreshold]);
  game = await deploy("CanonicalFHEDisputeGame", [verifier.target, WINDOWS.commit, WINDOWS.open, WINDOWS.challenge,
    availability.target, canonicalVerifier.target]);
}

const manifest = {
  rpcUrl: RPC_URL, chainId, windows: WINDOWS, secureTraceMode: true,
  mode: LEGACY ? "legacy-local-fhevm-regression" : "canonical-constructor-fixed",
  contracts: {
    ObjectiveMicroVerifier: await verifier.getAddress(),
    [LEGACY ? "LegacyConfigurableDisputeGame" : "CanonicalFHEDisputeGame"]: await game.getAddress(),
    AuthenticatedTraceAvailability: await availability.getAddress(),
    UniformParticipantSampler: await game.participantSampler(),
    ...(canonicalVerifier ? { CanonicalLeafVerifier: canonicalVerifier.target } : legacyContracts),
  },
  roles: {},
  note: LEGACY ? "Regression-only administrative adapter with simulated LocalFhevm services." :
    "Committee membership is fixed at deployment. Security requires fewer corrupt signers than the threshold; distinct addresses alone do not establish independent operators.",
};

if (REGISTER_ROLES) {
  const [op1, op2, ...rest] = accs.slice(1, 11);
  for (const [label, signer, fn, stake] of [
    ["operator1", op1, "registerOperator", "2"], ["operator2", op2, "registerOperator", "2"],
    ...rest.slice(0, 4).map((s, i) => [`auditor${i + 1}`, s, "registerAuditor", "1"]),
    ...rest.slice(4, 8).map((s, i) => [`decryptor${i + 1}`, s, "registerDecryptor", "1"]),
  ]) {
    await (await game.connect(signer)[fn]({ value: ethers.parseEther(stake) })).wait();
    manifest.roles[label] = await signer.getAddress();
    console.log(`role     : ${label.padEnd(10)} ${manifest.roles[label]} staked ${stake} ETH`);
  }
}

const out = arg("--out", path.join(here, `deployment.${chainId}.json`));
fs.writeFileSync(out, JSON.stringify(manifest, null, 2));
console.log(`manifest : ${out}`);
