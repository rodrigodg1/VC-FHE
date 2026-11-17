/**
 * Shared helpers for the role-separated linear clients.
 *
 * Each client is one protocol role of the evaluation's linear workflow
 * (Section "Workflow for Computation and Verification"):
 *
 *   01-deploy.mjs    admin      deploy MKLHS-Verification.sol (statement fixed
 *                               at deployment) and assign the task
 *   02-owners.mjs    owners     register keys + admit signed TFHE records
 *   03-operator.mjs  operator   take the FHE aggregation result and submit
 *                               (digest, commitment) on-chain
 *   04-consumer.mjs  consumer   verify digest + commitment against the chain
 *
 * The ciphertexts and the homomorphic aggregation are REAL TFHE-LWE, produced
 * by the Rust stage (`npm run emit:tfhe`, tfhe-rs core_crypto); the payload
 * `data/onchain_proofs_qoe_mk.json` is its output and asserts exact
 * decryption at emission (`decrypt_checked: true`). The clients are the
 * chain-facing halves of each role and never hold any decryption key.
 *
 * Network selection: RPC_URL (default http://127.0.0.1:8545). Any EVM
 * JSON-RPC endpoint with the BN254 precompiles works; see
 * VC-FHE/network/validators/ for a multi-validator PoA chain.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { loadPayload, compileContract, coordsDigest, recomputeCommitment }
  from "../linear/run-onchain.mjs";

export const here = path.dirname(fileURLToPath(import.meta.url));
export const RPC_URL = process.env.RPC_URL ?? "http://127.0.0.1:8545";

export function statePath(label) {
  return path.join(here, `state.${label}.json`);
}

export function loadCase(argv = process.argv.slice(2)) {
  const payload = loadPayload();
  const wanted = argv.find((a) => !a.startsWith("-"));
  const entry = wanted
    ? payload.sizes.find((s) => s.label === wanted)
    : payload.sizes[0];
  if (!entry) {
    const labels = payload.sizes.map((s) => s.label).join(", ");
    throw new Error(`unknown case "${wanted}"; available: ${labels}`);
  }
  return { payload, entry };
}

export async function connect() {
  const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, {
    polling: true, pollingInterval: 200,
  });
  await provider.send("eth_chainId", []);

  // Consensus chains (Besu, geth) expose no unlocked accounts: sign locally
  // with VCFHE_PRIVATE_KEYS or VCFHE_MNEMONIC (the repository-wide variables).
  // Dev nodes (hardhat, ganache) fall back to their unlocked accounts.
  const keys = (process.env.VCFHE_PRIVATE_KEYS ?? "").split(/[\s,]+/).filter(Boolean);
  let accounts;
  if (keys.length) {
    accounts = keys.map((k) => new ethers.NonceManager(new ethers.Wallet(k, provider)));
  } else if (process.env.VCFHE_MNEMONIC) {
    const n = Number(process.env.VCFHE_ACCOUNT_COUNT ?? 20);
    accounts = Array.from({ length: n }, (_, i) =>
      new ethers.NonceManager(
        ethers.HDNodeWallet.fromPhrase(
          process.env.VCFHE_MNEMONIC, undefined, `m/44'/60'/0'/0/${i}`
        ).connect(provider)
      ));
  } else {
    accounts = await provider.listAccounts();
  }
  if (accounts.length < 3) {
    throw new Error(
      `node at ${RPC_URL} exposes ${accounts.length} usable accounts; need >= n+2 ` +
      `(on consensus chains set VCFHE_MNEMONIC or VCFHE_PRIVATE_KEYS)`
    );
  }
  return { provider, accounts };
}

/** Same role/account layout as the reference runner. */
export function roles(accounts, n) {
  if (accounts.length < n + 2) {
    throw new Error(`need ${n + 2} accounts, node exposes ${accounts.length}`);
  }
  return {
    deployer: accounts[0],
    operator: accounts[1],
    ownerSigner: (i) => accounts[2 + (i % (accounts.length - 2))],
  };
}

export function readState(label) {
  const p = statePath(label);
  if (!fs.existsSync(p)) {
    throw new Error(`state file not found: ${p}\nRun the previous step first (see clients/README.md).`);
  }
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

export function writeState(label, value) {
  fs.writeFileSync(statePath(label), JSON.stringify(value, null, 2));
}

export async function contractAt(address, signer) {
  const { abi } = compileContract();
  return new ethers.Contract(address, abi, signer);
}

export { coordsDigest, recomputeCommitment, compileContract };
