#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import hre from "hardhat";
import { ethers } from "ethers";

const networkName = process.env.FHE_POD_NETWORK ?? "vcfhe";
const requiredAccounts = Number(process.env.VCFHE_REQUIRED_ACCOUNTS ?? 1);
const minimumBalanceWei = BigInt(process.env.VCFHE_MIN_BALANCE_WEI ?? 0);
const expectedChainId = process.env.VCFHE_EXPECTED_CHAIN_ID
  ? BigInt(process.env.VCFHE_EXPECTED_CHAIN_ID)
  : null;

if (!Number.isSafeInteger(requiredAccounts) || requiredAccounts < 1) {
  throw new Error("VCFHE_REQUIRED_ACCOUNTS must be a positive integer");
}

const connection = await hre.network.create(networkName);
try {
  const provider = new ethers.BrowserProvider(connection.provider);
  const network = await provider.getNetwork();
  const chainId = network.chainId;
  if (expectedChainId !== null && chainId !== expectedChainId) {
    throw new Error(`chain-id mismatch: expected ${expectedChainId}, RPC returned ${chainId}`);
  }

  const signers = await provider.listAccounts();
  if (signers.length < requiredAccounts) {
    throw new Error(
      `network exposes/configures ${signers.length} signer(s), but this run needs ${requiredAccounts}`
    );
  }

  const accounts = [];
  for (const signer of signers.slice(0, requiredAccounts)) {
    const address = await signer.getAddress();
    const balanceWei = await provider.getBalance(address);
    accounts.push({ address, balanceWei: balanceWei.toString() });
    if (balanceWei < minimumBalanceWei) {
      throw new Error(
        `signer ${address} balance ${balanceWei} is below VCFHE_MIN_BALANCE_WEI=${minimumBalanceWei}`
      );
    }
  }

  const now = new Date();
  const timestamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const artifact = {
    generatedAt: now.toISOString(),
    networkName,
    chainId: chainId.toString(),
    blockNumber: await provider.getBlockNumber(),
    requiredAccounts,
    availableAccounts: signers.length,
    minimumBalanceWei: minimumBalanceWei.toString(),
    signingMode: process.env.VCFHE_PRIVATE_KEYS
      ? "local-private-keys"
      : process.env.VCFHE_MNEMONIC
        ? "local-hd-mnemonic"
        : "remote-unlocked-accounts",
    accounts
  };

  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const outputDir = path.resolve(scriptDir, "..", "artifacts", "evaluations");
  fs.mkdirSync(outputDir, { recursive: true });
  const output = path.join(outputDir, `network-preflight-${timestamp}.json`);
  const latest = path.join(outputDir, "latest_network_preflight.json");
  fs.writeFileSync(output, `${JSON.stringify(artifact, null, 2)}\n`);
  fs.writeFileSync(latest, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`network preflight passed: chainId=${chainId} block=${artifact.blockNumber}`);
  console.log(`signers=${signers.length} required=${requiredAccounts}`);
  console.log(`artifact=${output}`);
} finally {
  await connection.close();
}
