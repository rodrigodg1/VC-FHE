#!/usr/bin/env node
/**
 * Tops up the signer accounts a campaign needs, from account 0.
 *
 * WHY THIS EXISTS
 * ---------------
 * The QBFT genesis funds 20 accounts derived from the campaign mnemonic. The
 * threshold-opening sweep needs `3 + auditors + decryptors` accounts, so its
 * largest point (16 auditors, 16 decryptors) needs 35 -- fifteen more than the
 * chain has ever funded.
 *
 * The alternative was to measure that point on the in-process EVM, which is
 * what the pipeline used to do. That is not acceptable here: the evaluation's
 * own guard (`requireChain`) refuses to report numbers produced off the
 * validator network, and it is right to. Rather than weaken the guard, fund
 * the accounts.
 *
 * Funding by transfer rather than by regenerating the genesis keeps the chain's
 * history, which means a campaign can be extended without discarding the blocks
 * that earlier campaigns were measured against.
 *
 * Idempotent: an account already above the threshold is skipped, so this is
 * safe to run before every campaign.
 *
 *   VCFHE_FUND_ACCOUNTS   how many accounts to guarantee (default 40)
 *   VCFHE_FUND_TARGET_ETH balance each one should reach  (default 100)
 */
import hre from "hardhat";
import { ethers } from "ethers";

const networkName = process.env.FHE_POD_NETWORK ?? "vcfhe";
const wanted = Number(process.env.VCFHE_FUND_ACCOUNTS ?? 40);
const targetEth = process.env.VCFHE_FUND_TARGET_ETH ?? "100";
const target = ethers.parseEther(targetEth);

const connection = await hre.network.create(networkName);
try {
  const provider = new ethers.BrowserProvider(connection.provider);
  const signers = await provider.listAccounts();

  if (signers.length < wanted) {
    // This is a configuration problem, not a funding problem: Hardhat derives
    // only VCFHE_ACCOUNT_COUNT accounts from the mnemonic, so no amount of
    // transferring will conjure the missing ones.
    throw new Error(
      `network configures ${signers.length} signer(s) but ${wanted} were requested; ` +
        `raise VCFHE_ACCOUNT_COUNT to at least ${wanted}`
    );
  }

  const funder = signers[0];
  const funderAddress = await funder.getAddress();
  const funded = [];

  for (let i = 1; i < wanted; i += 1) {
    const account = signers[i];
    const address = await account.getAddress();
    const balance = await provider.getBalance(address);
    if (balance >= target) continue;

    const topUp = target - balance;
    const tx = await funder.sendTransaction({ to: address, value: topUp });
    await tx.wait();
    funded.push({ index: i, address, topUpWei: topUp.toString() });
    console.log(`  funded [${i}] ${address}  +${ethers.formatEther(topUp)} ETH`);
  }

  const funderBalance = await provider.getBalance(funderAddress);
  if (funded.length === 0) {
    console.log(`  all ${wanted} signers already hold at least ${targetEth} ETH`);
  } else {
    console.log(
      `  topped up ${funded.length} signer(s); funder ${funderAddress} ` +
        `now holds ${ethers.formatEther(funderBalance)} ETH`
    );
  }
} finally {
  await connection.close?.();
}
