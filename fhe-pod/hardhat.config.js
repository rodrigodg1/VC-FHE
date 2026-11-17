function configuredHttpAccounts() {
  const keys = (process.env.VCFHE_PRIVATE_KEYS ?? "")
    .split(/[\s,]+/)
    .map((key) => key.trim())
    .filter(Boolean);
  if (keys.length > 0) return keys;

  const mnemonic = process.env.VCFHE_MNEMONIC?.trim();
  if (mnemonic) {
    return {
      mnemonic,
      count: Number(process.env.VCFHE_ACCOUNT_COUNT ?? 20)
    };
  }

  // Local Hardhat/Ganache nodes normally expose unlocked accounts through
  // eth_accounts. Public networks must use one of the two local-signing
  // configurations above.
  return "remote";
}

const expectedChainId = process.env.VCFHE_EXPECTED_CHAIN_ID
  ? Number(process.env.VCFHE_EXPECTED_CHAIN_ID)
  : undefined;

/** @type {import("hardhat/config").HardhatUserConfig} */
export default {
  solidity: {
    version: "0.8.24",
    // Offline environments can compile with a locally seeded WASM solc build
    // (same 0.8.24+commit.e11b9ed9 artifact as the npm `solc` dependency):
    //   HARDHAT_PREFER_WASM=1 npx hardhat ...
    ...(process.env.HARDHAT_PREFER_WASM === "1" ? { preferWasm: true } : {}),
    // Fully offline compilation: point HARDHAT_SOLC_PATH at a local solc
    // build (e.g. node_modules/solc/soljson.js, same 0.8.24+commit.e11b9ed9).
    ...(process.env.HARDHAT_SOLC_PATH ? { path: process.env.HARDHAT_SOLC_PATH } : {}),
    settings: {
      evmVersion: "paris",
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 1
      }
    }
  },
  paths: {
    sources: "contracts/src",
    tests: "contracts/test",
    artifacts: "contracts/hardhat-artifacts",
    cache: "contracts/hardhat-cache"
  },
  networks: {
    // External JSON-RPC chain (e.g., `npx hardhat node` on this or another
    // machine): select with FHE_POD_NETWORK=vcfhe, point with VCFHE_RPC_URL.
    vcfhe: {
      type: "http",
      url: process.env.VCFHE_RPC_URL ?? "http://127.0.0.1:8545",
      accounts: configuredHttpAccounts(),
      ...(expectedChainId === undefined ? {} : { chainId: expectedChainId })
    },
    hardhat: {
      type: "edr-simulated",
      chainType: "l1",
      chainId: 31337,
      // Enough local accounts for pool-scaling experiments
      // (eval:threshold-scaling sweeps auditor/decryptor pool sizes).
      accounts: {
        count: 64
      }
    }
  }
};
