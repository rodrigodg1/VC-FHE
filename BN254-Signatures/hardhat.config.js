require("@nomicfoundation/hardhat-toolbox");

function configuredHttpAccounts() {
    const keys = (process.env.VCFHE_PRIVATE_KEYS || "")
        .split(/[\s,]+/)
        .map((key) => key.trim())
        .filter(Boolean);
    if (keys.length > 0) return keys;

    const mnemonic = process.env.VCFHE_MNEMONIC && process.env.VCFHE_MNEMONIC.trim();
    if (mnemonic) {
        return {
            mnemonic,
            count: Number(process.env.VCFHE_ACCOUNT_COUNT || 20)
        };
    }
    return "remote";
}

const expectedChainId = process.env.VCFHE_EXPECTED_CHAIN_ID
    ? Number(process.env.VCFHE_EXPECTED_CHAIN_ID)
    : undefined;

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
    // Compiler settings are pinned rather than inherited from Hardhat defaults,
    // because both of them are priced into the reported gas table.
    //
    //   * evmVersion: Hardhat selects "paris" by default for solc 0.8.20. The
    //     evaluated chain activates Berlin and London at block zero
    //     (network/validators-besu/qbftConfig.json), which is also the runtime
    //     hardfork pinned below, so the compile target is pinned to the same
    //     rules. The two targets emit byte-identical bytecode for this contract:
    //     the pin records the intent and stops a future Hardhat default from
    //     silently moving the measurement.
    //   * optimizer: disabled, which is what produced the reported figures.
    //     Stated explicitly so the measurement setting is part of the
    //     configuration instead of a tool default. Enabling it (runs = 200)
    //     lowers deployment gas by 18% at N = 200 to 39% at N = 10, admission by
    //     about 3% and result submission by about 2%, without changing any
    //     acceptance or rejection outcome. The standalone harnesses
    //     scripts/verify_linear_soundness.mjs and scripts/mklhs_tfhe_onchain.mjs
    //     compile with the optimizer ON; they check acceptance semantics, not
    //     gas, so the two settings do not conflict.
    solidity: {
        version: "0.8.20",
        settings: {
            evmVersion: "london",
            optimizer: { enabled: false, runs: 200 }
        }
    },
    paths: {
        sources: "./contract",
        tests: "./test",
        cache: "./cache",
        artifacts: "./artifacts"
    },
    networks: {
        // In-process EVM used for the reported gas measurements. The hardfork is
        // pinned to the rules the validator genesis activates at block zero
        // (network/validators-besu/qbftConfig.json: berlinBlock 0, londonBlock 0),
        // so the measured gas is the gas the evaluated chain charges.
        //
        // Leaving this unset lets the measurement follow whatever hardfork the
        // installed Hardhat defaults to, which changes two priced items:
        //   * EIP-3860 (Shanghai) meters initcode, raising deployment gas;
        //   * EIP-7883 (Osaka) reprices MODEXP, raising the per-trial cost of the
        //     MapToGroup loop and hence admission gas.
        // Override with VCFHE_HARDFORK only to study that sensitivity.
        hardhat: {
            hardfork: process.env.VCFHE_HARDFORK || "london"
        },
        localhost: {
            url: "http://127.0.0.1:8545"
        },
        vcfhe: {
            url: process.env.VCFHE_RPC_URL || "http://127.0.0.1:8545",
            accounts: configuredHttpAccounts(),
            ...(expectedChainId === undefined ? {} : { chainId: expectedChainId })
        }
    }
};
