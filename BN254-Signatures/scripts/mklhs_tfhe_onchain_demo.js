/**
 * Thin wrapper: runs scripts/mklhs_tfhe_onchain.js against the schema-identical
 * pseudorandom DEMO payload (no Rust toolchain needed) for on-chain wiring
 * regression under the same Hardhat toolchain as the real-TFHE run. Gas is
 * representative; correctness semantics do not apply to the demo encoding.
 *
 *   npx hardhat run scripts/mklhs_tfhe_onchain_demo.js
 *
 * Requires onchain_proofs_demo_mk.json (see: npm run payload:demo-mk).
 */
"use strict";
process.env.PAYLOAD = process.env.PAYLOAD || "onchain_proofs_demo_mk.json";
process.env.CSV_OUT = process.env.CSV_OUT || "mklhs_demo_gas_results.csv";
require("./mklhs_tfhe_onchain.js");
