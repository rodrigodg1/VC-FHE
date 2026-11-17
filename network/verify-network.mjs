/**
 * Automated verification of a chain + the full VC-FHE protocol on it.
 * One command, machine-checked, non-zero exit on any failure.
 *
 *   node verify-network.mjs --rpc-url <url> --consensus qbft \
 *     --profile-digest <bytes32> --adjudicators <address,address,address>
 *
 * Checks, in order:
 *   [chain]    C1 JSON-RPC reachable, chain id read
 *              C2 validator set (qbft_getValidatorsByBlockNumber or
 *                 clique_getSigners) has --min-validators entries
 *              C3 blocks are being produced (height advances)
 *   [protocol] P1 constructor-fixed canonical non-linear stack deploys
 *                 (deploy-contracts.mjs --register-roles)
 *              P2 linear workflow, role by role: admin deploy+task,
 *                 owners register+admit (real-TFHE records, two-pairing
 *                 checks), operator submits (digest, commitment), accepted
 *              P3 consumer verification ACCEPTs the honest delivery
 *              P4 consumer verification REJECTs a tampered delivery
 *
 * Options:
 *   --rpc-url <url>          default http://127.0.0.1:8545
 *   --consensus <mode>       qbft | clique | none   (default qbft)
 *   --min-validators <n>     default 4 (qbft), 1 (clique)
 *   --skip-chain / --skip-protocol
 *   --profile-digest / --adjudicators / --adjudicator-threshold
 *                          forwarded to canonical deployment
 *   --legacy               historical configurable regression stack instead
 *
 * Signing: consensus chains expose no unlocked accounts; unless
 * VCFHE_PRIVATE_KEYS/VCFHE_MNEMONIC are already set, the harness uses the
 * dev mnemonic prefunded by the genesis files in this repository.
 */
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const qoeDir = path.join(here, "..", "toolkit", "examples", "qoe");

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const RPC_URL = arg("--rpc-url", "http://127.0.0.1:8545");
const CONSENSUS = arg("--consensus", "qbft");
const MIN_VALIDATORS = Number(arg("--min-validators", CONSENSUS === "qbft" ? 4 : 1));
const SKIP_CHAIN = process.argv.includes("--skip-chain");
const SKIP_PROTOCOL = process.argv.includes("--skip-protocol");

const DEV_MNEMONIC = "test test test test test test test test test test test junk";
const env = { ...process.env };
if (CONSENSUS !== "none" && !env.VCFHE_PRIVATE_KEYS && !env.VCFHE_MNEMONIC) {
  env.VCFHE_MNEMONIC = DEV_MNEMONIC;
}
env.RPC_URL = RPC_URL;
env.VCFHE_RPC_URL = RPC_URL;

const results = [];
function record(id, label, ok, detail = "") {
  results.push({ id, label, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${id}  ${label}${detail ? `  (${detail})` : ""}`);
}

async function rpc(method, params = []) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

function run(id, label, cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ?? here, env, stdio: "inherit", timeout: 900_000,
  });
  record(id, label, r.status === 0, r.status === 0 ? "" : `exit ${r.status}`);
  return r.status === 0;
}

// ---------------------------------------------------------------- chain
if (!SKIP_CHAIN) {
  try {
    const chainId = parseInt(await rpc("eth_chainId"), 16);
    record("C1", "JSON-RPC reachable", true, `chainId ${chainId}`);
  } catch (e) {
    record("C1", "JSON-RPC reachable", false, e.message);
    summary();
  }

  if (CONSENSUS === "qbft") {
    try {
      const v = await rpc("qbft_getValidatorsByBlockNumber", ["latest"]);
      record("C2", `QBFT validator set >= ${MIN_VALIDATORS}`, v.length >= MIN_VALIDATORS, `${v.length} validators: ${v.join(", ")}`);
    } catch (e) {
      record("C2", "QBFT validator set", false, e.message);
    }
  } else if (CONSENSUS === "clique") {
    try {
      const v = await rpc("clique_getSigners", []);
      record("C2", `Clique signer set >= ${MIN_VALIDATORS}`, v.length >= MIN_VALIDATORS, `${v.length} signers`);
    } catch (e) {
      record("C2", "Clique signer set", false, e.message);
    }
  }

  if (CONSENSUS !== "none") {
    const h0 = parseInt(await rpc("eth_blockNumber"), 16);
    await new Promise((r) => setTimeout(r, 7000));
    const h1 = parseInt(await rpc("eth_blockNumber"), 16);
    record("C3", "blocks are being produced", h1 > h0, `height ${h0} -> ${h1}`);
  }
}

// ------------------------------------------------------------- protocol
if (!SKIP_PROTOCOL) {
  const modeArgs = process.argv.includes("--legacy") ? ["--legacy"] :
    ["--profile-digest", arg("--profile-digest", ""), "--adjudicators", arg("--adjudicators", ""),
     "--adjudicator-threshold", arg("--adjudicator-threshold", "2")];
  run("P1", "non-linear stack deploys (+ permissionless roles staked)",
    "node", ["deploy-contracts.mjs", ...modeArgs, "--rpc-url", RPC_URL, "--register-roles",
             "--out", path.join(here, "deployment.verify.json")]);

  const CASE = "stav360-session-mos-mean";
  run("P2a", "linear: admin deploys statement + assigns task",
    "node", ["clients/01-deploy.mjs", CASE], { cwd: qoeDir });
  run("P2b", "linear: owners register keys + admit real-TFHE records",
    "node", ["clients/02-owners.mjs", CASE], { cwd: qoeDir });
  run("P2c", "linear: operator submits (digest, commitment), accepted",
    "node", ["clients/03-operator.mjs", CASE], { cwd: qoeDir });
  run("P3", "linear: consumer ACCEPTs the honest delivery",
    "node", ["clients/04-consumer.mjs", CASE], { cwd: qoeDir });
  run("P4", "linear: consumer REJECTs a tampered delivery",
    "node", ["clients/04-consumer.mjs", CASE, "--tampered"], { cwd: qoeDir });
}

summary();

function summary() {
  const failed = results.filter((r) => !r.ok);
  console.log("\n=== verify-network summary ===");
  console.log(`rpc: ${RPC_URL}  consensus: ${CONSENSUS}`);
  console.log(`${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) {
    for (const f of failed) console.log(`  FAILED: ${f.id} ${f.label} ${f.detail}`);
    process.exit(1);
  }
  process.exit(0);
}
