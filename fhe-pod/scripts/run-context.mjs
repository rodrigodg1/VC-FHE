/**
 * Execution provenance for every evaluation run.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Before this module the canonical evaluation outputs
 * (`artifacts/evaluations/*.csv|json`) recorded *what* was measured but not
 * *where*. Nothing in a committed CSV said whether a row came from the
 * four-validator Besu QBFT network or from the in-process development EVM,
 * which contract revision produced it, or which opening backend was active.
 * That provenance existed only inside `artifacts/runs/<id>/`, which is
 * gitignored -- so it did not survive into the repository at all, and a
 * reviewer could not tell the two venues apart from the artifacts.
 *
 * Every evaluation driver now stamps the block returned by `collectRunContext`
 * into its JSON report and flattens the `context*` columns into its CSV.
 *
 * FIELDS
 * ------
 *   schemaVersion   integer, bumped when the CSV/JSON layout changes
 *   startedAt       ISO-8601 UTC timestamp of the run
 *   network         FHE_POD_NETWORK, the Hardhat network name ("vcfhe" = QBFT)
 *   chainId         chain id read from the RPC endpoint (46853 = QBFT testnet,
 *                   31337 = in-process development EVM)
 *   rpcUrl          endpoint actually used (credentials stripped)
 *   venue           "qbft-network" | "in-process-evm" | "external-evm"
 *   consensus       "qbft" when the venue is the validator network
 *   secureTraceMode whether the security profile of the implementation is active
 *   openingBackend  "committee" | "kms-synthetic" | "kms-artifact"
 *   commitWindowSeconds / openWindowSeconds / challengeWindowSeconds
 *   gitCommit       HEAD of the repository, plus a dirty flag
 *   nodeVersion / platform / arch / cpuModel / cpuCount / totalMemoryBytes
 *
 * The block is intentionally flat and JSON-serialisable so it can be embedded
 * in a CSV without nesting.
 */

import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { projectRoot } from "./evm-lib.mjs";

/** Bump when the columns or the JSON report layout change. */
export const EVALUATION_SCHEMA_VERSION = 2;

/** Repository root (one level above `fhe-pod/`). */
export const repoRoot = path.resolve(projectRoot, "..");

/**
 * Rewrites an absolute path as a path relative to the repository root.
 *
 * Committed CSVs previously carried machine-specific absolute paths such as
 * `/workspace/VC-FHE/fhe-pod/artifacts/runs/...`, which
 * are meaningless on another machine. Relative paths keep the reference usable.
 */
export function repoRelative(absolutePath) {
  if (!absolutePath) return "";
  const relative = path.relative(repoRoot, absolutePath);
  return relative.startsWith("..") ? absolutePath : relative;
}

function safeExec(command, args) {
  try {
    return execFileSync(command, args, {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "";
  }
}

function gitInfo() {
  const commit = safeExec("git", ["rev-parse", "HEAD"]);
  if (!commit) return { gitCommit: "", gitDirty: "", gitBranch: "" };
  const status = safeExec("git", ["status", "--porcelain"]);
  return {
    gitCommit: commit,
    gitBranch: safeExec("git", ["rev-parse", "--abbrev-ref", "HEAD"]),
    gitDirty: status.length > 0
  };
}

/** Strips any embedded credentials before an endpoint is written to disk. */
function sanitizeUrl(rawUrl) {
  if (!rawUrl) return "";
  try {
    const url = new URL(rawUrl);
    url.username = "";
    url.password = "";
    return url.toString();
  } catch {
    return rawUrl;
  }
}

function classifyVenue(network, chainId) {
  if (network === "vcfhe" || chainId === 46853) return "qbft-network";
  if (network === "hardhat" || chainId === 31337) return "in-process-evm";
  return "external-evm";
}

function positiveInteger(raw, fallback) {
  const value = Number.parseInt(raw ?? "", 10);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

/**
 * Reads the chain id from the configured endpoint. Returns `null` when no
 * endpoint is reachable, so an offline lowering-only run still produces a
 * context block instead of failing.
 *
 * @param {string} rpcUrl
 * @returns {Promise<number|null>}
 */
export async function probeChainId(rpcUrl) {
  if (!rpcUrl) return null;
  try {
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      signal: AbortSignal.timeout(5000)
    });
    const payload = await response.json();
    return payload?.result ? Number.parseInt(payload.result, 16) : null;
  } catch {
    return null;
  }
}

/**
 * Collects the execution context of the current evaluation run.
 *
 * @param {object} [overrides] values the caller already knows (for example a
 *   chain id obtained from an existing provider) which take precedence over the
 *   probed ones.
 * @returns {Promise<object>} flat, JSON-serialisable provenance block
 */
export async function collectRunContext(overrides = {}) {
  const network = process.env.FHE_POD_NETWORK ?? "hardhat";
  const rpcUrl = sanitizeUrl(
    process.env.VCFHE_RPC_URL ?? process.env.RPC_URL ?? (network === "hardhat" ? "" : "")
  );
  const chainId = overrides.chainId ?? (await probeChainId(rpcUrl));
  const venue = classifyVenue(network, chainId);
  const kmsOpening = (process.env.FHE_POD_KMS_OPENING ?? "off").toLowerCase();
  const openingBackend =
    kmsOpening === "off" ? "committee" : kmsOpening === "artifact" ? "kms-artifact" : "kms-synthetic";

  return {
    schemaVersion: EVALUATION_SCHEMA_VERSION,
    startedAt: new Date().toISOString(),
    network,
    chainId: chainId ?? "",
    rpcUrl,
    venue,
    consensus: venue === "qbft-network" ? "qbft" : "none",
    secureTraceMode: (process.env.FHE_POD_SECURE_TRACE ?? "true").toLowerCase() !== "false",
    openingBackend,
    commitWindowSeconds: positiveInteger(process.env.DEMO_COMMIT_WINDOW_SECONDS, 40),
    openWindowSeconds: positiveInteger(process.env.DEMO_OPEN_WINDOW_SECONDS, 40),
    challengeWindowSeconds: positiveInteger(process.env.DEMO_CHALLENGE_WINDOW_SECONDS, 40),
    ...gitInfo(),
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cpuModel: os.cpus()?.[0]?.model ?? "",
    cpuCount: os.cpus()?.length ?? 0,
    totalMemoryBytes: os.totalmem(),
    ...overrides
  };
}

/**
 * Refuses to produce evaluation evidence off the consensus network.
 *
 * The blockchain is the substrate of the evaluation: every smart-contract
 * measurement -- linear and non-linear alike -- is meant to run against the
 * four-validator Besu QBFT chain, so that gas, inclusion latency and settlement
 * are observed under real BFT consensus. Nothing previously enforced that: the
 * drivers defaulted to the in-process EVM (`FHE_POD_NETWORK=hardhat`), and a
 * run that silently fell back to it produced CSVs indistinguishable, to a
 * reader, from QBFT-backed ones.
 *
 * Called by every evaluation driver before any measurement starts, so a missing
 * chain fails in seconds instead of after the slow stages.
 *
 * @param {object} context block from `collectRunContext`
 * @param {{allowDevEvm?: boolean, label?: string}} options
 *   `allowDevEvm` corresponds to the `--allow-dev-evm` flag and downgrades the
 *   refusal to a loud warning, for development runs that are not evaluation
 *   evidence.
 * @throws {Error} when the venue is not the QBFT network and the escape hatch
 *   was not requested.
 */
export function requireChain(context, { allowDevEvm = false, label = "evaluation" } = {}) {
  if (context.venue === "qbft-network") return;

  const detail =
    context.chainId === ""
      ? `no JSON-RPC endpoint answered at ${context.rpcUrl || "(unset VCFHE_RPC_URL)"}`
      : `network=${context.network} chainId=${context.chainId} (venue: ${context.venue})`;

  if (allowDevEvm) {
    console.warn(
      `\n  WARNING: ${label} is running off the QBFT network -- ${detail}.\n` +
        "  --allow-dev-evm was passed, so this continues, but the resulting rows\n" +
        "  are a development check and MUST NOT be reported as evaluation evidence.\n"
    );
    return;
  }

  throw new Error(
    `${label} refuses to run off the consensus network: ${detail}.\n` +
      "The blockchain is the substrate of the evaluation, so contract measurements\n" +
      "must be taken on the four-validator Besu QBFT chain. Start it and retry:\n" +
      "  docker compose up -d node1 node2 node3 node4\n" +
      "  export FHE_POD_NETWORK=vcfhe VCFHE_RPC_URL=http://127.0.0.1:8550\n" +
      "  export VCFHE_EXPECTED_CHAIN_ID=46853\n" +
      '  export VCFHE_MNEMONIC="test test test test test test test test test test test junk"\n' +
      "Pass --allow-dev-evm only for a development run that will not be reported."
  );
}

/**
 * Flattens a context block into `context*` CSV columns, so every row of every
 * evaluation CSV is self-describing and rows from different venues can be
 * concatenated and grouped without losing their origin.
 *
 * @param {object} context block produced by `collectRunContext`
 * @returns {{columns: string[], values: object}}
 */
export function contextColumns(context) {
  const entries = Object.entries(context).map(([key, value]) => [
    `context${key.charAt(0).toUpperCase()}${key.slice(1)}`,
    typeof value === "boolean" ? String(value) : value
  ]);
  return {
    columns: entries.map(([key]) => key),
    values: Object.fromEntries(entries)
  };
}
