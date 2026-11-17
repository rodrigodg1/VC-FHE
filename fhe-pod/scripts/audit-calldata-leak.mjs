#!/usr/bin/env node
/**
 * Plaintext-leak audit over the transactions of one dispute run.
 *
 * Fetches EVERY transaction of a run BY HASH from the node, splits the calldata
 * into the 4-byte selector plus 32-byte words, and reports every word whose
 * uint256 value equals one of the workload's operand values.
 *
 * A match is classified as ABI FRAMING when the word is a head offset or a
 * dynamic-array/bytes length rather than a payload word. Small operand values
 * (say 72 or 100) collide with such words routinely, and those collisions carry
 * no information about the computation. Anything else is a real leak.
 *
 *   node scripts/audit-calldata-leak.mjs <runDir> --values 1928,100,192800,...
 *                                        [--public 16,20,1600] [--rpc URL]
 *
 * `--public` names values the WORKLOAD ITSELF declares public: a panel size, an
 * SLA threshold, a fixed-point scale, a divisor. Their operands are
 * SOURCE_PUBLIC_CONSTANT, and for those the ciphertext handle IS the value by
 * construction (see `_loadOperand` and `_controlConstant` in
 * contracts/src/FhevmObjectiveMicroVerifier.sol). Finding them on chain is the
 * design, not a leak, so they are counted and shown separately instead of
 * failing the audit. Anything not named here must not appear.
 *
 * `runDir` must contain hardhat_dispute_result.json.
 *
 * The scanning core is exported so that scripts/verify-encrypted-execution.mjs
 * can run the same instrument over several runs (including a known-leaky
 * historical run, as a negative control) without shelling out.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

/**
 * Word roles in an ABI-encoded call, computed structurally from the calldata
 * itself: a head word that points at a well-formed tail is an OFFSET, the first
 * word of such a tail is a LENGTH. Everything else is a PAYLOAD word, which is
 * where a leaked operand would have to live.
 */
export function classifyWords(data) {
  const body = data.slice(10); // strip "0x" + 4-byte selector
  const wordCount = Math.floor(body.length / 64);
  const words = [];
  for (let i = 0; i < wordCount; i += 1) {
    words.push(BigInt(`0x${body.slice(i * 64, (i + 1) * 64)}`));
  }
  const role = new Array(wordCount).fill("payload");
  const markTail = (headIndex, base) => {
    const offset = words[headIndex];
    if (offset === undefined || offset % 32n !== 0n) return;
    const wordIndex = base + Number(offset / 32n);
    if (wordIndex <= headIndex || wordIndex >= wordCount) return;
    role[headIndex] = "offset";
    // The word an offset points at is the length of the dynamic object.
    if (role[wordIndex] === "payload") role[wordIndex] = "length";
    // A dynamic array of dynamic elements: its body is itself a head region.
    const length = words[wordIndex];
    if (length > 0n && length < 64n) {
      for (let k = 0; k < Number(length); k += 1) {
        const inner = wordIndex + 1 + k;
        if (inner < wordCount) markTail(inner, wordIndex + 1);
      }
    }
  };
  for (let i = 0; i < wordCount; i += 1) markTail(i, 0);
  return { words, role };
}

export function loadRunResult(runDir) {
  return JSON.parse(fs.readFileSync(path.join(runDir, "hardhat_dispute_result.json"), "utf8"));
}

/**
 * Every transaction of the run, fetched BY HASH from the node: the audit reads
 * what the chain stores, not what the run wrote to its own log.
 */
export async function fetchRunTransactions(runDir, provider) {
  const result = loadRunResult(runDir);
  const transactions = [];
  for (const entry of result.transactions) {
    const tx = await provider.getTransaction(entry.hash);
    if (!tx) throw new Error(`node does not know transaction ${entry.hash} (${entry.label})`);
    transactions.push({
      label: entry.label,
      hash: entry.hash,
      data: tx.data ?? "0x",
      to: tx.to ?? null,
      blockNumber: tx.blockNumber
    });
  }
  return { result, transactions };
}

/**
 * Word-level scan of a set of fetched transactions for a set of target values.
 * Returns, per value, how many payload words and how many framing words carried
 * it, plus the located hits.
 */
export function scanTransactionsForValues(transactions, targets) {
  const perValue = new Map(targets.map((value) => [value, { payload: 0, framing: 0, hits: [] }]));
  let totalWords = 0;
  for (const entry of transactions) {
    if (entry.data.length <= 10) continue;
    const { words, role } = classifyWords(entry.data);
    totalWords += words.length;
    for (let i = 0; i < words.length; i += 1) {
      const bucket = perValue.get(words[i]);
      if (!bucket) continue;
      if (role[i] === "payload") {
        bucket.payload += 1;
        bucket.hits.push({ label: entry.label, hash: entry.hash, word: i, role: role[i] });
      } else {
        bucket.framing += 1;
      }
    }
  }
  return { perValue, totalWords };
}

export async function auditRun({ runDir, provider, targets, declaredPublic = new Set() }) {
  const { result, transactions } = await fetchRunTransactions(runDir, provider);
  const { perValue, totalWords } = scanTransactionsForValues(transactions, targets);
  let leaks = 0;
  for (const [value, bucket] of perValue) {
    if (!declaredPublic.has(String(value))) leaks += bucket.payload;
  }
  return { result, transactions, perValue, totalWords, leaks, scanned: transactions.length };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const isCli = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isCli) {
  const args = process.argv.slice(2);
  const runDir = args[0];
  if (!runDir) {
    throw new Error("usage: node scripts/audit-calldata-leak.mjs <runDir> --values a,b,c [--rpc URL]");
  }
  const valuesArg = args[args.indexOf("--values") + 1] ?? "";
  const rpcUrl =
    (args.includes("--rpc") ? args[args.indexOf("--rpc") + 1] : null) ??
    process.env.VCFHE_RPC_URL ??
    "http://127.0.0.1:8550";

  const parseList = (raw) =>
    (raw ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => BigInt(entry));

  const targets = parseList(valuesArg);
  if (targets.length === 0) throw new Error("--values must list at least one operand value");
  const declaredPublic = new Set(
    parseList(args.includes("--public") ? args[args.indexOf("--public") + 1] : "").map(String)
  );

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const { result, perValue, totalWords, leaks, scanned } = await auditRun({
    runDir,
    provider,
    targets,
    declaredPublic
  });

  console.log(`run:        ${path.basename(runDir)}`);
  console.log(`rpc:        ${rpcUrl}  (chainId ${result.chainId})`);
  console.log(`fetched:    ${scanned} transactions by hash from the node`);
  console.log(`scanned:    ${totalWords} calldata words (32-byte, after the 4-byte selector)`);
  console.log("");
  console.log("value            payload-word occurrences   ABI-framing occurrences   kind");
  for (const [value, bucket] of perValue) {
    const isPublic = declaredPublic.has(String(value));
    console.log(
      `${String(value).padEnd(16)} ${String(bucket.payload).padEnd(26)} ` +
        `${String(bucket.framing).padEnd(24)} ${isPublic ? "declared PUBLIC scalar" : "private operand"}`
    );
  }
  console.log("");
  for (const [value, bucket] of perValue) {
    if (bucket.hits.length === 0) continue;
    const byLabel = new Map();
    for (const hit of bucket.hits) {
      byLabel.set(hit.label, (byLabel.get(hit.label) ?? 0) + 1);
    }
    console.log(`  value ${value} appears in payload words of:`);
    for (const [label, count] of [...byLabel].sort((a, b) => b[1] - a[1])) {
      console.log(`    ${String(count).padStart(4)} x ${label}`);
    }
    for (const hit of bucket.hits.slice(0, 4)) {
      console.log(`      e.g. ${hit.label} word${hit.word} tx=${hit.hash}`);
    }
  }
  console.log(
    leaks === 0
      ? "RESULT: PASS (zero operand occurrences outside ABI framing)"
      : `RESULT: FAIL (${leaks} operand occurrences in payload words)`
  );
  process.exit(leaks === 0 ? 0 : 1);
}
