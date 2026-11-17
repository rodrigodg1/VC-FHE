#!/usr/bin/env node
/**
 * Executable evidence that the evaluated operations and the dispute run over
 * ENCRYPTED data, and that no user operand is decrypted on chain.
 *
 *   npm run verify:encrypted
 *
 * Eight checks, each of which reads an artifact or the live chain and prints
 * the raw numbers it decided on. Nothing here trusts a claim written by the
 * pipeline itself: ciphertexts are deserialized and decrypted by a Rust helper
 * (`crates/tfhe-pod-demo/src/bin/ct-inspect.rs`, built as `target/release/
 * ct-inspect`), and transactions are fetched BY HASH from the node.
 *
 *   C1  a handle is keccak256 of a real serialized FheUint64 that decrypts to
 *       the declared clear value
 *   C2  a handle is not the plaintext (regression guard for the old
 *       "the handle IS the value" representation)
 *   C3  every manifest leaf executed homomorphically and agrees with the
 *       lowering
 *   C4  an auditor re-executing from the SAME stored input ciphertexts, with
 *       the published server key, reaches the SAME DECISION on every leaf in
 *       every one of --replays independent processes under CPU load -- the
 *       decision being FHE.eq against the committed result, which is what the
 *       settlement rule evaluates. Ciphertext bytes are reported but not
 *       required to match: they are not reproducible across schedules
 *   C5  no key material on chain, and the run's whole calldata is far smaller
 *       than one ciphertext
 *   C6  no private operand value in any transaction's calldata or in any event
 *       it emitted (public scalars reported separately)
 *   C7  the settlement transaction carries only handles, bits and signatures
 *   C8  negative control: the same instrument reports the leak of a historical
 *       run that still used `declareHandle`
 *
 * Exit code is 0 only if every executed check passed.
 *
 * Flags: --rpc URL --manifest P --ciphertext-dir D --traces P --workload ID
 *        --run DIR --leak-run DIR --only c1,c4 --sample N --replays N
 *        --load N (busy cores held during the C4 replays)
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { ethers } from "ethers";
import { PUBLIC_SCALAR_RHS_OPCODES } from "./micro-isa.mjs";
import { classifyWords, scanTransactionsForValues } from "./audit-calldata-leak.mjs";
import {
  decideLeaf,
  ensureCtInspect as buildCurrentCtInspect,
  replayWithDecisions,
  resultCiphertextPath,
  startCpuLoad
} from "./leaf-decision.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const podRoot = path.resolve(scriptDir, "..");

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
const flagValue = (name, fallback = null) => {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 && argv[index + 1] ? argv[index + 1] : fallback;
};
const resolvePod = (value) => (path.isAbsolute(value) ? value : path.resolve(podRoot, value));

const options = {
  rpcUrl: flagValue("rpc", process.env.VCFHE_RPC_URL ?? "http://127.0.0.1:8550"),
  manifestPath: resolvePod(flagValue("manifest", "artifacts/fhe/ciphertext-manifest.json")),
  ciphertextDir: resolvePod(flagValue("ciphertext-dir", "artifacts/fhe/ciphertexts")),
  tracesPath: resolvePod(flagValue("traces", "artifacts/fhe/traces.json")),
  // One id, a comma-separated list, or "all" for every honest workload the
  // manifest covers (the "<id>#corrupted" entries are the adversarial variants
  // and are audited as the negative control of C4, not as workloads).
  workloadId: flagValue("workload", "qoe_mos_degradation_alarm"),
  runDir: flagValue("run") ? resolvePod(flagValue("run")) : null,
  leakRunDir: flagValue("leak-run") ? resolvePod(flagValue("leak-run")) : null,
  sample: Number(flagValue("sample", "8")),
  replays: Number(flagValue("replays", "3")),
  // Busy cores held during the C4 replays. Scheduling contention is what makes
  // ciphertext bytes diverge, so the check looks for divergence rather than
  // waiting to be surprised by it in production. Half the cores by default:
  // enough to perturb the schedule across every workload without making the
  // sweep take longer than the campaign that produced the manifest.
  // scripts/leaf-decision-stability.test.mjs runs the same experiment on one
  // workload under heavier load.
  load: Number(flagValue("load", String(Math.max(2, Math.floor(os.cpus().length / 2))))),
  only: flagValue("only")
    ? new Set(
        flagValue("only")
          .split(",")
          .map((entry) => entry.trim().toUpperCase())
          .filter(Boolean)
      )
    : null
};

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

const loadJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const short = (value) => `${String(value).slice(0, 10)}…${String(value).slice(-6)}`;
const fmt = (n) => Number(n).toLocaleString("en-US");

/** 32-byte big-endian encoding of a value, as lowercase hex without 0x. */
const word32 = (value) => BigInt(value).toString(16).padStart(64, "0");
/** 8-byte big-endian encoding, the shape a packed u64 would have. */
const word8 = (value) => BigInt(value).toString(16).padStart(16, "0");

function countOccurrences(haystack, needle) {
  if (needle.length === 0) return 0;
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + 1);
  }
  return count;
}

let ctInspectBinary = null;
function ensureCtInspect() {
  if (ctInspectBinary) return ctInspectBinary;
  const binary = buildCurrentCtInspect();
  ctInspectBinary = binary;
  return binary;
}

function ctInspect(args, timeoutMs = 30 * 60 * 1000) {
  const binary = ensureCtInspect();
  const result = spawnSync(binary, args, {
    cwd: podRoot,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    timeout: timeoutMs
  });
  if (result.status !== 0) {
    throw new Error(
      `ct-inspect ${args.join(" ")} exited ${result.status}: ${(result.stderr ?? "").slice(-800)}`
    );
  }
  const lines = result.stdout.trim().split("\n");
  return JSON.parse(lines[lines.length - 1]);
}

// ---------------------------------------------------------------------------
// artifact / run discovery
// ---------------------------------------------------------------------------

const runsRoot = path.join(podRoot, "artifacts", "runs");

/** Run directories, newest first by the mtime of their dispute result. */
function listRunDirs() {
  if (!fs.existsSync(runsRoot)) return [];
  return fs
    .readdirSync(runsRoot)
    .map((name) => path.join(runsRoot, name))
    .filter((dir) => fs.existsSync(path.join(dir, "hardhat_dispute_result.json")))
    .map((dir) => ({ dir, mtime: fs.statSync(path.join(dir, "hardhat_dispute_result.json")).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)
    .map((entry) => entry.dir);
}

/** "application-layer-20260813T215937Z-qoe…" -> "application-layer". */
function runFamily(dir) {
  return path.basename(dir).replace(/-\d{8}T\d{6}.*$/, "");
}

function runLabels(result) {
  return new Set(result.transactions.map((tx) => tx.label));
}

/** Newest run produced by the CURRENT code: settles through the attested
 *  decision and contains no `declareHandle` transaction. */
function selectPrimaryRun(chainId) {
  for (const dir of listRunDirs()) {
    const result = loadJson(path.join(dir, "hardhat_dispute_result.json"));
    if (Number(result.chainId) !== Number(chainId)) continue;
    const labels = runLabels(result);
    if (labels.has("declareHandle")) continue;
    if (!labels.has("settleLeafViaAttestedDecision")) continue;
    return dir;
  }
  return null;
}

/**
 * A funded signer for C8's reconstruction of the deleted leaking route, from
 * the same key material the campaign configures (`VCFHE_PRIVATE_KEYS`, else
 * `VCFHE_MNEMONIC`). Null when neither is set, in which case C8 says so rather
 * than pretending the control ran.
 */
function leakProbeSigner(provider) {
  const keys = (process.env.VCFHE_PRIVATE_KEYS ?? "")
    .split(/[\s,]+/)
    .map((key) => key.trim())
    .filter(Boolean);
  if (keys.length > 0) return new ethers.Wallet(keys[0], provider);
  const mnemonic = process.env.VCFHE_MNEMONIC?.trim();
  if (!mnemonic) return null;
  return ethers.HDNodeWallet.fromPhrase(mnemonic, undefined, "m/44'/60'/0'/0/0").connect(provider);
}

/** Newest run on the same chain that still used `declareHandle` (C8). */
function selectLeakRun(chainId) {
  for (const dir of listRunDirs()) {
    const result = loadJson(path.join(dir, "hardhat_dispute_result.json"));
    if (Number(result.chainId) !== Number(chainId)) continue;
    if (runLabels(result).has("declareHandle")) return dir;
  }
  return null;
}

// ---------------------------------------------------------------------------
// compiled-artifact index (selector -> function, creation bytecode -> contract)
// ---------------------------------------------------------------------------

function loadCompiledArtifacts() {
  const dir = path.join(podRoot, "contracts", "out");
  const selectors = new Map();
  const constructors = new Map();
  const bytecodes = [];
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const artifact = loadJson(path.join(dir, file));
    if (!Array.isArray(artifact.abi)) continue;
    const iface = new ethers.Interface(artifact.abi);
    iface.forEachFunction((fragment) => {
      if (!selectors.has(fragment.selector)) {
        selectors.set(fragment.selector, { contract: artifact.contractName, fragment, iface });
      }
    });
    if (iface.deploy) constructors.set(artifact.contractName, iface.deploy);
    if (typeof artifact.bytecode === "string" && artifact.bytecode.length > 512) {
      bytecodes.push({
        name: artifact.contractName,
        bytecode: artifact.bytecode.toLowerCase().replace(/^0x/, "")
      });
    }
  }
  return { selectors, constructors, bytecodes };
}

// ---------------------------------------------------------------------------
// ABI-aware calldata model
// ---------------------------------------------------------------------------

/**
 * Flattens a decoded argument tree into typed leaves, keeping the path so a hit
 * can be named ("operatorLeaf.lhsHandle" rather than "word 3").
 */
function flattenDecoded(paramType, value, prefix, out) {
  const baseType = paramType.baseType;
  if (baseType === "array") {
    value.forEach((entry, index) => {
      flattenDecoded(paramType.arrayChildren, entry, `${prefix}[${index}]`, out);
    });
    return;
  }
  if (baseType === "tuple") {
    paramType.components.forEach((component, index) => {
      flattenDecoded(component, value[index], `${prefix}.${component.name || index}`, out);
    });
    return;
  }
  out.push({ path: prefix, type: paramType.type, value });
}

/**
 * Where a value could hide.
 *
 *   value       a field wide enough to carry an operand: bytes32 (the handle
 *               positions), uint64/uint256. A private operand here is a leak.
 *   structural  uint8/uint32/bool/address: opcode, leaf index, source kind,
 *               decision bit. Their domain is fixed by the protocol, so a small
 *               operand value colliding with one carries no information.
 *   bytes       an opaque blob (input proof, signature list, attestation
 *               payload) scanned separately, byte by byte.
 */
function classifyField(type) {
  if (type === "bytes") return "bytes";
  if (type === "string") return "structural";
  if (type === "bool" || type === "address") return "structural";
  const uintMatch = /^u?int(\d+)$/.exec(type);
  if (uintMatch) return Number(uintMatch[1]) >= 64 ? "value" : "structural";
  const bytesMatch = /^bytes(\d+)$/.exec(type);
  if (bytesMatch) return Number(bytesMatch[1]) >= 8 ? "value" : "structural";
  return "value";
}

function numericOf(type, value) {
  try {
    if (type === "bool") return value ? 1n : 0n;
    if (type === "address") return BigInt(value);
    if (type === "string" || type === "bytes") return null;
    if (/^bytes\d+$/.test(type)) return BigInt(value);
    if (/^u?int\d*$/.test(type)) return BigInt(value);
  } catch {
    return null;
  }
  return null;
}

/**
 * Decodes one transaction as far as the compiled ABIs allow and reports every
 * position that carries one of `targets`.
 */
/**
 * `decisionProof` = abi.encode(bytes[] signatures, bytes extraData), where
 * extraData is `leafDecisionBinding(taskId, leafIndex, opcode)`. Decoding it and
 * asking the deployed game to recompute the binding proves the blob is exactly
 * (signatures, protocol binding) and contains no free field.
 */
const LEAF_BINDING_TYPES = ["bytes32", "address", "uint256", "bytes32", "uint32", "uint8"];
const LEAF_BINDING_NAMES = ["bindingTag", "game", "chainId", "taskId", "leafIndex", "opcode"];

async function explainDecisionProof(proof, gameAddress, provider) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const [signatures, extraData] = coder.decode(["bytes[]", "bytes"], proof);
  const fields = coder.decode(LEAF_BINDING_TYPES, extraData);
  const gameAbi = loadJson(path.join(podRoot, "contracts", "out", "VerifiableFHEDisputeGame.json")).abi;
  const game = new ethers.Contract(gameAddress, gameAbi, provider);
  const recomputed = await game.leafDecisionBinding(fields[3], fields[4], fields[5]);
  return {
    signatures,
    extraData,
    fields,
    reproduced: String(recomputed).toLowerCase() === String(extraData).toLowerCase()
  };
}

function inspectTransaction(tx, targets, artifacts, invariantCalldata = null, explainedBlobs = null) {
  const data = (tx.data ?? "0x").toLowerCase();
  const hits = [];
  // A transaction whose exact calldata also occurs in a run of a DIFFERENT
  // workload cannot be a function of this workload's operands: the same bytes
  // are sent when those operands do not exist. Such hits are reported, never
  // counted (the opcode-surface sweep, which deliberately uses clear-value
  // handles over fixed sample triples, is the case that matters).
  const workloadInvariant = invariantCalldata ? invariantCalldata.has(data) : false;
  const record = (value, where, kind, detail) =>
    hits.push({
      value,
      where,
      kind: workloadInvariant ? "workload-invariant" : kind,
      detail,
      label: tx.label,
      hash: tx.hash
    });

  if (data.length <= 2) return { category: "no-calldata", hits, decoded: null };

  // --- contract creation: the calldata is compiler output plus constructor
  //     arguments. Matching it against the compiled artifact proves the code
  //     part is compiler output; the arguments are decoded and printed.
  if (tx.to === null) {
    const body = data.replace(/^0x/, "");
    const match = artifacts.bytecodes.find((entry) => body.startsWith(entry.bytecode));
    if (match) {
      const creation = body.slice(0, match.bytecode.length);
      const tail = body.slice(match.bytecode.length);
      for (const value of targets) {
        const inCreation = countOccurrences(creation, word32(value));
        if (inCreation > 0) {
          record(value, `creation bytecode of ${match.name}`, "compiled-bytecode", `${inCreation}x`);
        }
      }
      const constructorFragment = artifacts.constructors.get(match.name);
      if (constructorFragment && tail.length > 0) {
        try {
          const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
            constructorFragment.inputs,
            `0x${tail}`
          );
          const leaves = [];
          constructorFragment.inputs.forEach((input, index) => {
            flattenDecoded(input, decoded[index], `${match.name}(${input.name || index})`, leaves);
          });
          for (const leaf of leaves) {
            const numeric = numericOf(leaf.type, leaf.value);
            if (numeric !== null && targets.has(numeric)) {
              record(numeric, `${leaf.path} : ${leaf.type} = ${leaf.value}`, "constructor-arg", null);
            }
          }
        } catch {
          for (const value of targets) {
            const inTail = countOccurrences(tail, word32(value));
            if (inTail > 0) {
              record(value, `undecodable constructor arguments of ${match.name}`, "value", `${inTail}x`);
            }
          }
        }
      }
      return { category: `deployment:${match.name}`, hits, decoded: null };
    }
    // Unmatched creation code: be conservative, every word counts.
    const { words, role } = classifyWords(data);
    for (let i = 0; i < words.length; i += 1) {
      if (targets.has(words[i]) && role[i] === "payload") {
        record(words[i], `unmatched creation code word ${i}`, "value", null);
      }
    }
    return { category: "deployment:unmatched", hits, decoded: null };
  }

  const selector = data.slice(0, 10);
  const entry = artifacts.selectors.get(selector);
  if (!entry) {
    // Unknown selector: nothing attributes a word to structure, so every
    // payload word counts as a value position. This is what makes the negative
    // control (a deleted `declareHandle` entry point) fail loudly.
    const { words, role } = classifyWords(data);
    for (let i = 0; i < words.length; i += 1) {
      if (targets.has(words[i]) && role[i] === "payload") {
        record(words[i], `unknown selector ${selector} word ${i}`, "value", null);
      }
    }
    return { category: `unknown-selector:${selector}`, hits, decoded: null };
  }

  const decodedValues = entry.iface.decodeFunctionData(entry.fragment, data);
  const leaves = [];
  entry.fragment.inputs.forEach((input, index) => {
    flattenDecoded(input, decodedValues[index], input.name || `arg${index}`, leaves);
  });

  for (const leaf of leaves) {
    const kind = classifyField(leaf.type);
    if (kind === "bytes") {
      // An opaque blob is scanned as 32-byte ALIGNED words, with the same
      // offset/length classification used for calldata: a nested abi.encode
      // (the decision proof is abi.encode(bytes[] signatures, bytes extraData))
      // is full of small framing words that are not operands. Unaligned windows
      // are reported separately as an 8-byte probe.
      const hex = String(leaf.value).replace(/^0x/, "").toLowerCase();
      // A blob the protocol itself recomputes (the decision proof: t+1
      // signatures plus the binding the game derives from taskId/leafIndex/
      // opcode) has no free field: its words are structure by construction.
      const explanation = explainedBlobs?.get(hex) ?? null;
      const { words, role } = classifyWords(`0x00000000${hex}`);
      for (let i = 0; i < words.length; i += 1) {
        if (targets.has(words[i])) {
          record(
            words[i],
            `${leaf.path} (bytes) word ${i}${explanation ? ` = ${explanation}` : ""}`,
            explanation ? "structural" : role[i] === "payload" ? "value" : "structural",
            role[i]
          );
        }
      }
      for (const value of targets) {
        const narrow = countOccurrences(hex, word8(value));
        if (narrow > 0) {
          record(value, `${leaf.path} (bytes)`, "bytes-window", `${narrow}x 8-byte window`);
        }
      }
      continue;
    }
    const numeric = numericOf(leaf.type, leaf.value);
    if (numeric === null) continue;
    if (targets.has(numeric)) {
      record(numeric, `${leaf.path} : ${leaf.type}`, kind === "value" ? "value" : "structural", null);
    }
  }

  return {
    category: `${entry.contract}.${entry.fragment.name}`,
    hits,
    decoded: { entry, decodedValues, leaves }
  };
}

/**
 * A private operand of 256 or more is DISTINGUISHABLE: no protocol field
 * (opcode, source kind, decision bit) has such a value by construction, so any
 * occurrence anywhere is a leak. A smaller value collides with structure
 * routinely, so for those only value-carrying positions count, and the
 * structural collisions are reported instead of hidden.
 */
const DISTINGUISHABLE_MIN = 256n;

/**
 * Which of a value's occurrences count as a leak.
 *
 *   value              a field wide enough to hold an operand, an opaque bytes
 *                      payload, or a word of a call nobody can attribute to a
 *                      known ABI: always a leak
 *   constructor-arg    a decoded deployment parameter (a window, a threshold,
 *                      an address): a leak only if the value is large enough
 *                      that no such parameter could have it
 *   structural         uint8/uint32/bool/address field (opcode, leaf index,
 *                      source index, decision bit): same rule
 *   bytes-window       an 8-byte window inside an opaque blob: same rule
 *   compiled-bytecode  inside creation code that matches the compiled artifact
 *   workload-invariant identical calldata occurs in a different-workload run
 */
function verdictForValue(value, hits) {
  const distinguishable = value >= DISTINGUISHABLE_MIN;
  return hits.filter((hit) => {
    switch (hit.kind) {
      case "value":
        return true;
      case "constructor-arg":
      case "structural":
      case "bytes-window":
        return distinguishable;
      case "compiled-bytecode":
      case "workload-invariant":
      default:
        return false;
    }
  });
}

// ---------------------------------------------------------------------------
// workload operands
// ---------------------------------------------------------------------------

const PUBLIC_SCALAR_OPCODES = new Set([...PUBLIC_SCALAR_RHS_OPCODES, "CAST_U8"]);

/**
 * Private operands (and declared public scalars) of the workload a run
 * committed, read from the run's own micro-trace bundle.
 */
function runOperandSets(runDir) {
  const bundle = loadJson(path.join(runDir, "micro_trace_bundle.json"));
  const result = loadJson(path.join(runDir, "hardhat_dispute_result.json"));
  const priv = new Set();
  const pub = new Set();
  for (const witness of bundle.witnesses ?? []) {
    const opcode = witness.opcode_name;
    for (const side of ["lhs", "rhs"]) {
      const ref = witness[`${side}Ref`];
      const isPublic = ref ? ref.kind === "constant" : side === "rhs" && PUBLIC_SCALAR_OPCODES.has(opcode);
      (isPublic ? pub : priv).add(BigInt(witness[side]));
    }
    priv.add(BigInt(witness.claimed));
  }
  for (const leaf of [result.honestLeaf, result.dishonestLeaf]) {
    if (leaf && leaf.claimed !== undefined) priv.add(BigInt(leaf.claimed));
  }
  // A value used BOTH as a public scalar and as a private operand cannot be
  // attributed, so it is counted as public (the conservative direction for the
  // audit is to report it, never to silently pass a private one).
  const overlap = [...priv].filter((value) => pub.has(value));
  for (const value of overlap) priv.delete(value);
  // The operand value ZERO is not auditable by scanning: every empty bytes32,
  // every unused index and every zero-padded field equals it. It is reported
  // and excluded rather than counted, because counting it would drown the
  // audit in occurrences that carry no information.
  const zeroOperand = priv.delete(0n);
  return { bundle, result, priv, pub, overlap: new Set(overlap), zeroOperand };
}

// ---------------------------------------------------------------------------
// transaction fetching (by hash, from the node)
// ---------------------------------------------------------------------------

const txCache = new Map();

async function fetchRun(runDir, provider) {
  if (txCache.has(runDir)) return txCache.get(runDir);
  const result = loadJson(path.join(runDir, "hardhat_dispute_result.json"));
  const transactions = [];
  const logs = [];
  for (const entry of result.transactions) {
    const tx = await provider.getTransaction(entry.hash);
    if (!tx) throw new Error(`node does not know transaction ${entry.hash} (${entry.label})`);
    transactions.push({
      label: entry.label,
      hash: entry.hash,
      data: (tx.data ?? "0x").toLowerCase(),
      to: tx.to ?? null,
      blockNumber: tx.blockNumber
    });
    // Events are the other channel a value could escape through, so they are
    // fetched with the transaction and scanned alongside its calldata.
    const receipt = await provider.getTransactionReceipt(entry.hash);
    for (const log of receipt?.logs ?? []) {
      logs.push({
        label: entry.label,
        hash: entry.hash,
        address: log.address,
        topics: log.topics.map((topic) => topic.toLowerCase()),
        data: (log.data ?? "0x").toLowerCase()
      });
    }
  }
  const bundle = { runDir, result, transactions, logs };
  txCache.set(runDir, bundle);
  return bundle;
}

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------

const checks = [];
const defineCheck = (id, title, assertion, run) => checks.push({ id, title, assertion, run });

// --- C1 ---------------------------------------------------------------------
defineCheck(
  "C1",
  "Handles commit to real TFHE ciphertexts, not to values",
  "for sampled operands: keccak256(stored ciphertext file) == manifest handle, the file safe-deserializes as a tfhe-rs 1.4 FheUint64, and the stored client key decrypts it to the manifest's declared clear value",
  async (ctx) => {
    const evidence = [];
    const keysDir = path.join(options.ciphertextDir, "keys");
    const serverKeyPath = path.join(keysDir, "server-key.bin");
    const clientKeyPath = path.join(keysDir, "client-key.bin");

    const serverKeyDigest = ethers.keccak256(fs.readFileSync(serverKeyPath));
    const keyDigestOk = serverKeyDigest.toLowerCase() === String(ctx.manifest.keyDigest).toLowerCase();
    evidence.push(
      `stored server key ${fmt(fs.statSync(serverKeyPath).size)} B, keccak256 ${short(serverKeyDigest)} ` +
        `${keyDigestOk ? "==" : "!="} manifest.keyDigest ${short(ctx.manifest.keyDigest)}`
    );

    let ok = keyDigestOk;
    let sampledTotal = 0;
    let availableTotal = 0;
    for (const entry of ctx.manifestWorkloads) {
      const sampled = entry.inputs.slice(0, Math.max(1, options.sample));
      const paths = sampled.map((input) =>
        path.join(options.ciphertextDir, entry.workloadId, `input-${input.leafIndex}-${input.side}.ct`)
      );
      const inspectArgs = ["inspect", "--client-key", clientKeyPath];
      for (const file of paths) inspectArgs.push("--ct", file);
      const inspected = ctInspect(inspectArgs);
      sampledTotal += sampled.length;
      availableTotal += entry.inputs.length;

      let workloadOk = true;
      sampled.forEach((input, index) => {
        const file = paths[index];
        const bytes = fs.readFileSync(file);
        const digest = ethers.keccak256(bytes);
        const item = inspected.items[index];
        const sizeOk = bytes.length === input.bytes && bytes.length > 100_000;
        const digestOk = digest.toLowerCase() === input.handle.toLowerCase();
        const decryptOk = String(item.decrypted) === String(input.clear);
        const roundTripOk = item.reserializeIdentical === true;
        // The 32-byte big-endian encoding of the clear value must not sit inside
        // the ciphertext either: that is what a fake "ciphertext" would look like.
        const plaintextWords = countOccurrences(bytes.toString("hex"), word32(input.clear));
        const plaintextNarrow = countOccurrences(bytes.toString("hex"), word8(input.clear));
        const good = sizeOk && digestOk && decryptOk && roundTripOk && plaintextWords === 0;
        if (!good) {
          ok = false;
          workloadOk = false;
        }
        // Per-operand lines only for the first workload and for any failure:
        // eleven workloads times eight operands would bury the result.
        if (!good || ctx.manifestWorkloads.length === 1 || entry === ctx.manifestWorkloads[0]) {
          evidence.push(
            `${good ? "ok " : "BAD"} ${entry.workloadId} leaf ${input.leafIndex} ${input.side}: ` +
              `${fmt(bytes.length)} B (${(bytes.length / 1024).toFixed(1)} kB, ` +
              `${Math.round(bytes.length / 32)}x a 32-byte word), keccak256=${short(digest)} ` +
              `${digestOk ? "==" : "!="} handle, deserialized as ${item.deserializedAs}, ` +
              `decrypt=${item.decrypted} vs clear=${input.clear}, reserialize-identical=${roundTripOk}, ` +
              `32-byte-encoding-of-clear-inside-ciphertext=${plaintextWords}` +
              (plaintextNarrow > 0 ? ` (8-byte windows: ${plaintextNarrow})` : "")
          );
        }
      });
      if (entry !== ctx.manifestWorkloads[0]) {
        evidence.push(
          `${workloadOk ? "ok " : "BAD"} ${entry.workloadId}: ${sampled.length} of ` +
            `${entry.inputs.length} input operands sampled, all deserialized as FheUint64, ` +
            `hashed to their committed handle and decrypted to the declared clear value`
        );
      }
    }
    evidence.push(
      `sampled ${sampledTotal} of ${availableTotal} input operands across ` +
        `${ctx.manifestWorkloads.length} workload(s): ` +
        ctx.manifestWorkloads.map((entry) => entry.workloadId).join(", ")
    );
    return { pass: ok, evidence };
  }
);

// --- C2 ---------------------------------------------------------------------
defineCheck(
  "C2",
  "A handle is not the plaintext",
  "for every input operand and every leaf result of every workload in the manifest: BigInt(handle) != BigInt(clear), and every handle exceeds 2^64 (so it cannot be the 32-byte big-endian encoding of any uint64 operand)",
  async (ctx) => {
    const evidence = [];
    let operands = 0;
    let results = 0;
    let equalToClear = 0;
    let smallHandles = 0;
    const offenders = [];
    for (const workload of ctx.manifest.workloads) {
      for (const input of workload.inputs ?? []) {
        operands += 1;
        const handle = BigInt(input.handle);
        if (handle === BigInt(input.clear)) {
          equalToClear += 1;
          offenders.push(`${workload.workloadId} leaf ${input.leafIndex} ${input.side} handle == clear`);
        }
        if (handle < 2n ** 64n) {
          smallHandles += 1;
          offenders.push(`${workload.workloadId} leaf ${input.leafIndex} ${input.side} handle < 2^64`);
        }
      }
      for (const leaf of workload.leaves ?? []) {
        results += 1;
        const handle = BigInt(leaf.resultHandle);
        if (handle === BigInt(leaf.claimed)) {
          equalToClear += 1;
          offenders.push(`${workload.workloadId} leaf ${leaf.index} resultHandle == claimed`);
        }
        if (handle < 2n ** 64n) {
          smallHandles += 1;
          offenders.push(`${workload.workloadId} leaf ${leaf.index} resultHandle < 2^64`);
        }
      }
    }
    evidence.push(
      `${operands} input operands + ${results} leaf results = ${operands + results} handles checked ` +
        `across ${ctx.manifest.workloads.length} manifest workloads`
    );
    evidence.push(`handles numerically equal to their clear value: ${equalToClear}`);
    evidence.push(`handles below 2^64 (i.e. shaped like ciphertextHandleForClear): ${smallHandles}`);
    const sample = ctx.manifestWorkload.inputs[0];
    evidence.push(
      `e.g. ${ctx.manifestWorkload.workloadId} leaf ${sample.leafIndex} ${sample.side}: ` +
        `clear=${sample.clear} handle=${sample.handle}`
    );
    for (const offender of offenders.slice(0, 5)) evidence.push(`BAD ${offender}`);
    return { pass: equalToClear === 0 && smallHandles === 0 && operands + results > 0, evidence };
  }
);

// --- C3 ---------------------------------------------------------------------
defineCheck(
  "C3",
  "Every leaf was executed homomorphically and agrees with the lowering",
  "every leaf of every manifest workload has ok === true and decrypted === claimed",
  async (ctx) => {
    const evidence = [];
    const histogram = new Map();
    let leaves = 0;
    let bad = 0;
    for (const workload of ctx.manifest.workloads) {
      for (const leaf of workload.leaves ?? []) {
        leaves += 1;
        histogram.set(leaf.opcode, (histogram.get(leaf.opcode) ?? 0) + 1);
        if (leaf.ok !== true || String(leaf.decrypted) !== String(leaf.claimed)) {
          bad += 1;
          if (bad <= 5) {
            evidence.push(
              `BAD ${workload.workloadId} leaf ${leaf.index} ${leaf.opcode}: ok=${leaf.ok} ` +
                `decrypted=${leaf.decrypted} claimed=${leaf.claimed}`
            );
          }
        }
      }
    }
    evidence.push(
      `${leaves} leaves over ${ctx.manifest.workloads.length} workloads (manifest totalLeaves=${ctx.manifest.totalLeaves}), ` +
        `mismatches: ${bad}`
    );
    evidence.push(
      `opcode histogram actually executed over ciphertexts: ` +
        [...histogram.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([opcode, count]) => `${opcode}=${count}`)
          .join(" ")
    );
    evidence.push(
      `tfhe ${ctx.manifest.tfheVersion}, ${ctx.manifest.integerWidth}-bit integers, ` +
        `total FHE time ${fmt(ctx.manifest.totalFheMs)} ms for those leaves`
    );
    return { pass: leaves > 0 && bad === 0 && leaves === ctx.manifest.totalLeaves, evidence };
  }
);

// --- C4 ---------------------------------------------------------------------
defineCheck(
  "C4",
  "An auditor re-executing the workload reaches the same DECISION on every leaf",
  "re-executing the workload from the SAME stored input ciphertexts and the published server key, once per independent process and with the machine under CPU load, agrees with the committed result of every leaf under FHE.eq — the comparison the protocol makes — in every replay. Ciphertext BYTES are reported alongside and are NOT required to match: they are not reproducible across evaluation schedules, which is why the settlement rule is homomorphic equality and not byte equality",
  async (ctx) => {
    const evidence = [];
    let pass = true;
    let decisionAgreementsAll = 0;
    let byteMatchesAll = 0;
    let observationsAll = 0;
    let controlsRun = 0;

    // Load enough cores to perturb the evaluation schedule. Byte divergence is
    // a race; a check that only ever runs on an idle machine would report a
    // reproducibility that does not hold in practice. One load generator covers
    // every workload, so the machine stays contended throughout.
    const load = startCpuLoad(options.load);
    try {
      for (const entry of ctx.manifestWorkloads) {
        const replays = [];
        for (let i = 0; i < options.replays; i += 1) {
          replays.push(
            replayWithDecisions({
              ciphertextDir: options.ciphertextDir,
              tracesPath: options.tracesPath,
              workloadId: entry.workloadId,
              decide: true
            })
          );
        }

        const first = replays[0];
        let decisionAgreements = 0;
        let byteMatches = 0;
        let valueMatches = 0;
        const totalObservations = replays.length * first.leaves.length;
        const offenders = [];

        first.leaves.forEach((leaf, index) => {
          const committed = entry.leaves[index];
          const observed = replays.map((replay) => replay.leaves[index]);
          const agreeing = observed.filter((l) => l.decisionBit === true).length;
          const bytesEqual = observed.filter(
            (l) =>
              String(l.resultHandle).toLowerCase() === String(committed.resultHandle).toLowerCase()
          ).length;
          const values = new Set(observed.map((l) => String(l.decrypted)));
          const valueOk = values.size === 1 && values.has(String(committed.claimed));

          decisionAgreements += agreeing;
          byteMatches += bytesEqual;
          if (valueOk) valueMatches += 1;
          if (agreeing !== observed.length || !valueOk) {
            offenders.push(
              `BAD ${entry.workloadId} leaf ${leaf.index} ${leaf.opcode}: FHE.eq true in ` +
                `${agreeing}/${observed.length} replays, decrypted ${[...values].join("/")} vs ` +
                `claimed ${committed.claimed}`
            );
          }
        });

        decisionAgreementsAll += decisionAgreements;
        byteMatchesAll += byteMatches;
        observationsAll += totalObservations;

        const workloadOk =
          first.leaves.length > 0 &&
          decisionAgreements === totalObservations &&
          valueMatches === first.leaves.length;
        if (!workloadOk) pass = false;

        evidence.push(
          `${workloadOk ? "ok " : "BAD"} ${entry.workloadId}: ${first.leaves.length} leaves x ` +
            `${replays.length} independent processes under ${load.count} busy cores — ` +
            `DECISION ${decisionAgreements}/${totalObservations} agree under FHE.eq, ` +
            `BYTES ${byteMatches}/${totalObservations} reproduced (not required), ` +
            `VALUES ${valueMatches}/${first.leaves.length} decrypt to the claimed value`
        );
        for (const line of offenders.slice(0, 5)) evidence.push(`    ${line}`);

        // A decision check that always said "true" would pass vacuously.
        // Adjudicate one leaf the way `settleLeafViaAttestedDecision` gets its
        // bits, with a claim that is genuinely wrong, and require rejection.
        const corruptedKey = `${entry.workloadId}#corrupted`;
        const corrupted = ctx.manifest.workloads.find((w) => w.workloadId === corruptedKey);
        const traceWorkload = ctx.traceWorkloads.get(entry.workloadId);
        if (corrupted) {
          const disputed = entry.leaves.findIndex(
            (leaf, index) => String(leaf.claimed) !== String(corrupted.leaves[index]?.claimed)
          );
          if (disputed >= 0) {
            const decision = decideLeaf({
              ciphertextDir: options.ciphertextDir,
              manifest: ctx.manifest,
              referenceKey: entry.workloadId,
              leafIndex: disputed,
              rhsScalar: Number(traceWorkload?.leaves?.[disputed]?.rhs ?? 0),
              claims: [
                {
                  label: "challenger",
                  ciphertextPath: resultCiphertextPath(
                    options.ciphertextDir,
                    entry.workloadId,
                    disputed
                  ),
                  expectedHandle: entry.leaves[disputed].resultHandle
                },
                {
                  label: "operator",
                  ciphertextPath: resultCiphertextPath(options.ciphertextDir, corruptedKey, disputed),
                  expectedHandle: corrupted.leaves[disputed].resultHandle
                }
              ]
            });
            const separated =
              decision.byLabel.challenger === true && decision.byLabel.operator === false;
            if (!separated) pass = false;
            controlsRun += 1;
            evidence.push(
              `    ${separated ? "ok " : "BAD"} negative control, leaf ${disputed} ` +
                `(${decision.opcode}) adjudicated as the settlement does: honest claim valid=` +
                `${decision.byLabel.challenger}, corrupted claim valid=${decision.byLabel.operator}; ` +
                `the recomputation's own bytes ${
                  String(decision.recomputedHandle).toLowerCase() ===
                  String(entry.leaves[disputed].resultHandle).toLowerCase()
                    ? "matched"
                    : "did NOT match"
                } the committed result handle`
            );
          }
        }
      }
    } finally {
      load.stop();
    }

    evidence.push(
      `TOTAL over ${ctx.manifestWorkloads.length} workload(s): DECISION ` +
        `${decisionAgreementsAll}/${observationsAll} replayed leaves agreed with the committed result ` +
        `under FHE.eq; BYTES ${byteMatchesAll}/${observationsAll} reproduced the committed handle; ` +
        `${controlsRun} corrupted-claim control(s) rejected as they must be`
    );

    if (byteMatchesAll < observationsAll) {
      evidence.push(
        `${observationsAll - byteMatchesAll} of ${observationsAll} replayed leaves produced a DIFFERENT ` +
          "result ciphertext from the committed one while deciding identically. This is the measurement " +
          "that rules out settling a leaf by comparing handles: the same operation, the same operand " +
          "ciphertexts and the same server key, re-executed in another process, yield different bytes. " +
          "A byte comparison would have rejected a correct execution."
      );
    } else {
      evidence.push(
        "every replay also happened to reproduce the committed bytes in this run. That is not something " +
          "the protocol may rely on: divergence is a scheduling race (observed in this repository under " +
          "load, see scripts/leaf-decision-stability.test.mjs), so the settlement rule stays homomorphic " +
          "equality."
      );
    }

    return { pass: pass && observationsAll > 0, evidence };
  }
);

// --- C5 ---------------------------------------------------------------------
defineCheck(
  "C5",
  "Ciphertexts are not decryptable from chain data alone",
  "no transaction calldata of the run contains any 32-byte probe taken from the stored client key or server key, and the run's entire calldata is smaller than a single ciphertext",
  async (ctx) => {
    const evidence = [];
    const keysDir = path.join(options.ciphertextDir, "keys");
    const probes = [];
    // A 32-byte window of a key file is only a usable probe if it is
    // high-entropy: the trailing padding of a serialized key is mostly zeros and
    // matches any zero-padded ABI word, which would say nothing about leakage.
    // The first 32 bytes are probed regardless (that is the tfhe
    // safe-serialization header, shared by every ciphertext file, so its absence
    // also rules out a ciphertext body in calldata).
    const distinctBytes = (buffer) => new Set(buffer).size;
    for (const [name, file] of [
      ["client-key", path.join(keysDir, "client-key.bin")],
      ["server-key", path.join(keysDir, "server-key.bin")]
    ]) {
      const bytes = fs.readFileSync(file);
      probes.push({
        name: `${name}[0..32] (tfhe serialization header)`,
        hex: bytes.subarray(0, 32).toString("hex"),
        size: bytes.length
      });
      let taken = 0;
      for (let fraction = 1; fraction < 20 && taken < 3; fraction += 1) {
        const offset = Math.floor((bytes.length * fraction) / 20);
        const window = bytes.subarray(offset, offset + 32);
        if (window.length < 32 || distinctBytes(window) < 20) continue;
        taken += 1;
        probes.push({
          name: `${name}[${offset}..+32] (${distinctBytes(window)} distinct bytes)`,
          hex: window.toString("hex"),
          size: bytes.length
        });
      }
      if (taken === 0) {
        evidence.push(
          `${name}: no high-entropy 32-byte window exists (the secret key body is a binary/ternary ` +
            `secret, so its bytes are mostly 0x00/0x01); only the header probe is meaningful for it`
        );
      }
    }

    const { transactions } = await fetchRun(ctx.primaryRun, ctx.provider);
    const allCalldata = transactions.map((tx) => tx.data.replace(/^0x/, "")).join("");
    let found = 0;
    for (const probe of probes) {
      const occurrences = countOccurrences(allCalldata, probe.hex);
      if (occurrences > 0) found += occurrences;
      evidence.push(
        `probe ${probe.name} = ${probe.hex.slice(0, 24)}… : ${occurrences} occurrence(s) in ${fmt(transactions.length)} transactions`
      );
    }

    const calldataBytes = allCalldata.length / 2;
    const oneCiphertext = ctx.manifestWorkload.inputs[0].bytes;
    const ratio = oneCiphertext / calldataBytes;
    evidence.push(
      `total calldata of the run: ${fmt(calldataBytes)} B (including ${fmt(
        transactions.filter((tx) => tx.to === null).length
      )} contract deployments); one FheUint64 ciphertext: ${fmt(oneCiphertext)} B (${ratio.toFixed(1)}x larger)`
    );
    const nonDeploy = transactions
      .filter((tx) => tx.to !== null)
      .reduce((sum, tx) => sum + (tx.data.length - 2) / 2, 0);
    evidence.push(
      `calldata excluding deployments: ${fmt(nonDeploy)} B = ${(nonDeploy / oneCiphertext).toFixed(3)} ciphertexts; ` +
        `largest single transaction: ${fmt(
          Math.max(...transactions.map((tx) => (tx.data.length - 2) / 2))
        )} B`
    );
    evidence.push(
      `server key ${fmt(probes[3].size)} B and client key ${fmt(probes[0].size)} B never appear: ` +
        `decryption from chain data alone is impossible because the chain holds neither key nor any ciphertext body`
    );
    return { pass: found === 0 && calldataBytes < oneCiphertext, evidence };
  }
);

// --- C6 ---------------------------------------------------------------------
defineCheck(
  "C6",
  "No private operand value in any calldata or event",
  "for every transaction of the audited runs, fetched by hash: no private operand of the workload appears in a value-carrying position (bytes32/uint64/uint256 field, opaque bytes payload, unknown-selector payload word, constructor argument) nor in any emitted event's topics or data; declared public scalars are reported separately",
  async (ctx) => {
    const evidence = [];
    let pass = true;
    for (const runDir of ctx.auditRuns) {
      const { result, transactions, logs } = await fetchRun(runDir, ctx.provider);
      const { bundle, priv, pub, overlap, zeroOperand } = runOperandSets(runDir);
      const targets = new Set([...priv, ...pub]);
      const distinguishable = [...priv].filter((value) => value >= DISTINGUISHABLE_MIN);
      const small = [...priv].filter((value) => value < DISTINGUISHABLE_MIN);

      // Calldata of the audited runs that ran a DIFFERENT workload: identical
      // bytes there mean the transaction does not depend on this workload.
      const invariantCalldata = new Set();
      for (const otherDir of ctx.auditRuns) {
        if (otherDir === runDir) continue;
        const other = runOperandSets(otherDir);
        if (other.bundle.workload === bundle.workload) continue;
        for (const tx of (await fetchRun(otherDir, ctx.provider)).transactions) {
          invariantCalldata.add(tx.data);
        }
      }

      // The decision proof of this run, verified against the game's own
      // leafDecisionBinding view, so its words can be named instead of guessed.
      const explainedBlobs = new Map();
      const settleTx = transactions.find((tx) => tx.label === "settleLeafViaAttestedDecision");
      if (settleTx) {
        const settle = inspectTransaction(settleTx, new Set(), ctx.artifacts);
        const proof = settle.decoded.decodedValues[5];
        const explained = await explainDecisionProof(proof, result.contractAddress, ctx.provider);
        if (explained.reproduced) {
          explainedBlobs.set(
            String(proof).replace(/^0x/, "").toLowerCase(),
            `signatures + leafDecisionBinding(taskId, leafIndex=${explained.fields[4]}, opcode=${explained.fields[5]}) ` +
              `recomputed by the deployed game`
          );
        }
      }

      const perValue = new Map([...targets].map((value) => [value, []]));
      const categories = new Map();
      let invariantTxs = 0;
      for (const tx of transactions) {
        const inspected = inspectTransaction(tx, targets, ctx.artifacts, invariantCalldata, explainedBlobs);
        if (invariantCalldata.has(tx.data)) invariantTxs += 1;
        categories.set(inspected.category, (categories.get(inspected.category) ?? 0) + 1);
        for (const hit of inspected.hits) perValue.get(hit.value).push(hit);
      }

      // Blunt instrument, unchanged: raw 32-byte word scan of the same runs.
      const raw = scanTransactionsForValues(transactions, [...targets]);

      let leaks = 0;
      const leakLines = [];
      const structuralLines = [];
      const publicLines = [];
      for (const value of [...targets].sort((a, b) => (a < b ? -1 : 1))) {
        const hits = perValue.get(value) ?? [];
        const isPublic = pub.has(value);
        if (isPublic) {
          if (hits.length > 0) {
            const where = [...new Set(hits.map((hit) => hit.where))].slice(0, 3).join(", ");
            publicLines.push(
              `  public scalar ${value}: ${hits.length} occurrence(s) [${where}] — expected: its ` +
                `SOURCE_PUBLIC_CONSTANT handle IS the 32-byte encoding of the value`
            );
          } else {
            publicLines.push(`  public scalar ${value}: 0 occurrences`);
          }
          continue;
        }
        const leaking = verdictForValue(value, hits);
        if (leaking.length > 0) {
          leaks += leaking.length;
          const example = leaking[0];
          leakLines.push(
            `  LEAK private operand ${value}: ${leaking.length} occurrence(s), e.g. ${example.label} ` +
              `-> ${example.where} (tx ${example.hash})`
          );
        } else if (hits.length > 0) {
          const byWhere = new Map();
          for (const hit of hits) {
            const key = `${hit.kind}:${hit.where.replace(/\[\d+\]/g, "[]")}`;
            byWhere.set(key, (byWhere.get(key) ?? 0) + 1);
          }
          structuralLines.push(
            `  small operand ${value}: ${hits.length} structural collision(s) — ` +
              [...byWhere.entries()]
                .sort((a, b) => b[1] - a[1])
                .slice(0, 4)
                .map(([key, count]) => `${count}x ${key}`)
                .join(", ")
          );
        }
      }

      const rawPayloadDistinguishable = distinguishable.reduce(
        (sum, value) => sum + (raw.perValue.get(value)?.payload ?? 0),
        0
      );

      // Events: indexed arguments live in topics, the rest in 32-byte words of
      // `data`. A distinguishable operand in either is a leak; small values
      // collide with leaf indices and opcodes exactly as in calldata.
      let eventWords = 0;
      const eventHits = new Map();
      for (const log of logs) {
        const words = [...log.topics.slice(1)];
        for (let i = 0; i < (log.data.length - 2) / 64; i += 1) {
          words.push(`0x${log.data.slice(2 + i * 64, 2 + (i + 1) * 64)}`);
        }
        eventWords += words.length;
        for (const word of words) {
          const value = BigInt(word);
          if (!targets.has(value)) continue;
          if (!eventHits.has(value)) eventHits.set(value, []);
          eventHits.get(value).push(log.label);
        }
      }
      const eventLeaks = [...eventHits.entries()].filter(
        ([value]) => value >= DISTINGUISHABLE_MIN && !pub.has(value)
      );
      evidence.push(
        `  events: ${fmt(logs.length)} logs, ${fmt(eventWords)} words (topics + data) scanned; ` +
          `${eventLeaks.length} distinguishable private operand(s) present; ` +
          `${[...eventHits.keys()].filter((value) => pub.has(value)).length} declared public scalar(s) and ` +
          `${[...eventHits.keys()].filter((value) => !pub.has(value) && value < DISTINGUISHABLE_MIN).length} ` +
          `small value(s) collide with event fields`
      );
      for (const [value, labels] of eventLeaks) {
        evidence.push(`  LEAK-IN-EVENT private operand ${value} in ${[...new Set(labels)].join(", ")}`);
      }
      if (eventLeaks.length > 0) pass = false;

      evidence.push(
        `run ${path.basename(runDir)} — workload ${bundle.workload}, chainId ${result.chainId}, ` +
          `${transactions.length} transactions fetched by hash, ${fmt(raw.totalWords)} calldata words scanned`
      );
      evidence.push(
        `  operands: ${priv.size} private (${distinguishable.length} distinguishable >= 256, ` +
          `${small.length} small < 256), ${pub.size} declared public scalars` +
          (overlap.size > 0
            ? `, ${overlap.size} value(s) counted as public because they are also used as a public scalar`
            : "") +
          (zeroOperand ? ", operand value 0 excluded (indistinguishable from any zero field)" : "")
      );
      evidence.push(
        `  raw 32-byte word scan: ${rawPayloadDistinguishable} payload-word occurrence(s) of the ` +
          `${distinguishable.length} distinguishable private operands ` +
          `(${distinguishable.slice(0, 8).join(", ")}${distinguishable.length > 8 ? ", …" : ""})`
      );
      evidence.push(
        `  ABI-aware scan: ${leaks} occurrence(s) in value-carrying positions; ${invariantTxs} of ` +
          `${transactions.length} transactions have byte-identical calldata in a different-workload run ` +
          `(so cannot encode this workload's operands); transaction kinds: ` +
          [...categories.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 6)
            .map(([name, count]) => `${count}x ${name}`)
            .join(", ")
      );
      for (const line of leakLines) evidence.push(line);
      for (const line of publicLines.slice(0, 8)) evidence.push(line);
      for (const line of structuralLines.slice(0, 8)) evidence.push(line);
      if (structuralLines.length > 8) {
        evidence.push(`  … ${structuralLines.length - 8} further small-operand collision line(s) omitted`);
      }
      if (leaks > 0 || rawPayloadDistinguishable > 0) pass = false;
    }
    return { pass, evidence };
  }
);

// --- C7 ---------------------------------------------------------------------
defineCheck(
  "C7",
  "The settlement carries only handles, a bit and signatures",
  "the settleLeafViaAttestedDecision transaction decodes to bytes32 handles, a uint8 opcode, bools and bytes only; no decoded field carries an operand value; the handles are exactly the ciphertext handles of the manifest; the proof carries t+1 signatures of registered KMS cores",
  async (ctx) => {
    const evidence = [];
    const { result, transactions } = await fetchRun(ctx.primaryRun, ctx.provider);
    const tx = transactions.find((entry) => entry.label === "settleLeafViaAttestedDecision");
    if (!tx) throw new Error("run has no settleLeafViaAttestedDecision transaction");
    const inspected = inspectTransaction(tx, new Set(), ctx.artifacts);
    const { entry, decodedValues, leaves } = inspected.decoded;
    evidence.push(`tx ${tx.hash} -> ${entry.contract}.${entry.fragment.name} (${(tx.data.length - 10) / 2} B calldata)`);

    let pass = true;
    const allowed = new Set(["bytes32", "uint8", "uint32", "bool", "bytes"]);
    for (const leaf of leaves) {
      const printable =
        leaf.type === "bytes" ? `${String(leaf.value).slice(0, 26)}… (${(String(leaf.value).length - 2) / 2} B)` : String(leaf.value);
      const typeOk = allowed.has(leaf.type);
      if (!typeOk) pass = false;
      evidence.push(`  ${typeOk ? " " : "!"} ${leaf.path} : ${leaf.type} = ${printable}`);
    }

    // The proof blob: abi.encode(bytes[] signatures, bytes extraData), with
    // extraData recomputed by the deployed game from (taskId, leafIndex,
    // opcode). Verifying that recomputation is what lets its words be named
    // instead of guessed at when scanning for operands.
    const decisionProof = decodedValues[5];
    const explained = await explainDecisionProof(decisionProof, result.contractAddress, ctx.provider);
    const explainedBlobs = new Map();
    if (explained.reproduced) {
      explainedBlobs.set(
        String(decisionProof).replace(/^0x/, "").toLowerCase(),
        `leafDecisionBinding(taskId, leafIndex=${explained.fields[4]}, opcode=${explained.fields[5]})`
      );
    } else {
      pass = false;
      evidence.push("  BAD the decision proof's extraData is NOT the binding the game recomputes");
    }
    evidence.push(
      `  decisionProof = abi.encode(bytes[] signatures, bytes extraData); extraData == ` +
        `game.leafDecisionBinding(taskId, leafIndex=${explained.fields[4]}, opcode=${explained.fields[5]}) ` +
        `recomputed on chain: ${explained.reproduced} — its words are ` +
        `(${LEAF_BINDING_NAMES.join(", ")}) = (${short(explained.fields[0])}, ${short(explained.fields[1])}, ` +
        `${explained.fields[2]}, ${short(explained.fields[3])}, ${explained.fields[4]}, ${explained.fields[5]})`
    );

    // No operand-valued field: reuse the private operand set of this run.
    const { priv } = runOperandSets(ctx.primaryRun);
    const operandHits = inspectTransaction(tx, priv, ctx.artifacts, null, explainedBlobs).hits;
    const realHits = operandHits.filter((hit) => verdictForValue(hit.value, [hit]).length > 0);
    evidence.push(
      `  operand-valued fields: ${realHits.length} (searched ${priv.size} private operand values ` +
        `over every decoded field and inside the proof bytes)`
    );
    for (const hit of realHits.slice(0, 4)) {
      pass = false;
      evidence.push(`  LEAK ${hit.value} at ${hit.where}`);
    }

    // The handles must be the manifest's ciphertext handles, not encodings of
    // anything: this is what ties the settlement to the TFHE artifacts.
    const operatorLeaf = decodedValues[1];
    const challengerLeaf = decodedValues[2];
    const manifestHandles = new Set();
    for (const workload of ctx.manifest.workloads) {
      for (const input of workload.inputs ?? []) manifestHandles.add(input.handle.toLowerCase());
      for (const leaf of workload.leaves ?? []) manifestHandles.add(leaf.resultHandle.toLowerCase());
    }
    const settledHandles = [
      ["operatorLeaf.lhsHandle", operatorLeaf[1]],
      ["operatorLeaf.rhsHandle", operatorLeaf[2]],
      ["operatorLeaf.claimedHandle", operatorLeaf[3]],
      ["challengerLeaf.claimedHandle", challengerLeaf[3]]
    ];
    for (const [name, handle] of settledHandles) {
      const known = manifestHandles.has(String(handle).toLowerCase());
      const isClearEncoding = BigInt(handle) < 2n ** 64n;
      if (!known || isClearEncoding) pass = false;
      evidence.push(
        `  ${name} ${short(handle)}: in ciphertext manifest = ${known}, below 2^64 = ${isClearEncoding}`
      );
    }

    const { signatures, extraData } = explained;
    const attestation = result.leafDecisionAttestation ?? {};
    evidence.push(
      `  decisionProof = ${signatures.length} signature(s) of ${signatures[0].length / 2 - 1} bytes + ` +
        `extraData ${short(extraData)}; threshold t+1 = ${attestation.threshold} of ${attestation.coreCount} cores`
    );
    if (signatures.length < Number(attestation.threshold ?? 2)) pass = false;

    // Recover the signers and ask the deployed verifier whether they are its
    // registered KMS cores.
    const verifierAbi = loadJson(path.join(podRoot, "contracts", "out", "ZamaKMSVerdictVerifier.json")).abi;
    const verifier = new ethers.Contract(attestation.verifier, verifierAbi, ctx.provider);
    const registered = (await verifier.getKmsSigners()).map((address) => address.toLowerCase());
    const threshold = Number(await verifier.getThreshold());
    const types = {
      PublicDecryptVerification: [
        { name: "ctHandles", type: "bytes32[]" },
        { name: "decryptedResult", type: "bytes" },
        { name: "extraData", type: "bytes" }
      ]
    };
    const decryptedResult = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bool", "bool"],
      [decodedValues[3], decodedValues[4]]
    );
    const candidates = [
      [operatorLeaf[3], challengerLeaf[3]],
      [result.honestLeaf?.claimedHandle, challengerLeaf[3]],
      [result.dishonestLeaf?.claimedHandle, challengerLeaf[3]]
    ].filter((pair) => pair.every(Boolean));
    let recovered = [];
    for (const ctHandles of candidates) {
      const signers = signatures.map((signature) =>
        ethers
          .verifyTypedData(attestation.domain, types, { ctHandles, decryptedResult, extraData }, signature)
          .toLowerCase()
      );
      if (signers.every((signer) => registered.includes(signer))) {
        recovered = signers;
        break;
      }
    }
    const distinct = new Set(recovered);
    if (distinct.size < threshold) pass = false;
    evidence.push(
      `  signatures recover to ${distinct.size} distinct registered KMS core(s) ` +
        `(threshold ${threshold}, registered ${registered.length}): ${[...distinct].map(short).join(", ") || "none"}`
    );
    evidence.push(
      `  the signed payload is (ctHandles, decryptedResult=abi.encode(bool,bool), extraData=leafDecisionBinding): ` +
        `two decision bits, no operand`
    );
    return { pass, evidence };
  }
);

// --- C8 ---------------------------------------------------------------------
defineCheck(
  "C8",
  "Negative control: the battery detects a real leak",
  "the deleted declareHandle route is reconstructed as a real transaction on this chain, carrying this run's own private operands, and fetched back from the node by hash: the same instrument that clears the real run reports the leak. A synthetic calldata word carrying 192800/216000 is detected off-chain, and the audited run itself shows zero occurrences and no transaction with the deleted selector",
  async (ctx) => {
    const evidence = [];
    let pass = true;

    // --- part 1: a real on-chain leak, RECONSTRUCTED ------------------------
    //
    // The route that leaked -- `declareHandle(bytes32,uint256,uint8)`, which
    // published a disputed leaf's operand in the clear so the local FHEVM
    // stand-in could resolve a handle -- has been deleted from the contracts.
    // No run this repository can still produce contains one. A run directory
    // left over on one machine from before the deletion is not evidence anyone
    // else can check, and `artifacts/runs/` is not tracked, so a fresh clone has
    // none at all.
    //
    // The control is therefore RECONSTRUCTED, on this chain, now: one
    // transaction whose calldata is exactly what the deleted entry point would
    // have published for THIS run's own private operands, sent to a burn
    // address, then fetched BACK FROM THE NODE BY HASH and handed to the same
    // instrument that clears the real run in C6. If the instrument reports
    // nothing here, its silence on the real run means nothing.
    const { priv, pub } = runOperandSets(ctx.primaryRun);
    const leakedValues = [...priv].slice(0, 2);
    if (leakedValues.length === 0) {
      evidence.push("the audited run declares no private operand — nothing to reconstruct a leak from");
      return { pass: false, evidence };
    }
    const legacy = new ethers.Interface([
      "function declareHandle(bytes32 handle, uint256 value, uint8 width)"
    ]);

    const signer = ctx.leakProbeSigner;
    if (!signer) {
      evidence.push(
        "no funded signer available (set VCFHE_MNEMONIC or VCFHE_PRIVATE_KEYS) — the on-chain " +
          "reconstruction cannot be sent"
      );
      return { pass: false, evidence };
    }
    const reconstructed = [];
    for (const value of leakedValues) {
      const data = legacy.encodeFunctionData("declareHandle", [
        ethers.zeroPadValue(ethers.toBeHex(0x1234n), 32),
        value,
        64
      ]);
      // A burn address, not the dispute game: the point is to put the bytes the
      // deleted route would have put on chain ON the chain, and read them back
      // from the node, not to call anything.
      const sent = await signer.sendTransaction({
        to: "0x000000000000000000000000000000000000dEaD",
        data
      });
      await sent.wait();
      const onChain = await ctx.provider.getTransaction(sent.hash);
      reconstructed.push({
        label: "reconstructed:declareHandle",
        hash: onChain.hash,
        to: onChain.to,
        data: onChain.data
      });
      const decoded = legacy.decodeFunctionData("declareHandle", onChain.data);
      evidence.push(
        `reconstructed leak ${onChain.hash.slice(0, 12)}… fetched back from the node: ` +
          `declareHandle(handle=${short(decoded[0])}, value=${decoded[1]}, width=${decoded[2]}) ` +
          `-> cleartext operand ${decoded[1]} published on chain`
      );
    }

    const targets = new Set([...priv, ...pub]);
    let detected = 0;
    for (const tx of reconstructed) {
      for (const hit of inspectTransaction(tx, targets, ctx.artifacts).hits) {
        if (verdictForValue(hit.value, [hit]).length > 0) detected += 1;
      }
    }
    evidence.push(
      `  the same instrument, over transactions fetched by hash, reports ${detected} leak ` +
        `occurrence(s) in the reconstructed calldata; the leaked values ` +
        `(${leakedValues.join(", ")}) are operand values of this run's own witness set`
    );
    if (detected === 0) pass = false;

    // If a pre-deletion run does happen to be on this machine, audit it too --
    // but the control above does not depend on it.
    if (ctx.leakRun) {
      const { result, transactions } = await fetchRun(ctx.leakRun, ctx.provider);
      const historical = transactions.filter((tx) => tx.label === "declareHandle");
      const historicalSets = runOperandSets(ctx.leakRun);
      let historicalHits = 0;
      const publishedValues = [];
      for (const tx of historical) {
        publishedValues.push(BigInt(legacy.decodeFunctionData("declareHandle", tx.data)[1]));
        for (const hit of inspectTransaction(
          tx,
          new Set([...historicalSets.priv, ...historicalSets.pub]),
          ctx.artifacts
        ).hits) {
          if (verdictForValue(hit.value, [hit]).length > 0) historicalHits += 1;
        }
      }
      evidence.push(
        `historical run also present: ${path.basename(ctx.leakRun)} (workload ` +
          `${historicalSets.bundle.workload}, chainId ${result.chainId}) — ` +
          `${historical.length} declareHandle transaction(s) among ${transactions.length}, ` +
          `${historicalHits} leak occurrence(s) reported, values published in the clear: ` +
          `${[...new Set(publishedValues)].join(", ")}`
      );
    } else {
      evidence.push(
        "no pre-deletion run directory on this machine (artifacts/runs/ is not tracked); the control " +
          "above does not need one"
      );
    }

    // --- part 2: synthetic control, off-chain ------------------------------
    // The two intermediate products of qoe_mos_degradation_alarm, fed to the
    // same scanner as raw calldata, with no chain involved. This is the cheapest
    // form of the control and it is what the repository documentation points at
    // when it names 192800 and 216000: they come from this synthetic case, not
    // from any recorded run.
    const synthetic = {
      label: "synthetic:leakyDeclareHandle",
      hash: "0x" + "ff".repeat(32),
      to: "0x0000000000000000000000000000000000000001",
      data:
        "0xc808e02c" +
        word32(0x1234n) +
        word32(192800n) +
        word32(5n) +
        word32(216000n)
    };
    const syntheticTargets = new Set([192800n, 216000n]);
    const syntheticHits = inspectTransaction(synthetic, syntheticTargets, ctx.artifacts).hits;
    const syntheticLeaks = syntheticHits.filter((hit) => verdictForValue(hit.value, [hit]).length > 0);
    const rawSynthetic = scanTransactionsForValues([synthetic], [...syntheticTargets]);
    evidence.push(
      `synthetic leaky calldata (selector 0xc808e02c, the deleted declareHandle): ABI-aware scan reports ` +
        `${syntheticLeaks.length} leak(s) ${syntheticLeaks.map((hit) => `${hit.value}@${hit.where}`).join(", ")}`
    );
    evidence.push(
      `  raw word scan of the same calldata: 192800 -> ${rawSynthetic.perValue.get(192800n).payload} payload word(s), ` +
        `216000 -> ${rawSynthetic.perValue.get(216000n).payload} payload word(s)`
    );
    if (syntheticLeaks.length < 2) pass = false;

    // --- part 3: the instrument stays silent on the clean run --------------
    const clean = await fetchRun(ctx.primaryRun, ctx.provider);
    const cleanRaw = scanTransactionsForValues(clean.transactions, [...syntheticTargets]);
    const legacySelector = clean.transactions.filter((entry) => entry.data.startsWith("0xc808e02c"));
    evidence.push(
      `  control: the same two values in the current run ${path.basename(ctx.primaryRun)} -> ` +
        `192800: ${cleanRaw.perValue.get(192800n).payload} payload word(s), ` +
        `216000: ${cleanRaw.perValue.get(216000n).payload} payload word(s); ` +
        `transactions with the declareHandle selector: ${legacySelector.length}`
    );
    if (legacySelector.length > 0) pass = false;
    return { pass, evidence };
  }
);

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

async function main() {
  if (options.only && (!options.only.size || [...options.only].some(id => !checks.some(c => c.id === id)))) {
    throw new Error("--only must name one or more of C1..C8");
  }
  const needsChain = !options.only || ["C5", "C6", "C7", "C8"].some(id => options.only.has(id));
  const provider = needsChain ? new ethers.JsonRpcProvider(options.rpcUrl) : null;
  const chainId = provider ? Number((await provider.getNetwork()).chainId) : null;
  const manifest = loadJson(options.manifestPath);
  // "all" selects every honest entry; the "<id>#corrupted" variants are the
  // adversarial claims and are audited as C4's negative control, not on their
  // own. A comma-separated list selects exactly those ids.
  const selectedIds =
    options.workloadId === "all"
      ? manifest.workloads
          .map((entry) => entry.workloadId)
          .filter((id) => !id.endsWith("#corrupted"))
      : options.workloadId.split(",").map((id) => id.trim()).filter(Boolean);
  const manifestWorkloads = selectedIds.map((id) => {
    const entry = manifest.workloads.find((candidate) => candidate.workloadId === id);
    if (!entry) {
      throw new Error(
        `ciphertext manifest ${options.manifestPath} has no workload ${id} ` +
          `(has: ${manifest.workloads.map((candidate) => candidate.workloadId).join(", ")})`
      );
    }
    return entry;
  });
  const manifestWorkload = manifestWorkloads[0];
  if (!manifestWorkload) {
    throw new Error(
      `ciphertext manifest ${options.manifestPath} has no workload ${options.workloadId} ` +
        `(has: ${manifest.workloads.map((entry) => entry.workloadId).join(", ")})`
    );
  }
  const primaryRun = needsChain ? options.runDir ?? selectPrimaryRun(chainId) : null;
  if (needsChain && !primaryRun) {
    throw new Error(
      `no run under artifacts/runs/ on chainId ${chainId} that settles through ` +
        "settleLeafViaAttestedDecision without declareHandle; pass --run <dir>"
    );
  }
  const leakRun = needsChain ? options.leakRunDir ?? selectLeakRun(chainId) : null;

  // C6 audits the most recent run of every family produced by the current code
  // (experiment workloads and the ANATEL demonstration), so both a workload without
  // public scalars and one with DIV divisors are covered.
  const current = (needsChain ? listRunDirs() : []).filter((dir) => {
    const result = loadJson(path.join(dir, "hardhat_dispute_result.json"));
    return (
      Number(result.chainId) === chainId &&
      !runLabels(result).has("declareHandle") &&
      runLabels(result).has("settleLeafViaAttestedDecision")
    );
  });
  const newestPerFamily = new Map();
  for (const dir of current) {
    if (!newestPerFamily.has(runFamily(dir))) newestPerFamily.set(runFamily(dir), dir);
  }
  const auditRuns = [...new Set([primaryRun, ...newestPerFamily.values()].filter(Boolean))];

  const ctx = {
    provider,
    chainId,
    manifest,
    manifestWorkload,
    manifestWorkloads,
    // The lowered traces of the selected workloads: C4 needs the public scalar
    // of a DIV/MOD/SHR leaf to recompute it, since that operand is never
    // encrypted and so has no ciphertext to load.
    traceWorkloads: new Map(
      JSON.parse(fs.readFileSync(options.tracesPath, "utf8"))
        .workloads.filter((entry) => selectedIds.includes(entry.workloadId))
        .map((entry) => [entry.workloadId, entry])
    ),
    primaryRun,
    leakRun,
    auditRuns,
    artifacts: needsChain ? loadCompiledArtifacts() : [],
    // C8 reconstructs the deleted leaking route as a real transaction, so it
    // needs a funded account. Same key material the campaign already uses.
    leakProbeSigner: provider ? leakProbeSigner(provider) : null
  };

  console.log("verify-encrypted-execution — evidence that the pipeline runs on ciphertexts");
  console.log(provider ? `  rpc              ${options.rpcUrl} (chainId ${chainId}, head ${await provider.getBlockNumber()})`
    : "  chain checks     not requested; artifact-only verification");
  console.log(`  manifest         ${path.relative(podRoot, options.manifestPath)} (tfhe ${manifest.tfheVersion}, keyDigest ${short(manifest.keyDigest)})`);
  console.log(
    `  workloads        ${manifestWorkloads.length} selected, ` +
      `${manifestWorkloads.reduce((total, entry) => total + entry.leafCount, 0)} leaves: ` +
      manifestWorkloads.map((entry) => `${entry.workloadId}(${entry.leafCount})`).join(", ")
  );
  console.log(`  primary run      ${primaryRun ? path.basename(primaryRun) : "not requested"}`);
  console.log(`  audited runs     ${auditRuns.map((dir) => path.basename(dir)).join(", ")}`);
  console.log(`  negative control ${leakRun ? path.basename(leakRun) : "none found"}`);
  console.log("");

  let failures = 0;
  let executed = 0;
  for (const check of checks) {
    if (options.only && !options.only.has(check.id)) {
      console.log(`SKIP ${check.id}  ${check.title}`);
      continue;
    }
    executed += 1;
    const started = Date.now();
    let outcome;
    try {
      outcome = await check.run(ctx);
    } catch (error) {
      outcome = { pass: false, evidence: [`threw: ${error.message}`] };
    }
    const status = outcome.pass ? "PASS" : "FAIL";
    if (!outcome.pass) failures += 1;
    console.log(`${status} ${check.id}  ${check.title}  [${((Date.now() - started) / 1000).toFixed(1)}s]`);
    console.log(`       assertion: ${check.assertion}`);
    for (const line of outcome.evidence) console.log(`       ${line}`);
    console.log("");
  }

  console.log(
    `${executed} check(s) executed, ${executed - failures} passed, ${failures} failed` +
      (options.only ? " (PARTIAL RUN: --only was given)" : "")
  );
  process.exitCode = failures === 0 ? 0 : 1;
}

await main();
