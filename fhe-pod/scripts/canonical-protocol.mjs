import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify, isDeepStrictEqual } from "node:util";
import { ethers } from "./evm-lib.mjs";
import { validatePublicExecution, firstDivergence } from "./experimental-public-replay.mjs";
import { admitCanonicalDomain } from "./canonical-domain.mjs";
const exec = promisify(execFile);
export const CANONICAL_VERSION = "canonical-dag-execution-v1";
export const hashJson = value => ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(value)));
export const hashFile = async file => ethers.keccak256(await fs.readFile(file));
const json = async file => JSON.parse(await fs.readFile(file, "utf8"));
export async function runCanonicalBinary(binary, args) {
  return JSON.parse((await exec(binary, args, { maxBuffer: 16 * 1024 * 1024,
    timeout: 3600000 })).stdout);
}
export async function referenceProfile(binary) {
  return { version: CANONICAL_VERSION, binaryDigest: await hashFile(binary),
    tfhe: "1.4.0", threads: 1, fixedFFT: true, arch: os.arch(), os: os.platform(),
    osRelease: os.release(), cpu: os.cpus()[0]?.model ?? "unknown" };
}
export async function createExecutionContext({ binary, publicDir, inputBounds, records, keyEpoch, policyDomain }) {
  const program = await json(path.join(publicDir, "program.json"));
  const domain = admitCanonicalDomain(program, inputBounds);
  if (!Array.isArray(records) || records.length !== program.inputs.length ||
      new Set(records.map(r => r.id)).size !== records.length ||
      records.some(r => !r.id || !/^0x[0-9a-f]{64}$/.test(r.protectedId) || !ethers.isAddress(r.owner))) throw new Error("invalid stable owner records");
  const owners = new Map();
  for (const r of records) {
    if (owners.has(r.protectedId) && owners.get(r.protectedId) !== r.owner.toLowerCase()) throw new Error("inconsistent protected-record owner");
    owners.set(r.protectedId, r.owner.toLowerCase());
  }
  const inputs = await Promise.all(records.map(async (r, i) => ({ ...r,
    handle: await hashFile(path.join(publicDir, `input-${i}.ct`)) })));
  return { version: CANONICAL_VERSION, profile: await referenceProfile(binary),
    inputEncryption: "tfhe-compressed-public-key-v1",
    encryptionKeyDigest: await hashFile(path.join(publicDir, "encryption-key.bin")),
    programDigest: await hashFile(path.join(publicDir, "program.json")),
    keyDigest: await hashFile(path.join(publicDir, "server-key.bin")),
    keyEpoch, policyDomain, inputs, domain };
}
export async function checkExecutionContext(context, binary, publicDir) {
  const actual = await createExecutionContext({ binary, publicDir,
    inputBounds: context.domain.inputBounds, records: context.inputs.map(({ id, owner, protectedId }) => ({ id, owner, protectedId })),
    keyEpoch: context.keyEpoch, policyDomain: context.policyDomain });
  if (!isDeepStrictEqual(actual, context)) throw new Error("execution context mismatch");
}
export async function canonicalTrace(context, publicDir, traceDir) {
  const trace = await validatePublicExecution(publicDir, traceDir, CANONICAL_VERSION);
  const p = trace.manifest.profile, c = context.profile;
  const rustArch = c.arch === "arm64" ? "aarch64" : c.arch === "x64" ? "x86_64" : c.arch;
  const rustOs = c.os === "darwin" ? "macos" : c.os;
  if (p.binaryDigest !== c.binaryDigest || p.tfhe !== c.tfhe || p.threads !== 1 ||
      p.fixedFFT !== true || p.arch !== rustArch || p.os !== rustOs ||
      trace.manifest.programDigest !== context.programDigest || trace.manifest.serverKeyDigest !== context.keyDigest ||
      !isDeepStrictEqual(trace.manifest.inputs, context.inputs.map(r => r.handle))) throw new Error("unadmitted execution profile or input");
  return trace;
}
export async function detectCanonicalFault({ context, binary, publicDir, operatorDir, replayDir }) {
  await checkExecutionContext(context, binary, publicDir);
  const operator = await canonicalTrace(context, publicDir, operatorDir);
  await runCanonicalBinary(binary, ["execute-canonical", publicDir, replayDir]);
  const replay = await canonicalTrace(context, publicDir, replayDir);
  return { ...firstDivergence(operator.tree, replay.tree), operatorRoot: operator.tree.root,
    replayRoot: replay.tree.root, leafCount: replay.tree.leafCount, replayMs: replay.manifest.elapsedMs,
    contextDigest: hashJson(context), plaintextOpenings: 0 };
}
export async function adjudicateCanonicalLeaf({ context, binary, publicDir, operatorDir,
  challengerLeaf, leafIndex, outputFile }) {
  await checkExecutionContext(context, binary, publicDir);
  const operator = await canonicalTrace(context, publicDir, operatorDir);
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= operator.tree.leafCount) throw new Error("invalid leaf index");
  // The signing boundary authenticates this opening against the isolated
  // on-chain node. Candidate ciphertext bytes are unnecessary for comparison.
  const op = operator.manifest.leaves[leafIndex], ch = challengerLeaf;
  // No party may change the authenticated operands at the isolated transition.
  if (op.lhsHandle !== ch.lhsHandle || op.rhsHandle !== ch.rhsHandle) throw new Error("isolation has inconsistent operands");
  const recomputed = await runCanonicalBinary(binary, ["leaf", publicDir, operatorDir, String(leafIndex), outputFile]);
  if (recomputed.programDigest !== context.programDigest || recomputed.serverKeyDigest !== context.keyDigest ||
      recomputed.lhsHandle !== op.lhsHandle || recomputed.rhsHandle !== op.rhsHandle) throw new Error("recomputation input changed after validation");
  return { operatorValid: op.resultHandle === recomputed.resultHandle,
    challengerValid: ch.claimedHandle === recomputed.resultHandle,
    recomputedHandle: recomputed.resultHandle, claimedHandles: [op.resultHandle, ch.claimedHandle],
    contextDigest: hashJson(context), plaintextOpenings: 0, elapsedMs: recomputed.elapsedMs };
}
