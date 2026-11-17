// Research-only public replay. A byte mismatch is a candidate divergence, not
// an invalidity verdict under the deployed value-equality relation.
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify, isDeepStrictEqual } from "node:util";
import { ethers, leafHash, buildMerkleTreeFromLeafHashes } from "./evm-lib.mjs";
import { OPCODES } from "./micro-isa.mjs";
import { validateCircuit } from "./compliance-circuit.mjs";

const run = promisify(execFile);
const readJson = async file => JSON.parse(await fs.readFile(file, "utf8"));
const hashFile = async file => ethers.keccak256(await fs.readFile(file));
const requireEqual = (actual, expected, label) => {
  if (!isDeepStrictEqual(actual, expected)) throw new Error(`binding mismatch: ${label}`);
};

export async function validatePublicExecution(publicDir, traceDir, expectedVersion = "explicit-dag-execution-experiment-v1") {
  const program = validateCircuit(await readJson(path.join(publicDir, "program.json")));
  const manifest = await readJson(path.join(traceDir, "manifest.json"));
  requireEqual(manifest.version, expectedVersion, "trace version");
  requireEqual(manifest.programDigest, await hashFile(path.join(publicDir, "program.json")), "program");
  requireEqual(manifest.serverKeyDigest, await hashFile(path.join(publicDir, "server-key.bin")), "key");
  requireEqual(manifest.publicDecisionsReleased, 0, "release count");
  requireEqual(manifest.inputs?.length, program.inputs.length, "input count");
  requireEqual(manifest.leaves?.length, program.instructions.length, "trace length");
  for (let i = 0; i < program.inputs.length; i++) {
    requireEqual(manifest.inputs[i], await hashFile(path.join(publicDir, `input-${i}.ct`)), `input ${i}`);
  }
  const resolve = ref => ref.kind === "constant" ? ethers.toBeHex(BigInt(ref.value), 32)
    : ref.kind === "input" ? manifest.inputs[ref.index] : manifest.leaves[ref.index].resultHandle;
  for (const [i, instruction] of program.instructions.entries()) {
    const row = manifest.leaves[i];
    for (const field of ["index", "opcode", "lhs", "rhs"]) requireEqual(row[field], instruction[field], `leaf ${i} ${field}`);
    requireEqual(row.lhsHandle, resolve(instruction.lhs), `leaf ${i} lhs`);
    requireEqual(row.rhsHandle, resolve(instruction.rhs), `leaf ${i} rhs`);
    requireEqual(row.resultHandle, await hashFile(path.join(traceDir, `result-${i}.ct`)), `leaf ${i} result`);
  }
  requireEqual(manifest.terminalHandle, manifest.leaves.at(-1).resultHandle, "terminal result");
  const tree = buildMerkleTreeFromLeafHashes(manifest.leaves.map(row => leafHash({
    opcode: OPCODES[row.opcode], lhsHandle: row.lhsHandle, rhsHandle: row.rhsHandle,
    claimedHandle: row.resultHandle
  })));
  return { manifest, tree };
}

export function firstDivergence(left, right) {
  requireEqual(left.leafCount, right.leafCount, "tree dimensions");
  if (left.root === right.root) return { index: null, rounds: 0 };
  let index = 0, rounds = 0;
  for (let level = left.levels.length - 2; level >= 0; level--) {
    index *= 2;
    if (left.levels[level][index] === right.levels[level][index]) index++;
    rounds++;
  }
  return { index, rounds };
}

export async function experimentalPublicReplay({ binary, publicDir, operatorDir, replayDir }) {
  // Only public inputs, the program, evaluation key and claimed trace enter
  // this interface. No fault index, honest trace or owner values/key are read.
  const operator = await validatePublicExecution(publicDir, operatorDir);
  await run(binary, ["execute", publicDir, replayDir], { maxBuffer: 8 * 1024 * 1024 });
  const replay = await validatePublicExecution(publicDir, replayDir);
  requireEqual(operator.manifest.profile, replay.manifest.profile, "execution profile");
  const candidate = firstDivergence(operator.tree, replay.tree);
  const result = {
    status: candidate.index === null ? "byte-identical-replay" : "candidate-byte-divergence",
    ...candidate, operatorRoot: operator.tree.root, replayRoot: replay.tree.root,
    replayMs: replay.manifest.elapsedMs, leafCount: replay.tree.leafCount,
    publicDecisionsReleased: 0, settlementVerdict: null,
    limitation: "Experimental profile only; byte mismatch is not invalidity under value equality. No distributed backend or on-chain settlement was exercised."
  };
  await fs.writeFile(path.join(replayDir, "replay-report.json"), JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [, , binary, publicDir, operatorDir, replayDir] = process.argv;
  if (!replayDir) throw new Error("usage: experimental-public-replay.mjs BINARY PUBLIC OPERATOR REPLAY");
  console.log(JSON.stringify(await experimentalPublicReplay({ binary, publicDir, operatorDir, replayDir })));
}
