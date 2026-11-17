import { explicitTraceReferences } from "./trace-references.mjs";
import fs from "node:fs/promises";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";
import { ethers } from "ethers";

const EIP170_RUNTIME_CODE_LIMIT_BYTES = 24_576;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import { requireFheHandles } from "./fhe-handles.mjs";

export const projectRoot = path.resolve(__dirname, "..");

/**
 * Re-export of the `ethers` namespace.
 *
 * Node resolves a bare specifier by walking up from the IMPORTING file, not
 * from the working directory. A consumer that lives outside `fhe-pod/` -- the
 * ANATEL RQUAL demonstration in `VC-FHE/Anatel/anatel-rqual/` is the one that exists
 * -- therefore cannot `import("ethers")` even though it can import this module.
 * Re-exporting here resolves it once, from inside the pod, where the dependency
 * tree is.
 */
export { ethers };

/**
 * Receipt timeout, milliseconds. `tx.wait()` waits forever by default, so a
 * transaction dropped from the pool hangs the caller with no output. Bounded
 * here so a stalled deployment or sampling call fails loudly instead.
 */
export const RECEIPT_TIMEOUT_MS = Number(process.env.FHE_POD_RECEIPT_TIMEOUT_MS || 180_000);

/**
 * Awaits a receipt with a bound.
 *
 * The `receipt === null` branch below is NOT the path a timeout takes: ethers v6
 * `tx.wait(confirms, timeout)` REJECTS with `code: "TIMEOUT"` instead of
 * resolving to null. So the diagnostic that used to live only in that branch was
 * unreachable, and an operator got a bare
 *     Error: wait for transaction timeout (code=TIMEOUT, version=6.16.0)
 * with no label, no transaction hash and no hint. Measured cost of that: a
 * 32-minute chain freeze (macOS idle sleep freezing Docker's VM) presented as an
 * anonymous ethers timeout, indistinguishable at first read from a stuck pool or
 * a nonce collision. Both paths now produce the same message.
 */
export async function awaitReceipt(tx, label = "transaction") {
  let receipt;
  try {
    receipt = await tx.wait(1, RECEIPT_TIMEOUT_MS);
  } catch (error) {
    if (error?.code !== "TIMEOUT") throw error;
    throw new Error(timedOutMessage(label, tx.hash), { cause: error });
  }
  if (receipt === null) throw new Error(timedOutMessage(label, tx.hash));
  return receipt;
}

function timedOutMessage(label, hash) {
  return (
    `timed out after ${RECEIPT_TIMEOUT_MS} ms waiting for the receipt of "${label}" (tx ${hash}).\n`
    + "  Check, in this order:\n"
    + "    1. Is the chain still producing blocks? Compare two timestamps a few seconds apart;\n"
    + "       a long GAP means the node froze rather than the transaction being stuck.\n"
    + "       On macOS, idle sleep freezes Docker's VM and does exactly this -- the demo\n"
    + "       scripts re-exec themselves under `caffeinate` to prevent it, which setting\n"
    + "       VCFHE_CAFFEINATED=1 by hand disables.\n"
    + "    2. Is another process sending from the same accounts?\n"
    + "    3. Is the transaction still pending? An empty pool plus no receipt means it was\n"
    + "       dropped, not delayed.\n"
    + `  Raise the bound with FHE_POD_RECEIPT_TIMEOUT_MS if the chain is merely slow.`
  );
}
export const contractsSrcDir = path.join(projectRoot, "contracts", "src");
export const contractsOutDir = path.join(projectRoot, "contracts", "out");

export function logStep(message, extra = {}) {
  const now = new Date().toISOString();
  const fields = Object.entries(extra)
    .map(([key, value]) => `${key}=${value}`)
    .join(" ");
  console.log(fields ? `[${now}] ${message} ${fields}` : `[${now}] ${message}`);
}

let compileContractsPromise;

export async function compileContracts() {
  if (!compileContractsPromise) {
    compileContractsPromise = compileContractsOnce().catch((error) => {
      compileContractsPromise = undefined;
      throw error;
    });
  }
  return compileContractsPromise;
}

async function compileContractsOnce() {
  const sourceEntries = await fs.readdir(contractsSrcDir, { withFileTypes: true });
  const sources = {};

  for (const entry of sourceEntries) {
    if (!entry.isFile() || !entry.name.endsWith(".sol")) {
      continue;
    }
    const fullPath = path.join(contractsSrcDir, entry.name);
    sources[entry.name] = {
      content: await fs.readFile(fullPath, "utf8")
    };
  }

  const input = {
    language: "Solidity",
    sources,
    settings: {
      evmVersion: "paris",
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 1
      },
      // Deterministic runtime bytecode and ~53 bytes of EIP-170 headroom:
      // the IPFS metadata hash is not needed for these local artifacts.
      metadata: {
        bytecodeHash: "none"
      },
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]
        }
      }
    }
  };

  const output = JSON.parse(
    solc.compile(JSON.stringify(input), { import: resolveSolidityImport })
  );
  const hardErrors = (output.errors ?? []).filter(
    (entry) => entry.severity === "error"
  );
  if (hardErrors.length > 0) {
    throw new Error(
      `solc failed:\n${hardErrors.map((entry) => entry.formattedMessage).join("\n")}`
    );
  }

  await fs.mkdir(contractsOutDir, { recursive: true });
  const artifacts = {};

  for (const [sourceName, contracts] of Object.entries(output.contracts)) {
    for (const [contractName, contract] of Object.entries(contracts)) {
      const deployedBytecode = contract.evm.deployedBytecode.object;
      const deployedBytecodeBytes = deployedBytecode.length / 2;
      if (deployedBytecodeBytes > EIP170_RUNTIME_CODE_LIMIT_BYTES) {
        throw new Error(
          `${contractName} runtime is ${deployedBytecodeBytes} bytes, above the ` +
          `${EIP170_RUNTIME_CODE_LIMIT_BYTES}-byte EIP-170 deployment limit`
        );
      }
      const artifact = {
        contractName,
        abi: contract.abi,
        bytecode: `0x${contract.evm.bytecode.object}`,
        deployedBytecode: `0x${deployedBytecode}`,
        deployedBytecodeBytes
      };
      artifacts[contractName] = artifact;
      await fs.writeFile(
        path.join(contractsOutDir, `${contractName}.json`),
        JSON.stringify(artifact, null, 2)
      );
    }
  }

  return artifacts;
}

function resolveSolidityImport(importPath) {
  const candidates = [];
  const nodeModulesDir = path.join(projectRoot, "node_modules");
  const fhevmSolidityDir = path.join(nodeModulesDir, "@fhevm", "solidity");

  if (importPath.startsWith("@")) {
    candidates.push(path.join(nodeModulesDir, importPath));
  }

  for (const basePath of [
    contractsSrcDir,
    projectRoot,
    nodeModulesDir,
    fhevmSolidityDir,
    path.join(fhevmSolidityDir, "lib"),
    path.join(fhevmSolidityDir, "config"),
    path.join(fhevmSolidityDir, "lib", "cryptography")
  ]) {
    candidates.push(path.resolve(basePath, importPath));
  }

  for (const candidate of candidates) {
    try {
      return { contents: readFileSync(candidate, "utf8") };
    } catch {
      // Try next candidate.
    }
  }

  return { error: `Solidity import not found: ${importPath}` };
}

export async function loadArtifact(contractName) {
  const artifactPath = path.join(contractsOutDir, `${contractName}.json`);
  try {
    return JSON.parse(await fs.readFile(artifactPath, "utf8"));
  } catch {
    const artifacts = await compileContracts();
    if (!artifacts[contractName]) {
      throw new Error(`Contract artifact not found for ${contractName}`);
    }
    return artifacts[contractName];
  }
}

// --- Commit-then-sample assignment -----------------------------------------
// Auditor/decryptor assignment is drawn from the hash of the first block
// mined after the task commitment (see VerifiableFHEDisputeGame.sol,
// sampleParticipants). This helper mines the seed block and triggers the
// permissionless sampling call; audit windows start when sampling lands.
export async function sampleTaskParticipants(game, taskId) {
  const provider = game.runner.provider;
  // The seed is blockhash(sampleBlock); the tx is valid only strictly after
  // that block. estimateGas runs one block early, so mine two blocks and send
  // with an explicit gas limit to bypass the premature estimation revert.
  // Development nodes mine on demand; consensus chains (e.g. Besu QBFT) have
  // no evm_mine, so there we wait for two real blocks instead.
  try {
    await provider.send("evm_mine", []);
    await provider.send("evm_mine", []);
  } catch {
    const start = await provider.getBlockNumber();
    while ((await provider.getBlockNumber()) < start + 2) {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
  const tx = await game.sampleParticipants(taskId, { gasLimit: 1_500_000 });
  return await awaitReceipt(tx, "sampleParticipants");
}

export async function latestRunDir() {
  const runsDir = path.join(projectRoot, "artifacts", "runs");
  const entries = await fs.readdir(runsDir, { withFileTypes: true });
  const directories = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const fullPath = path.join(runsDir, entry.name);
    try {
      await fs.access(path.join(fullPath, "attestation_payload.json"));
      await fs.access(path.join(fullPath, "micro_trace_bundle.json"));
    } catch {
      continue;
    }
    const stats = await fs.stat(fullPath);
    directories.push({ fullPath, mtimeMs: stats.mtimeMs });
  }

  if (directories.length === 0) {
    throw new Error("No completed run directory with dispute artifacts found");
  }

  directories.sort((left, right) => right.mtimeMs - left.mtimeMs);
  return directories[0].fullPath;
}

export async function loadRunArtifacts(runDir) {
  const resolvedRunDir = runDir ?? (await latestRunDir());
  const [attestationPayload, microTraceBundle] = await Promise.all([
    fs.readFile(path.join(resolvedRunDir, "attestation_payload.json"), "utf8"),
    fs.readFile(path.join(resolvedRunDir, "micro_trace_bundle.json"), "utf8")
  ]);

  return {
    runDir: resolvedRunDir,
    attestationPayload: JSON.parse(attestationPayload),
    microTraceBundle: JSON.parse(microTraceBundle)
  };
}

export async function writeJson(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(
    filePath,
    JSON.stringify(
      value,
      (_key, currentValue) =>
        typeof currentValue === "bigint" ? currentValue.toString() : currentValue,
      2
    )
  );
}

export function ensureBytes32(hexValue) {
  if (typeof hexValue !== "string") {
    throw new TypeError("bytes32 value must be a string");
  }
  const prefixed = hexValue.startsWith("0x") ? hexValue : `0x${hexValue}`;
  if (!/^0x[0-9a-fA-F]{64}$/.test(prefixed)) {
    throw new Error(`Expected bytes32 hex, got ${hexValue}`);
  }
  return prefixed.toLowerCase();
}

/**
 * The three ciphertext handles a trace leaf commits to.
 *
 * A leaf object may already carry them (that is what `attachTraceHandles`
 * produces, and what every run with a ciphertext manifest uses). When it does
 * not, they are derived from the clear values through
 * `ciphertextHandleForClear`, which is the legacy "the handle IS the plaintext"
 * regime documented below: it claims no confidentiality and exists so the
 * contract unit tests can keep exercising binding and provenance algebra over
 * opaque 32-byte words without a TFHE manifest.
 */
export function traceLeafHandles(leaf) {
  return {
    lhsHandle: leaf.lhsHandle ?? ciphertextHandleForClear(leaf.lhs),
    rhsHandle: leaf.rhsHandle ?? ciphertextHandleForClear(leaf.rhs),
    claimedHandle: leaf.claimedHandle ?? ciphertextHandleForClear(leaf.claimed)
  };
}

/**
 * The `LeafClaim` tuple as the contracts see it. Built explicitly (rather than
 * by handing a witness object to ethers) so that no clear operand can reach
 * calldata by accident: a leaf carrying `lhs`/`rhs`/`claimed` for off-chain
 * bookkeeping is stripped down to opcode + handles here.
 */
export function traceLeafClaim(leaf) {
  const handles = traceLeafHandles(leaf);
  return {
    opcode: leaf.opcode,
    lhsHandle: handles.lhsHandle,
    rhsHandle: handles.rhsHandle,
    claimedHandle: handles.claimedHandle
  };
}

/**
 * Trace leaf commitment.
 *
 * WHY THIS COMMITS TO HANDLES AND NOT TO VALUES
 * ---------------------------------------------
 * The trace root is what bisection walks, so whatever the leaf hash commits to
 * is exactly what the two parties must put in calldata for the terminal round
 * to be checkable. While the leaf was keccak256(opcode, lhs, rhs, claimed), the
 * end of every dispute REQUIRED publishing the disputed operands in the clear,
 * and the disclosure that precedes bisection had to publish all of them. The
 * leaf now commits to the three ciphertext handles instead. What stays public
 * is the STRUCTURE (which operation, over which committed ciphertexts, feeding
 * which one); the operand values never appear. The FHEVM backend re-executes
 * the disputed leaf homomorphically from those same handles, so adjudication
 * loses nothing.
 */
export function leafHash(leaf) {
  const handles = traceLeafHandles(leaf);
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint8", "bytes32", "bytes32", "bytes32"],
      [leaf.opcode, handles.lhsHandle, handles.rhsHandle, handles.claimedHandle]
    )
  );
}

/**
 * Legacy handle derivation: the 32-byte big-endian encoding of the clear value.
 * This makes the registered "ciphertext handle" the plaintext, so it is not an
 * encryption of anything. It survives only for the contract unit tests, which
 * exercise binding and provenance logic and never claim confidentiality.
 *
 * The evaluated workloads take their handles from the TFHE executor instead
 * (scripts/fhe-handles.mjs); buildAuthenticatedTracePlan uses those whenever a
 * ciphertext manifest covers the workload, and VCFHE_REQUIRE_FHE_HANDLES=1
 * forbids this fallback outright.
 */
export function ciphertextHandleForClear(value) {
  return ethers.zeroPadValue(ethers.toBeHex(BigInt(value)), 32);
}

/**
 * Filler for the input-record Merkle tree, which is padded to a power of two.
 * A padding record is never referenced by a leaf operand, so it commits to no
 * ciphertext; the domain separator marks it as tree padding rather than an
 * encryption of the index.
 */
function paddingInputHandle(taskId, index) {
  return ethers.keccak256(
    ethers.solidityPacked(["string", "bytes32", "uint32"], ["VCFHE_INPUT_TREE_PADDING", taskId, index])
  );
}

export const authenticatedInputRecordTypehash = ethers.keccak256(
  ethers.toUtf8Bytes(
    "FHE_POD_INPUT_RECORD_V1(address owner,bytes32 ciphertextHandle,bytes32 metadataHash)"
  )
);
export const authenticatedProgramLeafTypehash = ethers.keccak256(
  ethers.toUtf8Bytes(
    "FHE_POD_PROGRAM_LEAF_V1(bytes32 taskId,uint32 leafIndex,uint8 opcode,uint8 lhsSourceKind,uint32 lhsSourceIndex,uint8 rhsSourceKind,uint32 rhsSourceIndex,uint256 lhsConstant,uint256 rhsConstant)"
  )
);
export const authenticatedProvenanceLeafTypehash = ethers.keccak256(
  ethers.toUtf8Bytes(
    "FHE_POD_PROVENANCE_LEAF_V1(bytes32 taskId,uint32 leafIndex,bytes32 traceLeafHash,bytes32 lhsHandle,bytes32 rhsHandle,bytes32 claimedHandle,uint8 lhsSourceKind,uint32 lhsSourceIndex,bytes32 lhsInputRecord,uint8 rhsSourceKind,uint32 rhsSourceIndex,bytes32 rhsInputRecord)"
  )
);

export const provenanceSource = Object.freeze({
  AUTHENTICATED_INPUT: 0,
  PREVIOUS_OUTPUT: 1,
  PUBLIC_CONSTANT: 2
});

export function authenticatedInputRecordHash(owner, ciphertextHandle, metadataHash) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "bytes32", "bytes32"],
      [authenticatedInputRecordTypehash, owner, ciphertextHandle, metadataHash]
    )
  );
}

function nextPowerOfTwo(value) {
  let result = 1;
  while (result < value) result *= 2;
  return result;
}

/**
 * Dataflow of a trace, and the ciphertext handle of every operand and result.
 *
 * Factored out of `buildAuthenticatedTracePlan` because the TRACE MERKLE TREE
 * now commits to handles: the tree can no longer be built from the clear
 * witnesses alone, and the tree and the authenticated plan must derive the very
 * same handles or the disclosed leaves would not reconstruct the committed
 * root. One function, two callers.
 *
 * `programLeaves` is the statement the requester authorized (the honest
 * program); `leaves` is what the operator actually executed. The dataflow
 * (which operand is the previous leaf's output) is read from the program, the
 * result ciphertexts from the execution: a dishonest operator can change what
 * it computed, not what it was asked to compute.
 */
function resolveTraceHandles(leaves, programLeaves = leaves, fheHandles = null) {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error("trace handle resolution requires leaves");
  }
  if (!Array.isArray(programLeaves) || programLeaves.length !== leaves.length) {
    throw new Error("programLeaves must match the execution trace length");
  }
  if (requireFheHandles && !fheHandles) {
    throw new Error(
      "VCFHE_REQUIRE_FHE_HANDLES=1 but no ciphertext manifest was supplied for this trace; "
      + "the plan would register clear values as ciphertext handles."
    );
  }
  // A handle is the keccak256 of the serialized TFHE ciphertext when the
  // executor covered this workload, and the clear-value encoding otherwise.
  const inputHandle = (value, leafIndex, side) => {
    if (!fheHandles) return ciphertextHandleForClear(value);
    const handle = fheHandles.inputHandle(leafIndex, side);
    if (handle) return handle;
    // Not every trace operand is a ciphertext. DIV/MOD/SHR take a PUBLIC scalar
    // divisor or shift amount, and unary opcodes ignore their rhs entirely: the
    // encrypted execution never encrypts those, so the manifest holds no
    // ciphertext to hash. The trace still registers them as inputs, and their
    // handle is the public value -- which claims no confidentiality, because
    // the operand is public by construction. Only the manifest's own
    // classification enables this path, so a genuinely missing ciphertext still
    // fails.
    if (fheHandles.isPublicConstant?.(leafIndex, side)) {
      return ciphertextHandleForClear(value);
    }
    throw new Error(
      `ciphertext manifest has no input handle for leaf ${leafIndex} ${side} of ${fheHandles.workloadId}`
    );
  };
  const resultHandle = (leafIndex, claimed) =>
    (fheHandles ? fheHandles.leafResultHandles[leafIndex] : ciphertextHandleForClear(claimed));

  const explicit = explicitTraceReferences(programLeaves);
  if (explicit) return leaves.map((leaf, i) => {
    const handle = (ref, side) => ref.kind === "constant" ? ciphertextHandleForClear(ref.value)
      : ref.kind === "output" ? resultHandle(ref.index, leaves[ref.index].claimed)
      : inputHandle(programLeaves[i][side], i, side);
    return { refs: explicit[i], lhsHandle: handle(explicit[i].lhs, "lhs"),
      rhsHandle: handle(explicit[i].rhs, "rhs"), claimedHandle: resultHandle(i, leaf.claimed) };
  });
  return leaves.map((leaf, leafIndex) => {
    const previous = leafIndex > 0 ? leaves[leafIndex - 1] : null;
    const programLeaf = programLeaves[leafIndex];
    const previousProgramLeaf = leafIndex > 0 ? programLeaves[leafIndex - 1] : null;
    const lhsFromPrevious =
      previousProgramLeaf !== null &&
      BigInt(programLeaf.lhs) === BigInt(previousProgramLeaf.claimed);
    const rhsFromPrevious =
      previousProgramLeaf !== null &&
      BigInt(programLeaf.rhs) === BigInt(previousProgramLeaf.claimed);
    return {
      lhsFromPrevious,
      rhsFromPrevious,
      lhsHandle: lhsFromPrevious
        ? resultHandle(leafIndex - 1, previous.claimed)
        : inputHandle(programLeaf.lhs, leafIndex, "lhs"),
      rhsHandle: rhsFromPrevious
        ? resultHandle(leafIndex - 1, previous.claimed)
        : inputHandle(programLeaf.rhs, leafIndex, "rhs"),
      claimedHandle: resultHandle(leafIndex, leaf.claimed)
    };
  });
}

/**
 * Returns the trace leaves carrying the three ciphertext handles they commit
 * to. Callers build the trace Merkle tree from the RESULT of this function; the
 * clear `lhs`/`rhs`/`claimed` fields are preserved for off-chain bookkeeping
 * (printing, reference checks) and are stripped before anything is sent on
 * chain by `traceLeafClaim`.
 */
export function attachTraceHandles(leaves, programLeaves = leaves, fheHandles = null) {
  const handles = resolveTraceHandles(leaves, programLeaves, fheHandles);
  return leaves.map((leaf, leafIndex) => ({
    ...leaf,
    lhsHandle: handles[leafIndex].lhsHandle,
    rhsHandle: handles[leafIndex].rhsHandle,
    claimedHandle: handles[leafIndex].claimedHandle
  }));
}

export function buildAuthenticatedTracePlan(
  taskId, leaves, inputOwner, programLeaves = leaves, fheHandles = null
) {
  const traceHandles = resolveTraceHandles(leaves, programLeaves, fheHandles);
  const inputRecords = [];
  const provenanceLeaves = [];

  function addInput(ciphertextHandle, leafIndex, side) {
    const metadataHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "uint32", "string"],
        [taskId, leafIndex, side]
      )
    );
    const recordHash = authenticatedInputRecordHash(
      typeof inputOwner === "string" ? inputOwner : inputOwner[leafIndex],
      ciphertextHandle,
      metadataHash
    );
    const sourceIndex = inputRecords.length;
    inputRecords.push({ ciphertextHandle, metadataHash, recordHash, sourceIndex });
    return { sourceIndex, recordHash, ciphertextHandle };
  }

  // Register each original record once, in its public index order. Regional
  // circuits visit cell inputs before rating inputs, so traversal order is not
  // an input identity. Repeated uses must carry the exact same ciphertext.
  if (traceHandles[0].refs) {
    const originals = new Map();
    traceHandles.forEach(handles => {
      for (const side of ["lhs", "rhs"]) {
        const ref = handles.refs[side];
        if (ref.kind !== "input") continue;
        const old = originals.get(ref.index), handle = handles[`${side}Handle`];
        if (old && old !== handle) throw new Error(`input ${ref.index} has inconsistent ciphertexts`);
        originals.set(ref.index, handle);
      }
    });
    for (const [index, handle] of [...originals].sort((a, b) => a[0] - b[0])) addInput(handle, index, "record");
  }
  leaves.forEach((leaf, leafIndex) => {
    if (traceHandles[leafIndex].refs) {
      const handles = traceHandles[leafIndex];
      const record = { opcode: leaf.opcode, lhsHandle: handles.lhsHandle,
        rhsHandle: handles.rhsHandle, claimedHandle: handles.claimedHandle };
      for (const side of ["lhs", "rhs"]) {
        const ref = handles.refs[side];
        record[`${side}SourceKind`] = ref.kind === "input" ? provenanceSource.AUTHENTICATED_INPUT
          : ref.kind === "output" ? provenanceSource.PREVIOUS_OUTPUT : provenanceSource.PUBLIC_CONSTANT;
        record[`${side}SourceIndex`] = ref.kind === "constant" ? 0 : ref.index;
        record[`${side}InputRecord`] = ref.kind === "input" ? inputRecords[ref.index].recordHash : ethers.ZeroHash;
      }
      provenanceLeaves.push(record);
      return;
    }
    const { lhsFromPrevious, rhsFromPrevious, lhsHandle, rhsHandle, claimedHandle } =
      traceHandles[leafIndex];
    const lhsInput = lhsFromPrevious ? null : addInput(lhsHandle, leafIndex, "lhs");
    const rhsInput = rhsFromPrevious ? null : addInput(rhsHandle, leafIndex, "rhs");
    // A disclosed leaf carries STRUCTURE ONLY: the opcode, the three handles
    // and where each operand came from. No operand value is published, so the
    // reveal-or-slash obligation is on the shape of the computation, not on
    // anybody's data.
    provenanceLeaves.push({
      opcode: leaf.opcode,
      lhsHandle,
      rhsHandle,
      claimedHandle,
      lhsSourceKind: lhsFromPrevious
        ? provenanceSource.PREVIOUS_OUTPUT
        : provenanceSource.AUTHENTICATED_INPUT,
      lhsSourceIndex: lhsFromPrevious ? leafIndex - 1 : lhsInput.sourceIndex,
      lhsInputRecord: lhsFromPrevious ? ethers.ZeroHash : lhsInput.recordHash,
      rhsSourceKind: rhsFromPrevious
        ? provenanceSource.PREVIOUS_OUTPUT
        : provenanceSource.AUTHENTICATED_INPUT,
      rhsSourceIndex: rhsFromPrevious ? leafIndex - 1 : rhsInput.sourceIndex,
      rhsInputRecord: rhsFromPrevious ? ethers.ZeroHash : rhsInput.recordHash
    });
  });

  const paddedInputCount = nextPowerOfTwo(Math.max(1, inputRecords.length));
  while (inputRecords.length < paddedInputCount) {
    const sourceIndex = inputRecords.length;
    const ciphertextHandle = paddingInputHandle(taskId, sourceIndex);
    const metadataHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "uint32", "string"],
        [taskId, sourceIndex, "padding"]
      )
    );
    inputRecords.push({
      ciphertextHandle,
      metadataHash,
      recordHash: authenticatedInputRecordHash(typeof inputOwner === "string" ? inputOwner : inputOwner[0], ciphertextHandle, metadataHash),
      sourceIndex
    });
  }

  const inputTree = buildMerkleTreeFromLeafHashes(inputRecords.map((record) => record.recordHash));
  const programHashes = provenanceLeaves.map((leaf, leafIndex) =>
    ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "bytes32", "bytes32", "uint32", "uint8", "uint8", "uint32",
          "uint8", "uint32", "uint256", "uint256"
        ],
        [
          authenticatedProgramLeafTypehash,
          taskId,
          leafIndex,
          programLeaves[leafIndex].opcode,
          leaf.lhsSourceKind,
          leaf.lhsSourceIndex,
          leaf.rhsSourceKind,
          leaf.rhsSourceIndex,
          // A PUBLIC_CONSTANT operand's handle IS its 32-byte big-endian
          // encoding (that is what makes it public), so the program root keeps
          // binding the constant itself without the leaf carrying a separate
          // clear field. Every other source kind contributes 0, exactly as
          // before.
          leaf.lhsSourceKind === provenanceSource.PUBLIC_CONSTANT
            ? BigInt(leaf.lhsHandle)
            : 0,
          leaf.rhsSourceKind === provenanceSource.PUBLIC_CONSTANT
            ? BigInt(leaf.rhsHandle)
            : 0
        ]
      )
    )
  );
  const provenanceHashes = provenanceLeaves.map((leaf, leafIndex) =>
    ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "bytes32", "bytes32", "uint32", "bytes32", "bytes32", "bytes32",
          "bytes32", "uint8", "uint32", "bytes32", "uint8", "uint32", "bytes32"
        ],
        [
          authenticatedProvenanceLeafTypehash,
          taskId,
          leafIndex,
          leafHash(leaf),
          leaf.lhsHandle,
          leaf.rhsHandle,
          leaf.claimedHandle,
          leaf.lhsSourceKind,
          leaf.lhsSourceIndex,
          leaf.lhsInputRecord,
          leaf.rhsSourceKind,
          leaf.rhsSourceIndex,
          leaf.rhsInputRecord
        ]
      )
    )
  );
  const programTree = buildMerkleTreeFromLeafHashes(programHashes);
  const provenanceTree = buildMerkleTreeFromLeafHashes(provenanceHashes);

  const disclosureLeaves = provenanceLeaves.map((leaf) => ({
    leaf,
    lhsInputProof:
      leaf.lhsSourceKind === provenanceSource.AUTHENTICATED_INPUT
        ? merkleProofForLeafHashTree(inputTree, leaf.lhsSourceIndex).proof
        : [],
    rhsInputProof:
      leaf.rhsSourceKind === provenanceSource.AUTHENTICATED_INPUT
        ? merkleProofForLeafHashTree(inputTree, leaf.rhsSourceIndex).proof
        : []
  }));

  return {
    inputRecords,
    inputTree,
    programTree,
    provenanceTree,
    provenanceLeaves,
    disclosureLeaves
  };
}

export async function authorizeAuthenticatedTask({
  availability,
  requester,
  operatorAddress,
  taskId,
  tree,
  leaves,
  resultHash,
  outputAttestationHash,
  programLeaves = leaves,
  recordTransaction = null,
  authorizationLifetimeSeconds = 3600,
  fheHandles = null
}) {
  const plan = buildAuthenticatedTracePlan(
    taskId,
    leaves,
    requester.address,
    programLeaves,
    fheHandles
  );
  const registrationPromise = availability.connect(requester).registerInputOrigins(
    plan.inputRecords.map((record) => record.ciphertextHandle),
    plan.inputRecords.map((record) => record.metadataHash)
  );
  if (recordTransaction) {
    await recordTransaction("registerInputOrigins", registrationPromise, {
      taskId,
      inputCount: plan.inputRecords.length,
      inputRoot: plan.inputTree.root
    });
  } else {
    await awaitReceipt(await registrationPromise, "registration");
  }
  // On a real network `getBlock("latest")` can transiently return null (the
  // node answers between blocks, or a poll lands during a view change), so read
  // the head defensively and fall back to the raw RPC result.
  let latestBlock = await requester.provider.getBlock("latest");
  for (let attempt = 0; latestBlock === null && attempt < 10; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    latestBlock = await requester.provider.getBlock("latest");
  }
  if (latestBlock === null) {
    const raw = await requester.provider.send("eth_getBlockByNumber", ["latest", false]);
    if (!raw) throw new Error("chain returned no latest block while authorizing the task");
    latestBlock = { timestamp: Number(BigInt(raw.timestamp)) };
  }
  const authorizationPromise = availability.connect(requester).authorizeTaskStatement(
      taskId,
      operatorAddress,
      tree.root,
      resultHash,
      plan.inputTree.root,
      plan.inputTree.leafCount,
      plan.programTree.root,
      plan.provenanceTree.root,
      tree.leafCount,
      outputAttestationHash,
      Number(latestBlock.timestamp) + authorizationLifetimeSeconds
    );
  if (recordTransaction) {
    await recordTransaction("authorizeTaskStatement", authorizationPromise, {
      taskId,
      requester: requester.address,
      operator: operatorAddress,
      inputRoot: plan.inputTree.root,
      programRoot: plan.programTree.root,
      provenanceRoot: plan.provenanceTree.root
    });
  } else {
    await awaitReceipt(await authorizationPromise, "authorization");
  }
  return plan;
}

export async function publishAuthenticatedDisputeTrace({
  availability,
  operator,
  taskId,
  plan,
  batchSize = 8
}) {
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    throw new Error("batchSize must be a positive integer");
  }
  const receipts = [];
  for (let start = 0; start < plan.disclosureLeaves.length; start += batchSize) {
    const batch = plan.disclosureLeaves.slice(start, start + batchSize);
    receipts.push(
      await awaitReceipt(
        await availability.connect(operator).publishDisputedTraceBatch(
          taskId,
          batch.map((disclosure) => disclosure.leaf),
          batch.map((disclosure) => disclosure.lhsInputProof),
          batch.map((disclosure) => disclosure.rhsInputProof)
        ),
        "publishDisputedTraceBatch"
      )
    );
  }
  return receipts;
}

// V3: the accusation is stated over ciphertext handles. An auditor that
// disagrees with a leaf commits to WHICH leaf and to the two competing result
// ciphertexts, never to the values behind them; the digest is still binding
// (handles are collision-resistant commitments) and is still recomputed
// on-chain from the terminal LeafClaim pair.
export const challengeErrorTypehash = ethers.keccak256(
  ethers.toUtf8Bytes(
    "FHE_POD_CHALLENGE_V3(bytes32 taskId,uint32 leafIndex,uint8 opcode,bytes32 operatorLhsHandle,bytes32 operatorRhsHandle,bytes32 operatorClaimedHandle,bytes32 challengerLhsHandle,bytes32 challengerRhsHandle,bytes32 challengerClaimedHandle)"
  )
);

export function challengeErrorDigest(taskId, leafIndex, operatorLeaf, challengerLeaf) {
  const operator = traceLeafHandles(operatorLeaf);
  const challenger = traceLeafHandles(challengerLeaf);
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32",
        "bytes32",
        "uint32",
        "uint8",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32"
      ],
      [
        challengeErrorTypehash,
        taskId,
        leafIndex,
        operatorLeaf.opcode,
        operator.lhsHandle,
        operator.rhsHandle,
        operator.claimedHandle,
        challenger.lhsHandle,
        challenger.rhsHandle,
        challenger.claimedHandle
      ]
    )
  );
}

export function auditTraceLeafHash(taskId, auditorAddress, auditTraceLeaf) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "uint32", "bytes32", "bytes32", "bytes32"],
      [
        taskId,
        auditorAddress,
        auditTraceLeaf.leafIndex,
        auditTraceLeaf.operatorLeafHash,
        auditTraceLeaf.recomputedLeafHash,
        auditTraceLeaf.errorDigest
      ]
    )
  );
}

export const diligenceCheckpointTypehash = ethers.keccak256(
  ethers.toUtf8Bytes(
    "FHE_POD_DILIGENCE_CHECKPOINT_V1(bytes32 taskId,address auditor,bytes32 operatorTraceRoot,uint32 leafIndex,uint32 checkpointIndex,bytes32 operatorLeafHash,bytes32 recomputedLeafHash,bytes32 previousCheckpointHash,bytes32 nextCheckpointHash,bytes32 transcriptDigest)"
  )
);

export const diligenceCheckpointSpace = 7;

export function auditDiligenceCheckpointHash(
  taskId,
  auditorAddress,
  operatorTraceRoot,
  checkpoint
) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32",
        "bytes32",
        "address",
        "bytes32",
        "uint32",
        "uint32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32"
      ],
      [
        diligenceCheckpointTypehash,
        taskId,
        auditorAddress,
        operatorTraceRoot,
        checkpoint.leafIndex,
        checkpoint.checkpointIndex,
        checkpoint.operatorLeafHash,
        checkpoint.recomputedLeafHash,
        checkpoint.previousCheckpointHash,
        checkpoint.nextCheckpointHash,
        checkpoint.transcriptDigest
      ]
    )
  );
}

export function buildMerkleTreeFromLeafHashes(leafHashes) {
  if (!Array.isArray(leafHashes) || leafHashes.length === 0) {
    throw new Error("Merkle tree requires at least one leaf hash");
  }
  if ((leafHashes.length & (leafHashes.length - 1)) !== 0) {
    throw new Error("Merkle tree leaf count must be a power of two");
  }

  const levels = [leafHashes];
  let currentLevel = leafHashes;

  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let index = 0; index < currentLevel.length; index += 2) {
      nextLevel.push(
        ethers.solidityPackedKeccak256(
          ["bytes32", "bytes32"],
          [currentLevel[index], currentLevel[index + 1]]
        )
      );
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    root: currentLevel[0],
    levels,
    leafCount: leafHashes.length
  };
}

export function merkleProofForLeafHashTree(tree, leafIndex) {
  if (leafIndex < 0 || leafIndex >= tree.levels[0].length) {
    throw new Error("leaf index out of bounds");
  }

  const proof = [];
  const proofSiblingOnLeft = [];
  let index = leafIndex;

  for (let levelIndex = 0; levelIndex < tree.levels.length - 1; levelIndex += 1) {
    const level = tree.levels[levelIndex];
    const siblingIndex = index ^ 1;
    proof.push(level[siblingIndex]);
    proofSiblingOnLeft.push(siblingIndex < index);
    index = Math.floor(index / 2);
  }

  return { proof, proofSiblingOnLeft };
}

// --- Terminal output binding -------------------------------------------------
// The published result commitment is no longer a free operator claim: the
// contract requires resultHash == keccak256(abi.encode(typehash, taskId,
// operatorTraceRoot, leafCount, terminalLeaf.claimedHandle,
// outputAttestationHash)) together with a Merkle proof that terminalLeaf is the
// LAST leaf of the committed trace. These helpers derive the canonical binding
// off-chain so operators can create tasks and consumers can independently
// verify that a published output matches the committed execution trace.
//
// V2 binds the terminal output HANDLE rather than the terminal output value.
// The trace leaf commits to handles now, so the terminal leaf tuple carries no
// clear value to bind to; and a chain that adjudicates encrypted execution
// cannot see the plaintext output anyway. A consumer verifies as before, with
// one extra (already necessary) step: it checks that the ciphertext it was
// given hashes to the bound handle, and decrypts it under its own
// authorization. The attestation hash still commits to the published encrypted
// output, so substituting either the ciphertext or the trace still fails.
export const outputBindingTypehash = ethers.keccak256(
  ethers.toUtf8Bytes(
    "FHE_POD_OUTPUT_BINDING_V2(bytes32 taskId,bytes32 operatorTraceRoot,uint32 leafCount,bytes32 terminalOutputHandle,bytes32 outputAttestationHash)"
  )
);

export function computeBoundResultHash(
  taskId,
  operatorTraceRoot,
  leafCount,
  terminalOutputHandle,
  outputAttestationHash
) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "uint32", "bytes32", "bytes32"],
      [
        outputBindingTypehash,
        taskId,
        operatorTraceRoot,
        leafCount,
        terminalOutputHandle,
        outputAttestationHash
      ]
    )
  );
}

export function terminalOutputBinding(taskId, tree, treeLeaves, outputAttestationHash) {
  if (!Array.isArray(treeLeaves) || treeLeaves.length !== tree.leafCount) {
    throw new Error("treeLeaves must match the committed tree leaf count");
  }
  const terminalIndex = tree.leafCount - 1;
  const terminalLeaf = traceLeafClaim(treeLeaves[terminalIndex]);
  const { proof } = merkleProofForLeafHashTree(tree, terminalIndex);
  const resultHash = computeBoundResultHash(
    taskId,
    tree.root,
    tree.leafCount,
    terminalLeaf.claimedHandle,
    outputAttestationHash
  );
  return {
    resultHash,
    terminalLeaf: [
      terminalLeaf.opcode,
      terminalLeaf.lhsHandle,
      terminalLeaf.rhsHandle,
      terminalLeaf.claimedHandle
    ],
    terminalLeafProof: proof,
    outputAttestationHash
  };
}

export function boundCreateTaskArgs(taskId, tree, treeLeaves, outputAttestationHash) {
  const binding = terminalOutputBinding(taskId, tree, treeLeaves, outputAttestationHash);
  return [
    taskId,
    tree.root,
    binding.resultHash,
    tree.leafCount,
    binding.terminalLeaf,
    binding.terminalLeafProof,
    outputAttestationHash
  ];
}

export function verifyPublishedOutputBinding({
  taskId,
  operatorTraceRoot,
  leafCount,
  publishedOutputHandle,
  outputAttestationHash,
  onChainResultHash
}) {
  const recomputed = computeBoundResultHash(
    taskId,
    operatorTraceRoot,
    leafCount,
    publishedOutputHandle,
    outputAttestationHash
  );
  return recomputed.toLowerCase() === String(onChainResultHash).toLowerCase();
}

export function buildAuditDiligenceCheckpoint(
  taskId,
  auditorAddress,
  operatorTraceRoot,
  leafIndex,
  operatorLeaf,
  recomputedLeaf,
  checkpointIndex = 0
) {
  const operatorLeafHash = leafHash(operatorLeaf);
  const recomputedLeafHash = leafHash(recomputedLeaf);
  const checkpoint = {
    leafIndex,
    checkpointIndex,
    operatorLeafHash,
    recomputedLeafHash,
    previousCheckpointHash: ethers.ZeroHash,
    nextCheckpointHash: ethers.ZeroHash,
    transcriptDigest: ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "bytes32",
          "address",
          "bytes32",
          "uint32",
          "uint32",
          "bytes32",
          "bytes32"
        ],
        [
          taskId,
          auditorAddress,
          operatorTraceRoot,
          leafIndex,
          checkpointIndex,
          operatorLeafHash,
          recomputedLeafHash
        ]
      )
    )
  };
  return {
    checkpoint,
    checkpointHash: auditDiligenceCheckpointHash(
      taskId,
      auditorAddress,
      operatorTraceRoot,
      checkpoint
    )
  };
}

export function buildSingleLeafAuditTranscript(taskId, auditorAddress, auditTraceLeaf) {
  const leafHashValue = auditTraceLeafHash(taskId, auditorAddress, auditTraceLeaf);
  return {
    root: leafHashValue,
    leafHash: leafHashValue,
    proof: [],
    proofSiblingOnLeft: [],
    leaves: [auditTraceLeaf]
  };
}

export function buildAuditTranscript({
  taskId,
  auditorAddress,
  operatorTraceRoot,
  auditTraceLeaf,
  operatorLeaf,
  recomputedLeaf
}) {
  const challengeLeafHash = auditTraceLeafHash(taskId, auditorAddress, auditTraceLeaf);
  const diligenceCheckpoints = [];
  const diligenceCheckpointHashes = [];
  for (let checkpointIndex = 0; checkpointIndex < diligenceCheckpointSpace; checkpointIndex += 1) {
    const { checkpoint, checkpointHash } = buildAuditDiligenceCheckpoint(
      taskId,
      auditorAddress,
      operatorTraceRoot,
      auditTraceLeaf.leafIndex,
      operatorLeaf,
      recomputedLeaf,
      checkpointIndex
    );
    diligenceCheckpoints.push(checkpoint);
    diligenceCheckpointHashes.push(checkpointHash);
  }
  const challengeLeafIndex = diligenceCheckpointSpace;
  const tree = buildMerkleTreeFromLeafHashes([
    ...diligenceCheckpointHashes,
    challengeLeafHash
  ]);
  const challengeProof = merkleProofForLeafHashTree(tree, challengeLeafIndex);

  return {
    root: tree.root,
    leafHash: challengeLeafHash,
    proof: challengeProof.proof,
    proofSiblingOnLeft: challengeProof.proofSiblingOnLeft,
    diligenceCheckpoints,
    diligenceCheckpointHashes,
    leaves: [auditTraceLeaf]
  };
}

export function selectAuditDiligenceCheckpoint(auditTranscript, checkpointIndex) {
  const resolvedIndex = Number(checkpointIndex);
  if (
    !Number.isInteger(resolvedIndex) ||
    resolvedIndex < 0 ||
    resolvedIndex >= auditTranscript.diligenceCheckpoints.length
  ) {
    throw new Error(`Bad diligence checkpoint index: ${checkpointIndex}`);
  }
  const tree = buildMerkleTreeFromLeafHashes([
    ...auditTranscript.diligenceCheckpointHashes,
    auditTranscript.leafHash
  ]);
  const checkpointProof = merkleProofForLeafHashTree(tree, resolvedIndex);
  return {
    diligenceCheckpoint: auditTranscript.diligenceCheckpoints[resolvedIndex],
    diligenceCheckpointHash: auditTranscript.diligenceCheckpointHashes[resolvedIndex],
    diligenceProof: checkpointProof.proof,
    diligenceProofSiblingOnLeft: checkpointProof.proofSiblingOnLeft
  };
}

export function buildMerkleTree(leaves) {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error("Merkle tree requires at least one leaf");
  }

  const hashedLeaves = leaves.map(leafHash);
  const levels = [hashedLeaves];
  let currentLevel = hashedLeaves;

  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let index = 0; index < currentLevel.length; index += 2) {
      nextLevel.push(
        ethers.solidityPackedKeccak256(
          ["bytes32", "bytes32"],
          [currentLevel[index], currentLevel[index + 1]]
        )
      );
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    root: currentLevel[0],
    levels,
    leafCount: hashedLeaves.length
  };
}

export function getSubtreeChildren(tree, start, end) {
  const span = end - start;
  if (span <= 1 || (span & (span - 1)) !== 0) {
    throw new Error("Subtree span must be a power of two greater than one");
  }

  const levelIndex = Math.log2(span);
  const level = tree.levels[levelIndex];
  const nodeIndex = start / span;
  const childLevel = tree.levels[levelIndex - 1];
  const leftIndex = nodeIndex * 2;
  const rightIndex = leftIndex + 1;

  return {
    left: childLevel[leftIndex],
    right: childLevel[rightIndex]
  };
}

export function mutateLeafClaim(leaf, overrides = {}) {
  return {
    ...leaf,
    ...overrides
  };
}
