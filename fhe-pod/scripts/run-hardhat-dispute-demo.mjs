import hre from "hardhat";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { ethers } from "ethers";
import {
  attachTraceHandles,
  authorizeAuthenticatedTask,
  boundCreateTaskArgs,
  sampleTaskParticipants,
  buildAuditTranscript,
  buildMerkleTree,
  challengeErrorDigest,
  ciphertextHandleForClear,
  compileContracts,
  getSubtreeChildren,
  leafHash,
  loadRunArtifacts,
  selectAuditDiligenceCheckpoint,
  terminalOutputBinding,
  traceLeafClaim,
  writeJson
} from "./evm-lib.mjs";
// The corruption the dishonest operator applies is declared once, in the
// lowering module, and is also what scripts/export-traces-for-fhe.mjs exports
// for the TFHE executor; importing it here is what keeps the trace committed
// on-chain and the trace executed under encryption the same object.
import { deriveDishonestLeaves } from "./application-lowering.mjs";
import {
  assertHandlesMatchTrace,
  ciphertextDirPath,
  ciphertextManifestPath,
  fheHandlesForWorkload,
  loadCiphertextManifest,
  podRootPath,
  requireFheHandles
} from "./fhe-handles.mjs";
// The isolated leaf is decided by evaluating FHE.eq over ciphertexts, not by
// comparing ciphertext bytes; see the module header for why byte equality is
// unsound here.
import { decideLeaf, resultCiphertextPath } from "./leaf-decision.mjs";

const supportedOperations = [
  { opcode: 1, name: "MUL", expression: "claimed == lhs * rhs", sample: [12, 5, 60] },
  { opcode: 2, name: "SHR", expression: "claimed == lhs >> rhs", sample: [60, 2, 15] },
  { opcode: 3, name: "CAST_U8", expression: "claimed == uint8(lhs)", sample: [257, 0, 1] },
  { opcode: 4, name: "MIN", expression: "claimed == min(lhs, rhs)", sample: [15, 7, 7] },
  { opcode: 5, name: "BITAND", expression: "claimed == lhs & rhs", sample: [7, 1, 1] },
  { opcode: 6, name: "ADD", expression: "claimed == lhs + rhs", sample: [10, 4, 14] },
  { opcode: 7, name: "SUB", expression: "claimed == lhs - rhs", sample: [10, 4, 6] },
  { opcode: 8, name: "DIV", expression: "rhs != 0 && claimed == lhs / rhs", sample: [20, 4, 5] },
  { opcode: 9, name: "MOD", expression: "rhs != 0 && claimed == lhs % rhs", sample: [22, 5, 2] },
  { opcode: 10, name: "EQ", expression: "claimed == (lhs == rhs ? 1 : 0)", sample: [9, 9, 1] },
  { opcode: 11, name: "LT", expression: "claimed == (lhs < rhs ? 1 : 0)", sample: [8, 9, 1] },
  { opcode: 12, name: "GT", expression: "claimed == (lhs > rhs ? 1 : 0)", sample: [10, 9, 1] },
  { opcode: 13, name: "BITOR", expression: "claimed == lhs | rhs", sample: [4, 1, 5] },
  { opcode: 14, name: "BITXOR", expression: "claimed == lhs ^ rhs", sample: [7, 3, 4] },
  { opcode: 15, name: "ADD_CHAIN", expression: "claimed == lhs after rhs repeated +1 steps (1 <= rhs <= 8)", sample: [10, 4, 14] }
];

const transactionLog = [];

function transactionGasMetadata(receipt, transactionResponse) {
  const gasUsed = receipt.gasUsed ?? 0n;
  const receiptFee = receipt.fee ?? null;
  const effectiveGasPrice =
    receipt.gasPrice ?? receipt.effectiveGasPrice ?? transactionResponse.gasPrice ?? 0n;
  const transactionCostWei = receiptFee ?? (gasUsed * effectiveGasPrice);
  return {
    gasUsed: gasUsed.toString(),
    effectiveGasPriceWei: effectiveGasPrice.toString(),
    gasPriceWei: effectiveGasPrice.toString(),
    transactionCostWei: transactionCostWei.toString(),
    transactionCostSource: receiptFee !== null ? "receipt.fee" : "gasUsed*effectiveGasPrice"
  };
}

function parseIntegerEnv(name, fallback, { min = 0 } = {}) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${name} must be an integer >= ${min}; received ${raw}`);
  }
  return value;
}

const configuredAuditorCount =
  process.env.DEMO_AUDITOR_COUNT !== undefined
    ? parseIntegerEnv("DEMO_AUDITOR_COUNT", 3, { min: 3 })
    : parseIntegerEnv("DEMO_NODE_COUNT", 3, { min: 3 });

const demoConfig = {
  auditorCount: configuredAuditorCount,
  decryptorCount: parseIntegerEnv("DEMO_DECRYPTOR_COUNT", 3, { min: 3 }),
  commitWindowSeconds: parseIntegerEnv("DEMO_COMMIT_WINDOW_SECONDS", 20, { min: 1 }),
  openWindowSeconds: parseIntegerEnv("DEMO_OPEN_WINDOW_SECONDS", 20, { min: 1 }),
  challengeWindowSeconds: parseIntegerEnv("DEMO_CHALLENGE_WINDOW_SECONDS", 20, { min: 1 }),
  // Disclosure window for the authenticated trace-availability module.
  //
  // This is a SEPARATE deployment parameter, and it must be sized by the rule
  // the implementation states: a trace of N leaves published k at a time needs
  // b = ceil(N/k) SEQUENTIAL batches, so the window has to exceed b*Delta plus
  // a finality margin, where Delta is the inclusion time of one transaction.
  //
  // It used to be wired to `challengeWindowSeconds`, which silently violated
  // that rule. On the validator network Delta is about eight seconds, and the
  // largest evaluated trace (64 leaves, 8 per batch) needs eight batches, so
  // roughly 64 s of strictly sequential traffic inside a 40 s window. The sixth
  // batch reverted past the deadline and aborted the campaign on the regulatory
  // workload. Batches cannot be parallelised: the contract reconstructs the
  // Merkle frontier incrementally and requires strictly increasing leaf
  // indices, so more time is the only correct answer here.
  //
  // The default below covers the largest evaluated trace with margin. Raise it
  // for longer traces or a slower chain; the sizing rule, not this number, is
  // the thing to preserve.
  disclosureWindowSeconds: parseIntegerEnv("DEMO_DISCLOSURE_WINDOW_SECONDS", 300, { min: 1 }),
  manipulatedLeafIndex: parseIntegerEnv("DEMO_MANIPULATED_LEAF_INDEX", 4, { min: 0 }),
  repetition: process.env.DEMO_REPETITION ?? "1",
  skipSurfaceChecks: process.env.DEMO_SKIP_SURFACE_CHECKS === "1",
  // Verdict-opening backend:
  //   off       - commit-reveal committee (openVerdict), the modeled path;
  //   synthetic - openVerdictViaKMS with locally signed KMS-format EIP-712
  //               signatures (correctness/gas of the real contract path);
  //   artifact  - openVerdictViaKMS replaying real Zama KMS threshold
  //               decryptions recorded by threshold-kms/scripts/
  //               run-kms-onchain-opening.mjs (requires
  //               FHE_POD_KMS_ARTIFACT and FHE_POD_KMS_VERIFIER).
  kmsOpening: process.env.FHE_POD_KMS_OPENING ?? "off",
  kmsArtifactPath: process.env.FHE_POD_KMS_ARTIFACT ?? null,
  kmsVerifierAddress: process.env.FHE_POD_KMS_VERIFIER ?? null
};
if (!["off", "synthetic", "artifact"].includes(demoConfig.kmsOpening)) {
  throw new Error(
    `FHE_POD_KMS_OPENING must be off|synthetic|artifact; received ${demoConfig.kmsOpening}`
  );
}

function printLine(message = "") {
  console.log(message);
}

function printTitle(title) {
  printLine("");
  printLine("============================================================");
  printLine(title);
  printLine("============================================================");
}

function printStep(number, title, details = []) {
  printLine("");
  printLine(`[${number}] ${title}`);
  for (const detail of details) {
    printLine(`    - ${detail}`);
  }
}

function shortHash(value) {
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function printEvent(emoji, label, extras = []) {
  const suffix = extras.filter(Boolean).join(" | ");
  console.log(`    ${emoji} ${label}${suffix ? "  " + suffix : ""}`);
}

/**
 * Receipt timeout, milliseconds.
 *
 * `tx.wait()` waits FOREVER by default. On a consensus chain a transaction can
 * be dropped from the pool -- a nonce collision with another process using the
 * same mnemonic is the usual cause -- and the driver then hangs with no output
 * and no error, in the middle of a run that takes hours. Observed once: a hang
 * of 1 h 39 min before anyone noticed. Every wait here is bounded and says what
 * to check.
 */
const RECEIPT_TIMEOUT_MS = Number(process.env.FHE_POD_RECEIPT_TIMEOUT_MS || 180_000);

/** Awaits a receipt with a bound, failing loudly instead of hanging. */
async function awaitReceipt(tx, label) {
  const receipt = await tx.wait(1, RECEIPT_TIMEOUT_MS);
  if (receipt === null) {
    throw new Error(
      `timed out after ${RECEIPT_TIMEOUT_MS} ms waiting for the receipt of ` +
        `"${label}" (tx ${tx.hash}). The transaction was accepted but never ` +
        "mined. Is another process sending from the same accounts?"
    );
  }
  return receipt;
}

async function recordTx(label, txPromise, metadata = {}) {
  const start = performance.now();
  // Epoch stamps, not only a duration. `durationMs` measures one transaction in
  // isolation and cannot express the time BETWEEN transactions, which is where
  // the protocol windows elapse. Recording when each transaction was sent and
  // when it was mined lets any phase of the run be measured after the fact:
  // the dispute wall clock reported by the implementation is the interval from the
  // `openChallenge` submission to the mining of the leaf settlement, and it is
  // derived from these two fields in run-application-layer-evaluation.mjs.
  const startedAtMs = Date.now();
  const tx = await txPromise;
  const receipt = await awaitReceipt(tx, label);
  const durationMs = Math.round(performance.now() - start);
  const minedAtMs = Date.now();
  const gasMetadata = transactionGasMetadata(receipt, tx);
  transactionLog.push({
    label,
    hash: tx.hash,
    blockNumber: Number(receipt.blockNumber),
    status: Number(receipt.status),
    durationMs,
    startedAtMs,
    minedAtMs,
    ...gasMetadata,
    ...metadata
  });
  printEvent(
    receipt.status === 1 ? "\u2714" : "\u2718",
    label,
    [
      `gas=${gasMetadata.gasUsed}`,
      `block=${receipt.blockNumber}`,
      metadata.taskId ? `task=${shortHash(metadata.taskId)}` : null,
      metadata.operator ? `operator=${shortHash(metadata.operator)}` : null,
      metadata.auditor ? `auditor=${shortHash(metadata.auditor)}` : null,
      metadata.decryptor ? `decryptor=${shortHash(metadata.decryptor)}` : null,
      metadata.verdict !== undefined ? `verdict=${metadata.verdict}` : null,
      metadata.operation ? `op=${metadata.operation}` : null,
      metadata.operatorValid !== undefined ? `opValid=${metadata.operatorValid}` : null,
      metadata.challengerValid !== undefined ? `chValid=${metadata.challengerValid}` : null
    ]
  );
  return receipt;
}

async function recordDeployment(label, contract, metadata = {}) {
  const start = performance.now();
  const startedAtMs = Date.now();
  await contract.waitForDeployment();
  const tx = contract.deploymentTransaction();
  if (!tx) return;
  const receipt = await awaitReceipt(tx, label);
  const durationMs = Math.round(performance.now() - start);
  const minedAtMs = Date.now();
  const address = await contract.getAddress();
  const gasMetadata = transactionGasMetadata(receipt, tx);
  transactionLog.push({
    label,
    hash: tx.hash,
    blockNumber: Number(receipt.blockNumber),
    status: Number(receipt.status),
    durationMs,
    startedAtMs,
    minedAtMs,
    ...gasMetadata,
    address,
    ...metadata
  });
  printEvent("\uD83D\uDCE6", label, [`addr=${shortHash(address)}`, `gas=${gasMetadata.gasUsed}`, `block=${receipt.blockNumber}`]);
}

function printSupportedOperations() {
  printStep("2", "Supported FHE micro-operations", [
    "The contract verifies only one revealed disputed instruction.",
    "These opcodes are small enough to be checked on a vanilla EVM."
  ]);
  for (const operation of supportedOperations) {
    printLine(
      `    opcode ${operation.opcode.toString().padStart(2, "0")} | ${operation.name.padEnd(8)} | ${operation.expression}`
    );
  }
}

function resultHashFromAttestation(attestationPayload) {
  const value = attestationPayload.result_hash_sha256;
  return value.startsWith("0x") ? value : `0x${value}`;
}

function commitmentFor(taskId, auditor, verdict, podRoot) {
  const salt = ethers.keccak256(
    ethers.toUtf8Bytes(`${taskId}:${auditor.address}:${verdict}:${podRoot}`)
  );
  const verdictCommit = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bool", "bytes32", "bytes32"],
      [verdict, salt, podRoot]
    )
  );

  return { salt, podRoot, verdict, verdictCommit };
}

// --- Threshold-KMS verdict opening (real contract path) ---------------------
// State for FHE_POD_KMS_OPENING=synthetic|artifact. In both modes the audit's
// verdictCommit is the bytes32 handle of a TFHE ebool verdict ciphertext and
// the opening transaction is openVerdictViaKMS carrying the KMS cores'
// EIP-712 signatures over (ctHandles, decryptedResult, extraData); see
// contracts/src/ZamaKMSVerdictVerifier.sol and threshold-kms/README.md.
const PUBLIC_DECRYPT_TYPES = {
  PublicDecryptVerification: [
    { name: "ctHandles", type: "bytes32[]" },
    { name: "decryptedResult", type: "bytes" },
    { name: "extraData", type: "bytes" }
  ]
};
const kmsState = {
  enabled: demoConfig.kmsOpening !== "off",
  mode: demoConfig.kmsOpening,
  verifier: null,
  verifierAddress: null,
  threshold: 2,
  domain: null,
  cores: [],
  artifact: null,
  pools: null,
  consumed: []
};

// --- Threshold-KMS leaf-decision attestation --------------------------------
// The terminal leaf of a dispute is settled from a t+1-signed attestation of
// the two equality bits (see
// VerifiableFHEDisputeGame.settleLeafViaAttestedDecision). The bits are decided
// OFF-CHAIN by comparing CIPHERTEXT HANDLES -- never values -- and the signed
// payload is the same `PublicDecryptVerification` struct `openVerdictViaKMS`
// uses, so exactly one signature scheme exists in this repository.
//
// This state is independent of FHE_POD_KMS_OPENING: verdict opening keeps its
// commit-reveal committee fallback, leaf settlement over real ciphertext
// handles has none, so the attestor is always deployed.
const leafDecisionState = {
  cores: [],
  threshold: 2,
  verifier: null,
  verifierAddress: null,
  domain: null
};

async function setupLeafDecisionAttestor(provider, deployer, artifacts) {
  const chainId = Number((await provider.getNetwork()).chainId);
  // n=4, t=1 => threshold 2 = t+1 = `num_majority`, the same shape as the
  // synthetic verdict-opening cores. Deterministic keys keep runs comparable.
  leafDecisionState.cores = Array.from({ length: 4 }, (_, index) =>
    new ethers.Wallet(
      ethers.keccak256(ethers.toUtf8Bytes(`vcfhe-leaf-decision-core:${index}`))
    )
  );
  leafDecisionState.threshold = 2;
  const verifier = await new ethers.ContractFactory(
    artifacts.ZamaKMSVerdictVerifier.abi,
    artifacts.ZamaKMSVerdictVerifier.bytecode,
    deployer
  ).deploy(
    "VCFHE-Leaf-Decision",
    "1",
    0,
    ethers.ZeroAddress,
    leafDecisionState.cores.map((core) => core.address),
    leafDecisionState.threshold
  );
  await recordDeployment("deploy:ZamaKMSLeafDecisionVerifier", verifier);
  leafDecisionState.verifier = verifier;
  leafDecisionState.verifierAddress = await verifier.getAddress();
  leafDecisionState.domain = {
    name: "VCFHE-Leaf-Decision",
    version: "1",
    chainId,
    verifyingContract: leafDecisionState.verifierAddress
  };
  return leafDecisionState;
}

/**
 * The leaf equality bits, decided HOMOMORPHICALLY.
 *
 * The leaf is recomputed from its operand ciphertexts and each party's claimed
 * result ciphertext is compared to that recomputation with `FHE.eq`; only the
 * two resulting bits are decrypted. See scripts/leaf-decision.mjs for why the
 * decision cannot be a comparison of ciphertext bytes: a handle is
 * `keccak256(safe_serialize(ciphertext))`, and two correct evaluations of the
 * same operation need not serialize to the same bytes, so byte equality can
 * reject an honest operator. Plaintext equality under encryption cannot.
 *
 * Nothing here reads, prints or transmits an operand value.
 *
 * @param {object} context  ciphertext manifest, ciphertext directory and the
 *                          per-variant result handles (null on a clear-value
 *                          fallback run, which VCFHE_REQUIRE_FHE_HANDLES=1
 *                          forbids)
 */
function decideLeafHomomorphically(context, leafIndex, operatorClaimedHandle, challengerClaimedHandle) {
  const claims = [
    { label: "operator", handle: operatorClaimedHandle },
    { label: "challenger", handle: challengerClaimedHandle }
  ].map((claim) => {
    // Which executed variant is this claim's ciphertext? The one whose stored
    // result for this leaf has exactly the handle the party put on chain. The
    // decision must be about the claim, so the ciphertext has to be bound to it.
    const wanted = String(claim.handle).toLowerCase();
    const variant = context.variants.find(
      (candidate) => String(candidate.resultHandles[leafIndex]).toLowerCase() === wanted
    );
    if (!variant) {
      throw new Error(
        `no executed variant holds a result ciphertext for leaf ${leafIndex} with handle ` +
          `${claim.handle}; the ${claim.label}'s claim cannot be adjudicated`
      );
    }
    return {
      label: claim.label,
      ciphertextPath: resultCiphertextPath(context.ciphertextDir, variant.manifestKey, leafIndex),
      expectedHandle: claim.handle
    };
  });

  const decided = decideLeaf({
    ciphertextDir: context.ciphertextDir,
    manifest: context.manifest,
    // Operands come from the honest variant: they are the statement the
    // requester authorised, which no operator can change.
    referenceKey: context.referenceKey,
    leafIndex,
    rhsScalar: context.publicScalarFor(leafIndex),
    claims
  });

  return {
    operatorValid: decided.byLabel.operator,
    challengerValid: decided.byLabel.challenger,
    detail: decided
  };
}

/**
 * Fallback for runs with no ciphertext manifest, where the "handle" IS the
 * clear value (`ciphertextHandleForClear`). There, comparing handles is
 * comparing plaintexts, which is sound for what that mode is; it is not
 * encrypted evidence, and VCFHE_REQUIRE_FHE_HANDLES=1 rejects such a run.
 */
function leafDecisionBitsFromClearHandles(
  operatorClaimedHandle,
  challengerClaimedHandle,
  referenceHandle
) {
  const same = (a, b) =>
    typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
  return {
    operatorValid: same(operatorClaimedHandle, referenceHandle),
    challengerValid: same(challengerClaimedHandle, referenceHandle)
  };
}

/**
 * t+1 core signatures over the EIP-712 digest that binds
 * (game, chainId, taskId, leafIndex, opcode) via `extraData`, the two claimed
 * handles via `ctHandles`, and the two decision bits via `decryptedResult`.
 */
async function attestLeafDecision(game, taskId, leafIndex, opcode, handles, bits) {
  const boundExtraData = await game.leafDecisionBinding(taskId, leafIndex, opcode);
  const decryptedResult = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bool", "bool"],
    [bits.operatorValid, bits.challengerValid]
  );
  const signatures = [];
  for (const core of leafDecisionState.cores.slice(0, leafDecisionState.threshold)) {
    signatures.push(
      await core.signTypedData(leafDecisionState.domain, PUBLIC_DECRYPT_TYPES, {
        ctHandles: handles,
        decryptedResult,
        extraData: boundExtraData
      })
    );
  }
  return encodeKmsDecryptionProof(signatures, boundExtraData);
}

function encodeVerdictPlaintext(bit) {
  return ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [bit ? 1n : 0n]);
}

function encodeKmsDecryptionProof(signatures, extraData = "0x") {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes[]", "bytes"],
    [signatures, extraData]
  );
}

async function setupKmsOpening(provider, deployer, artifacts) {
  if (!kmsState.enabled) return null;
  const chainId = Number((await provider.getNetwork()).chainId);
  if (kmsState.mode === "synthetic") {
    // Four deterministic local "KMS core" identities (n=4, t=1 => threshold
    // 2 = num_majority). Deterministic keys keep repeated runs comparable.
    kmsState.cores = Array.from({ length: 4 }, (_, index) =>
      new ethers.Wallet(
        ethers.keccak256(ethers.toUtf8Bytes(`vcfhe-synthetic-kms-core:${index}`))
      )
    );
    kmsState.threshold = 2;
    const verifier = await new ethers.ContractFactory(
      artifacts.ZamaKMSVerdictVerifier.abi,
      artifacts.ZamaKMSVerdictVerifier.bytecode,
      deployer
    ).deploy(
      "VCFHE-Verdict-Opening",
      "1",
      0,
      ethers.ZeroAddress,
      kmsState.cores.map((core) => core.address),
      kmsState.threshold
    );
    await recordDeployment("deploy:ZamaKMSVerdictVerifier", verifier);
    kmsState.verifier = verifier;
    kmsState.verifierAddress = await verifier.getAddress();
    kmsState.domain = {
      name: "VCFHE-Verdict-Opening",
      version: "1",
      chainId,
      verifyingContract: kmsState.verifierAddress
    };
    return kmsState;
  }
  // artifact mode: reuse a pre-deployed verifier and a recorded pool of real
  // KMS threshold decryptions (one entry = one ebool ciphertext + its
  // threshold-decrypted plaintext + the cores' external signatures).
  if (!demoConfig.kmsArtifactPath || !demoConfig.kmsVerifierAddress) {
    throw new Error(
      "FHE_POD_KMS_OPENING=artifact requires FHE_POD_KMS_ARTIFACT and FHE_POD_KMS_VERIFIER"
    );
  }
  kmsState.artifact = JSON.parse(fs.readFileSync(demoConfig.kmsArtifactPath, "utf8"));
  kmsState.verifierAddress = ethers.getAddress(demoConfig.kmsVerifierAddress);
  kmsState.verifier = new ethers.Contract(
    kmsState.verifierAddress,
    artifacts.ZamaKMSVerdictVerifier.abi,
    deployer
  );
  kmsState.threshold = Number(await kmsState.verifier.getThreshold());
  kmsState.domain = kmsState.artifact.domain;
  if (
    kmsState.domain?.verifyingContract?.toLowerCase() !==
    kmsState.verifierAddress.toLowerCase()
  ) {
    throw new Error(
      "KMS artifact domain.verifyingContract does not match FHE_POD_KMS_VERIFIER"
    );
  }
  kmsState.pools = {
    0: (kmsState.artifact.openings ?? []).filter((entry) => Number(entry.verdictBit) === 0),
    1: (kmsState.artifact.openings ?? []).filter((entry) => Number(entry.verdictBit) === 1)
  };
  return kmsState;
}

function drawKmsOpening(taskId, auditorAddress, verdict) {
  const bit = verdict ? 1 : 0;
  if (kmsState.mode === "synthetic") {
    const ciphertext = ethers.toUtf8Bytes(
      `synthetic-ebool:${taskId}:${auditorAddress}:${bit}:${demoConfig.repetition}`
    );
    return {
      handle: ethers.keccak256(ciphertext),
      verdictBit: bit,
      decryptedResult: encodeVerdictPlaintext(bit),
      signatures: null // signed lazily in openKmsAudit (needs the handle only)
    };
  }
  const entry = kmsState.pools[bit].shift();
  if (!entry) {
    throw new Error(
      `KMS artifact exhausted: no unused recorded threshold decryption with verdict bit ${bit}`
    );
  }
  kmsState.consumed.push(entry);
  return {
    handle: entry.handle,
    verdictBit: bit,
    decryptedResult: entry.decryptedResult,
    signatures: entry.signatures
  };
}

async function openKmsAudit(game, taskId, auditor, commitment) {
  // The opening is bound to (taskId, auditor, game): the cores sign this
  // execution binding as the EIP-712 `extraData`, so the resulting bundle
  // cannot be replayed to another task, auditor, or game instance.
  const boundExtraData = await game.verdictOpeningBinding(taskId, auditor.address);
  let signatures = commitment.kmsEntry.signatures;
  if (kmsState.mode === "synthetic") {
    signatures = [];
    for (const core of kmsState.cores.slice(0, kmsState.threshold)) {
      signatures.push(
        await core.signTypedData(kmsState.domain, PUBLIC_DECRYPT_TYPES, {
          ctHandles: [commitment.kmsEntry.handle],
          decryptedResult: commitment.kmsEntry.decryptedResult,
          extraData: boundExtraData
        })
      );
    }
  }
  await recordTx(
    "openVerdictViaKMS",
    game.openVerdictViaKMS(
      taskId,
      auditor.address,
      commitment.podRoot,
      commitment.kmsEntry.decryptedResult,
      encodeKmsDecryptionProof(signatures, boundExtraData),
      { gasLimit: 400_000n }
    ),
    {
      taskId,
      auditor: auditor.address,
      verdict: commitment.verdict,
      kmsMode: kmsState.mode,
      kmsVerifier: kmsState.verifierAddress,
      kmsThreshold: kmsState.threshold,
      handle: commitment.kmsEntry.handle
    }
  );
}

async function submitCommittedAudit(
  game,
  taskId,
  auditor,
  verdict,
  label,
  podRootOverride,
  auditedLeafIndex,
  leafCount
) {
  const resolvedAuditedLeafIndex =
    auditedLeafIndex ??
    (await firstAssignedLeaf(game, taskId, auditor, leafCount));
  const podRoot =
    podRootOverride ??
    ethers.keccak256(ethers.toUtf8Bytes(`pod:${label}:${auditor.address}:${verdict}`));
  let commitment;
  if (kmsState.enabled) {
    const kmsEntry = drawKmsOpening(taskId, auditor.address, verdict);
    commitment = {
      podRoot,
      verdict,
      verdictCommit: kmsEntry.handle,
      kms: true,
      kmsEntry
    };
  } else {
    commitment = commitmentFor(taskId, auditor, verdict, podRoot);
  }
  await recordTx(
    `submitAudit:${label}`,
    game
      .connect(auditor)
      .submitAudit(
        taskId,
        resolvedAuditedLeafIndex,
        commitment.podRoot,
        commitment.verdictCommit
      ),
    {
      taskId,
      auditor: auditor.address,
      verdict,
      podRoot: commitment.podRoot,
      auditedLeafIndex: resolvedAuditedLeafIndex
    }
  );
  return commitment;
}

async function firstAssignedLeaf(game, taskId, auditor, leafCount, preferred = 0) {
  if (await game.isAuditorAssignedToLeaf(taskId, auditor.address, preferred)) {
    return preferred;
  }
  for (let leafIndex = 0; leafIndex < leafCount; leafIndex += 1) {
    if (await game.isAuditorAssignedToLeaf(taskId, auditor.address, leafIndex)) {
      return leafIndex;
    }
  }
  throw new Error(`No assigned leaf for auditor ${auditor.address}`);
}

async function openCommittedAudit(game, taskId, auditor, commitment, decryptors) {
  if (commitment.kms) {
    // Real threshold-KMS path: one permissionless transaction carrying the
    // KMS cores' signatures replaces the per-committee openVerdict calls.
    await openKmsAudit(game, taskId, auditor, commitment);
    return;
  }
  // The sampled opening participants are DISTINCT accounts, so their
  // transactions occupy independent nonce spaces and can be in flight together.
  //
  // This is not a micro-optimisation. Opening one audit needs one transaction
  // per participant, and the protocol only accepts them inside the open window.
  // On the validator network a transaction costs about eight seconds end to end
  // (submit, include, receipt), so three auditors times two participants is
  // roughly forty-eight seconds of sequential traffic inside a forty-second
  // window: the last opening reverts with WrongPhase and the whole campaign
  // aborts. Observed exactly that. Sending one round per auditor instead of one
  // transaction per participant brings the phase back inside the window without
  // touching any protocol parameter the implementation reports.
  //
  // Ordering across auditors stays sequential, which the protocol requires:
  // each auditor's openings are independent of the others', but a participant
  // must not have two transactions racing for the same nonce.
  await Promise.all(
    decryptors.map((decryptor) =>
      recordTx(
        "openVerdict",
        game
          .connect(decryptor)
          .openVerdict(
            taskId,
            auditor.address,
            commitment.verdict,
            commitment.salt,
            commitment.podRoot
          ),
        {
          taskId,
          auditor: auditor.address,
          decryptor: decryptor.address,
          verdict: commitment.verdict
        }
      )
    )
  );
}

async function assignedWallets(game, taskId, wallets, getter) {
  const addresses = await game[getter](taskId);
  return addresses.map((address) => {
    const wallet = wallets.find(
      (candidate) => candidate.address.toLowerCase() === address.toLowerCase()
    );
    if (!wallet) {
      throw new Error(`Assigned address ${address} not present in wallet list`);
    }
    return wallet;
  });
}

/// Advances chain time to strictly after the task's `which` deadline
/// ("commit" | "open" | "challenge"). Development chains time-travel by the
/// exact remaining delta; consensus chains wait for real chain time. Waiting
/// an ABSOLUTE deadline (instead of a relative window length) is what keeps
/// the flow correct on real chains, where the preceding transactions already
/// consumed part of the window.
async function advancePastTaskDeadline(provider, game, taskId, which) {
  const [commitDeadline, openDeadline, challengeDeadline] =
    await game.getTaskDeadlines(taskId);
  const deadline = Number(
    which === "commit" ? commitDeadline : which === "open" ? openDeadline : challengeDeadline
  );
  // Raw RPC read: BrowserProvider caches block objects, and a stale "latest"
  // makes the relative bump overshoot fixed deadlines (observed with the
  // in-process EDR chain: cached timestamps lag by whole advances).
  const latestRaw = await provider.send("eth_getBlockByNumber", ["latest", false]);
  const latestTimestamp = Number.parseInt(latestRaw.timestamp, 16);
  const remaining = deadline + 1 - latestTimestamp;
  printLine(
    `    ⏲  advance past ${which} deadline: deadline=${deadline} latest=${latestTimestamp} remaining=${remaining}`
  );
  if (remaining <= 0) {
    // Real chain: the deadline already passed in wall-clock terms.
    return "already-past";
  }
  return increaseTime(provider, remaining);
}

async function increaseTime(provider, seconds) {
  try {
    await provider.send("evm_increaseTime", [seconds]);
    await provider.send("evm_mine", []);
    return "rpc-time-travel";
  } catch (error) {
    // Public EVM networks do not expose development time-travel methods. In
    // that mode, wait for finalized chain time instead of pretending the RPC
    // can mine a block on demand. Raw RPC reads avoid stale cached blocks.
    const readTimestamp = async () => {
      const block = await provider.send("eth_getBlockByNumber", ["latest", false]);
      return Number.parseInt(block.timestamp, 16);
    };
    const targetTimestamp = (await readTimestamp()) + seconds;
    printLine(
      `    ⏳ RPC has no evm_increaseTime; waiting for chain timestamp ${targetTimestamp}`
    );
    while (true) {
      if ((await readTimestamp()) >= targetTimestamp) return "wall-clock-chain-time";
      await new Promise((resolve) => setTimeout(resolve, 5_000));
    }
  }
}

async function verifyExpandedOperationSurface(verifier) {
  const results = [];
  for (const operation of supportedOperations) {
    const [lhs, rhs, claimed] = operation.sample;
    const accepted = await verifier.verifyLeaf(operation.opcode, lhs, rhs, claimed);
    const rejected = await verifier.verifyLeaf(operation.opcode, lhs, rhs, claimed + 1);
    if (!accepted || rejected) {
      throw new Error(`${operation.name} verifier surface check failed`);
    }
    results.push({
      opcode: operation.opcode,
      name: operation.name,
      expression: operation.expression,
      sample: { lhs, rhs, claimed },
      acceptedCorrectClaim: accepted,
      rejectedWrongClaim: !rejected
    });
  }
  return results;
}

function extractFhevmLeafCheckRequested(fhevmVerifier, receipt) {
  for (const log of receipt.logs) {
    try {
      const parsed = fhevmVerifier.interface.parseLog(log);
      if (parsed?.name !== "FhevmLeafCheckRequested") continue;
      return {
        taskId: parsed.args.taskId,
        leafIndex: Number(parsed.args.leafIndex),
        operatorValidHandle: parsed.args.operatorValidHandle,
        challengerValidHandle: parsed.args.challengerValidHandle
      };
    } catch {
      // Ignore logs emitted by other contracts.
    }
  }
  throw new Error("FhevmLeafCheckRequested event not found");
}

function extractFhevmLeafCheckFinalized(fhevmVerifier, receipt) {
  for (const log of receipt.logs) {
    try {
      const parsed = fhevmVerifier.interface.parseLog(log);
      if (parsed?.name !== "FhevmLeafCheckFinalized") continue;
      return {
        taskId: parsed.args.taskId,
        leafIndex: Number(parsed.args.leafIndex),
        operatorValid: parsed.args.operatorValid,
        challengerValid: parsed.args.challengerValid
      };
    } catch {
      // Ignore logs emitted by other contracts.
    }
  }
  throw new Error("FhevmLeafCheckFinalized event not found");
}

async function verifyFhevmOperationSurface(localFhevm) {
  const results = [];
  for (const operation of supportedOperations) {
    const [lhs, rhs, claimed] = operation.sample;
    const taskId = ethers.keccak256(
      ethers.toUtf8Bytes(`fhevm-op-surface:${demoConfig.repetition}:${operation.opcode}`)
    );
    // Surface check over clear-value handles: this sweep exercises the opcode
    // surface of the backend, not confidentiality, so the handle IS the value
    // here and the local runtime resolves it without a declaration.
    const pair = {
      opcode: operation.opcode,
      lhsHandle: ciphertextHandleForClear(lhs),
      rhsHandle: ciphertextHandleForClear(rhs),
      operatorClaimedHandle: ciphertextHandleForClear(claimed + 1),
      challengerClaimedHandle: ciphertextHandleForClear(claimed),
      lhsSourceKind: 0,
      rhsSourceKind: 0,
      lhsInputProof: "0x01",
      rhsInputProof: "0x01",
      operatorClaimedProof: "0x01",
      challengerClaimedProof: "0x01"
    };

    const requestReceipt = await recordTx(
      "fhevmSurface:requestLeafCheck",
      localFhevm.fhevmVerifier.requestLeafCheck(taskId, operation.opcode, pair, {
        gasLimit: 3_000_000n
      }),
      { taskId, opcode: operation.opcode, operation: operation.name }
    );
    const requested = extractFhevmLeafCheckRequested(localFhevm.fhevmVerifier, requestReceipt);
    const operatorValid =
      (await localFhevm.executor.plaintextOf(requested.operatorValidHandle)) !== 0n;
    const challengerValid =
      (await localFhevm.executor.plaintextOf(requested.challengerValidHandle)) !== 0n;

    if (operatorValid || !challengerValid) {
      throw new Error(`${operation.name} FHEVM surface check failed`);
    }

    const finalizeReceipt = await recordTx(
      "fhevmSurface:finalizeLeafCheck",
      localFhevm.fhevmVerifier.finalizeLeafCheck(
        taskId,
        operation.opcode,
        requested.operatorValidHandle,
        requested.challengerValidHandle,
        operatorValid,
        challengerValid,
        "0x01",
        { gasLimit: 250_000n }
      ),
      { taskId, opcode: operation.opcode, operation: operation.name, operatorValid, challengerValid }
    );
    const finalized = extractFhevmLeafCheckFinalized(localFhevm.fhevmVerifier, finalizeReceipt);

    results.push({
      opcode: operation.opcode,
      name: operation.name,
      expression: operation.expression,
      sample: { lhs, rhs, claimed },
      requestTaskId: taskId,
      operatorWrongClaimed: claimed + 1,
      challengerCorrectClaimed: claimed,
      operatorValid,
      challengerValid,
      finalizedOperatorValid: finalized.operatorValid,
      finalizedChallengerValid: finalized.challengerValid,
      operatorValidHandle: requested.operatorValidHandle,
      challengerValidHandle: requested.challengerValidHandle,
      requestLeafIndex: requested.leafIndex,
      finalizedLeafIndex: finalized.leafIndex
    });
  }
  return results;
}

async function runDispute(
  game,
  localFhevm,
  taskId,
  operatorWallet,
  challengerWallet,
  operatorTree,
  challengerTree,
  operatorLeaf,
  challengerLeaf,
  sourceLeaf,
  leafDecision = null
) {
  const rounds = [];
  let dispute = await game.getTaskDisputeState(taskId);
  const totalLeaves = Number(dispute.disputeEnd) - Number(dispute.disputeStart);
  const totalRounds = Math.ceil(Math.log2(totalLeaves));

  printLine("");
  printLine("    ┌────────────────────────────────────────────────────────────────┐");
  printLine("    │  🔍 BISECTION — searching for the disputed leaf               │");
  printLine("    ├────────────────────────────────────────────────────────────────┤");
  printLine(`    │  Initial interval: [${Number(dispute.disputeStart)}, ${Number(dispute.disputeEnd)})  (${totalLeaves} leaves)`);
  printLine(`    │  Expected rounds:  ${totalRounds}  (log2(${totalLeaves}))`);
  printLine("    │  Each round: operator and challenger reveal the subtree's two");
  printLine("    │  children; the contract descends into the one they disagree on.");
  printLine("    └────────────────────────────────────────────────────────────────┘");
  printLine("");

  let roundNumber = 0;
  while (Number(dispute.disputeEnd) - Number(dispute.disputeStart) > 1) {
    const start = Number(dispute.disputeStart);
    const end = Number(dispute.disputeEnd);
    const operatorChildren = getSubtreeChildren(operatorTree, start, end);
    const challengerChildren = getSubtreeChildren(challengerTree, start, end);

    await recordTx(
      "submitBisection:operator",
      game
        .connect(operatorWallet)
        .submitBisection(taskId, true, operatorChildren.left, operatorChildren.right),
      { taskId, start, end }
    );
    await recordTx(
      "submitBisection:challenger",
      game
        .connect(challengerWallet)
        .submitBisection(taskId, false, challengerChildren.left, challengerChildren.right),
      { taskId, start, end }
    );
    await recordTx("advanceDispute", game.advanceDispute(taskId, { gasLimit: 250_000n }), {
      taskId,
      start,
      end
    });

    dispute = await game.getTaskDisputeState(taskId);
    roundNumber++;
    const newStart = Number(dispute.disputeStart);
    const newEnd = Number(dispute.disputeEnd);
    printLine(
      `    🔻 Round ${roundNumber}/${totalRounds}: interval narrowed to [${newStart}, ${newEnd}) ` +
        `(${newEnd - newStart} ${newEnd - newStart > 1 ? "leaves" : "leaf"})`
    );
    rounds.push({
      disputeStart: Number(dispute.disputeStart),
      disputeEnd: Number(dispute.disputeEnd),
      operatorNode: dispute.currentOperatorNode,
      challengerNode: dispute.currentChallengerNode
    });
  }

  let receipt;
  let fhevmResolution = null;
  if (localFhevm) {
    printLine("");
    printLine("    ┌────────────────────────────────────────────────────────────────┐");
    printLine("    │  ⚖  FHEVM VERIFICATION — objective decision on one leaf       │");
    printLine("    ├────────────────────────────────────────────────────────────────┤");
    printLine(`    │  Isolated leaf:  leaf_index=${Number(dispute.disputeStart)}`);
    printLine(`    │  Opcode:         ${Number(operatorLeaf.opcode)}`);
    printLine(`    │  Operator says:   claimedHandle=${shortHash(String(sourceLeaf?.claimedHandle ?? traceLeafClaim(operatorLeaf).claimedHandle))}`);
    printLine(`    │  Challenger says: claimedHandle=${shortHash(String(traceLeafClaim(challengerLeaf).claimedHandle))}`);
    printLine("    │  The leaf is RECOMPUTED under encryption from its operands and");
    printLine("    │  each claim is compared with FHE.eq; only the BIT is decrypted,");
    printLine("    │  attested by t+1 EIP-712 signatures.");
    printLine("    │  Ciphertext bytes do not reproduce across runs; the bit does.");
    printLine("    │  No operand travels in the clear.");
    printLine("    └────────────────────────────────────────────────────────────────┘");
    printLine("");
    // The LeafClaim tuple carries only {opcode, lhsHandle, rhsHandle,
    // claimedHandle}. The operand handles come from the provenance record the
    // task committed (`sourceLeaf`); the two claimed handles come from each
    // party's own committed leaf.
    //
    // WHY NOT requestFhevmLeafResolution HERE. The on-chain homomorphic route
    // needs a backend that can resolve a handle to its content. The local
    // stand-in cannot, and the only way to make it do so was to publish the
    // operands in a handle-declaration transaction -- a plaintext leak of the
    // disputed leaf. That entry point no longer exists. The equality is decided
    // off-chain from the ciphertext handles and settled from a t+1-signed
    // attestation, which is what a production coprocessor + threshold KMS
    // deployment does with the same digest and the same acceptance rule.
    const operatorClaim = traceLeafClaim(operatorLeaf);
    const challengerClaim = traceLeafClaim(challengerLeaf);
    // The handle the attestation must speak about on the operator's side is the
    // one the contract resolves in secure-trace mode: the DISCLOSED provenance
    // record, not the operator's LeafClaim field.
    const attestedOperatorHandle = String(
      sourceLeaf?.claimedHandle ?? operatorClaim.claimedHandle
    );
    const attestedChallengerHandle = String(challengerClaim.claimedHandle);
    // THE DECISION. With real ciphertexts it is homomorphic: recompute the leaf
    // from its operand ciphertexts and compare each claim to the recomputation
    // with FHE.eq, decrypting only the bit. Without a manifest the run is on
    // clear-value handles, where handle equality IS plaintext equality.
    const leafIndex = Number(dispute.disputeStart);
    // An evaluation run must never settle a leaf by comparing clear-value handles.
    // The context is built whenever the manifest covers both variants, which
    // VCFHE_REQUIRE_FHE_HANDLES=1 already forces; this makes the invariant fail
    // loudly rather than downgrade the evidence silently.
    if (!leafDecision && requireFheHandles) {
      throw new Error(
        "VCFHE_REQUIRE_FHE_HANDLES=1 but no ciphertext context is available to decide the isolated " +
          "leaf homomorphically; refusing to fall back to clear-value handle equality."
      );
    }
    const bits = leafDecision
      ? decideLeafHomomorphically(
          leafDecision,
          leafIndex,
          attestedOperatorHandle,
          attestedChallengerHandle
        )
      : leafDecisionBitsFromClearHandles(
          attestedOperatorHandle,
          attestedChallengerHandle,
          String(attestedChallengerHandle)
        );
    const reference = leafDecision
      ? bits.detail.recomputedHandle
      : String(attestedChallengerHandle);
    const decisionProof = await attestLeafDecision(
      game,
      taskId,
      Number(dispute.disputeStart),
      Number(operatorLeaf.opcode),
      [attestedOperatorHandle, attestedChallengerHandle],
      bits
    );
    fhevmResolution = {
      verifier: leafDecisionState.verifierAddress,
      backend: "settleLeafViaAttestedDecision",
      threshold: leafDecisionState.threshold,
      signers: leafDecisionState.cores.length,
      referenceHandle: reference,
      operatorClaimedHandle: attestedOperatorHandle,
      challengerClaimedHandle: attestedChallengerHandle,
      operatorValid: bits.operatorValid,
      challengerValid: bits.challengerValid,
      // How the two bits were obtained. "fhe-eq" means the leaf was recomputed
      // homomorphically and each claim compared to it with FHE.eq, only the bit
      // being decrypted; result bytes are never a validity condition (see
      // leaf-decision.mjs). "clear-handle-equality" is the no-manifest fallback.
      decidedBy: leafDecision ? "fhe-eq" : "clear-handle-equality",
      eqDetail: leafDecision
        ? {
            recomputedHandle: bits.detail.recomputedHandle,
            recomputedBytesEqualCommitted: bits.detail.decisions.some(
              (d) => d.label === "challenger" && d.claimBytesEqualRecomputed
            ),
            // Cost of deciding the leaf, which the settlement rule made real:
            // recomputing the disputed instruction under encryption plus one
            // FHE.eq per claim. Under the previous byte-comparison rule this
            // was a string comparison and cost nothing, so it is a new
            // protocol-inherent cost and it depends on WHICH operation is
            // disputed. The on-chain settlement that consumes the two bits is
            // one transaction and does not.
            recomputeMs: bits.detail.recomputeMs,
            eqMs: bits.detail.decisions.reduce((total, d) => total + Number(d.eqMs ?? 0), 0),
            offchainDecisionMs:
              Number(bits.detail.recomputeMs ?? 0) +
              bits.detail.decisions.reduce((total, d) => total + Number(d.eqMs ?? 0), 0),
            eboolHandles: Object.fromEntries(
              bits.detail.decisions.map((d) => [d.label, d.eboolHandle])
            )
          }
        : null
    };
    receipt = await recordTx(
      "settleLeafViaAttestedDecision",
      // Restricted to nobody: validity comes from the t+1 signatures and the
      // digest is bound to this game, chain, task, leaf and opcode.
      game.connect(challengerWallet).settleLeafViaAttestedDecision(
        taskId,
        operatorClaim,
        challengerClaim,
        bits.operatorValid,
        bits.challengerValid,
        decisionProof,
        { gasLimit: 900_000n }
      ),
      {
        taskId,
        leafIndex: Number(dispute.disputeStart),
        opcode: Number(operatorLeaf.opcode),
        operatorValid: bits.operatorValid,
        challengerValid: bits.challengerValid
      }
    );
  } else {
    receipt = await recordTx(
      "resolveLeafDispute",
      game.resolveLeafDispute(
        taskId,
        traceLeafClaim(operatorLeaf),
        traceLeafClaim(challengerLeaf)
      ),
      { taskId, leafIndex: Number(dispute.disputeStart), opcode: Number(operatorLeaf.opcode) }
    );
  }
  const leafCheck = extractLeafCheck(game, receipt);

  return { rounds, leafCheck, fhevmResolution };
}

function extractLeafCheck(game, receipt) {
  for (const log of receipt.logs) {
    try {
      const parsed = game.interface.parseLog(log);
      if (parsed?.name !== "LeafCheckedOnChain") continue;
      return {
        taskId: parsed.args.taskId,
        leafIndex: Number(parsed.args.leafIndex),
        opcode: Number(parsed.args.opcode),
        operatorValid: parsed.args.operatorValid,
        challengerValid: parsed.args.challengerValid,
        verifier: parsed.args.verifier
      };
    } catch {
      // Ignore logs emitted by other contracts.
    }
  }
  throw new Error("LeafCheckedOnChain event not found");
}

async function deployProtocol(provider) {
  const signerCount = 3 + demoConfig.auditorCount + demoConfig.decryptorCount;
  // BrowserProvider#getSigner(index) re-queries/request-authorizes the account
  // list on every call. A large Promise.all (e.g. the 16x16 pool sweep) can
  // overwhelm an external JSON-RPC provider with concurrent
  // eth_requestAccounts calls. Fetch the remote signer list once instead.
  const availableSigners = await provider.listAccounts();
  if (availableSigners.length < signerCount) {
    throw new Error(
      `network exposes ${availableSigners.length} signers, but this run needs ${signerCount}`
    );
  }
  const [
    deployer,
    honestOperator,
    dishonestOperator,
    ...roleWallets
  ] = availableSigners.slice(0, signerCount);
  const auditors = roleWallets.slice(0, demoConfig.auditorCount);
  const decryptors = roleWallets.slice(demoConfig.auditorCount);

  const artifacts = await compileContracts();
  const verifierFactory = new ethers.ContractFactory(
    artifacts.ObjectiveMicroVerifier.abi,
    artifacts.ObjectiveMicroVerifier.bytecode,
    deployer
  );
  const verifier = await verifierFactory.deploy();
  await recordDeployment("deploy:ObjectiveMicroVerifier", verifier);

  const gameFactory = new ethers.ContractFactory(
    artifacts.LegacyConfigurableDisputeGame.abi,
    artifacts.LegacyConfigurableDisputeGame.bytecode,
    deployer
  );
  const game = await gameFactory.deploy(
    await verifier.getAddress(),
    demoConfig.commitWindowSeconds,
    demoConfig.openWindowSeconds,
    demoConfig.challengeWindowSeconds,
    true
  );
  await recordDeployment("deploy:LegacyConfigurableDisputeGame", game);

  const availability = await new ethers.ContractFactory(
    artifacts.AuthenticatedTraceAvailability.abi,
    artifacts.AuthenticatedTraceAvailability.bytecode,
    deployer
  ).deploy(await game.getAddress(), demoConfig.disclosureWindowSeconds);
  await recordDeployment("deploy:AuthenticatedTraceAvailability", availability);
  await recordTx(
    "setAvailabilityModule",
    game.setAvailabilityModule(await availability.getAddress()),
    { availability: await availability.getAddress() }
  );

  const localFhevm = await deployLocalFhevmRuntime(artifacts, deployer);
  await recordTx(
    "setFhevmVerifier",
    game.setFhevmVerifier(await localFhevm.fhevmVerifier.getAddress()),
    { verifier: await localFhevm.fhevmVerifier.getAddress() }
  );

  // Threshold attestor for terminal leaf decisions. Always wired: settlement
  // over real ciphertext handles has no fallback that keeps operands private.
  await setupLeafDecisionAttestor(provider, deployer, artifacts);
  await recordTx(
    "setLeafDecisionVerifier",
    game.setLeafDecisionVerifier(leafDecisionState.verifierAddress),
    {
      verifier: leafDecisionState.verifierAddress,
      threshold: leafDecisionState.threshold
    }
  );

  if (kmsState.enabled) {
    await setupKmsOpening(provider, deployer, artifacts);
    await recordTx(
      "setKmsVerdictVerifier",
      game.setKmsVerdictVerifier(kmsState.verifierAddress),
      {
        verifier: kmsState.verifierAddress,
        mode: kmsState.mode,
        threshold: kmsState.threshold
      }
    );
  }

  for (const operator of [honestOperator, dishonestOperator]) {
    await recordTx(
      "registerOperator",
      game.connect(operator).registerOperator({ value: ethers.parseEther("2") }),
      { operator: operator.address }
    );
  }
  for (const auditor of auditors) {
    await recordTx(
      "registerAuditor",
      game.connect(auditor).registerAuditor({ value: ethers.parseEther("1") }),
      { auditor: auditor.address }
    );
  }
  for (const decryptor of decryptors) {
    await recordTx(
      "registerDecryptor",
      game.connect(decryptor).registerDecryptor({ value: ethers.parseEther("1") }),
      { decryptor: decryptor.address }
    );
  }

  return {
    game,
    verifier,
    availability,
    requester: deployer,
    localFhevm,
    honestOperator,
    dishonestOperator,
    auditors,
    decryptors
  };
}

async function deployLocalFhevmRuntime(artifacts, deployer) {
  const aclFactory = new ethers.ContractFactory(
    artifacts.LocalFhevmACL.abi,
    artifacts.LocalFhevmACL.bytecode,
    deployer
  );
  const acl = await aclFactory.deploy();
  await recordDeployment("deploy:LocalFhevmACL", acl);

  const executorFactory = new ethers.ContractFactory(
    artifacts.LocalFhevmExecutor.abi,
    artifacts.LocalFhevmExecutor.bytecode,
    deployer
  );
  const executor = await executorFactory.deploy();
  await recordDeployment("deploy:LocalFhevmExecutor", executor);

  const kmsFactory = new ethers.ContractFactory(
    artifacts.LocalFhevmKMSVerifier.abi,
    artifacts.LocalFhevmKMSVerifier.bytecode,
    deployer
  );
  const kms = await kmsFactory.deploy(await acl.getAddress(), await executor.getAddress());
  await recordDeployment("deploy:LocalFhevmKMSVerifier", kms);

  const fhevmVerifierFactory = new ethers.ContractFactory(
    artifacts.FhevmObjectiveMicroVerifier.abi,
    artifacts.FhevmObjectiveMicroVerifier.bytecode,
    deployer
  );
  const fhevmVerifier = await fhevmVerifierFactory.deploy(
    await acl.getAddress(),
    await executor.getAddress(),
    await kms.getAddress()
  );
  await recordDeployment("deploy:FhevmObjectiveMicroVerifier", fhevmVerifier);

  return { acl, executor, kms, fhevmVerifier };
}

async function runHonestNodeScenario(
  provider,
  game,
  availability,
  requester,
  operator,
  auditors,
  decryptors,
  tree,
  treeLeaves,
  outputAttestationHash,
  fheHandles
) {
  const taskId = ethers.encodeBytes32String("honest-node");
  const binding = terminalOutputBinding(taskId, tree, treeLeaves, outputAttestationHash);
  await authorizeAuthenticatedTask({
    availability,
    requester,
    operatorAddress: operator.address,
    taskId,
    tree,
    leaves: treeLeaves,
    resultHash: binding.resultHash,
    outputAttestationHash,
    programLeaves: treeLeaves,
    recordTransaction: recordTx,
    fheHandles
  });
  await recordTx(
    "createTask:honest",
    game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, treeLeaves, outputAttestationHash)),
    { taskId, operator: operator.address, traceRoot: tree.root, leafCount: tree.leafCount }
  );
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(
    game,
    taskId,
    auditors,
    "getAssignedAuditors"
  );
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );

  const commitments = [];
  for (const auditor of assignedAuditors) {
    commitments.push(
      await submitCommittedAudit(
        game,
        taskId,
        auditor,
        true,
        "honest-node",
        undefined,
        undefined,
        tree.leafCount
      )
    );
  }

  await advancePastTaskDeadline(provider, game, taskId, "commit");
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      commitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastTaskDeadline(provider, game, taskId, "challenge");
  await recordTx("finalizeUnchallenged", game.finalizeUnchallenged(taskId), { taskId });
  const status = await game.getTaskStatus(taskId);

  if (Number(status.decision) !== 1) {
    throw new Error(`Honest node should be accepted, got decision ${status.decision}`);
  }

  return {
    taskId,
    root: tree.root,
    decision: Number(status.decision),
    finalized: Number(status.status) === 3,
    assignedAuditors: assignedAuditors.map((auditor) => auditor.address),
    assignedDecryptors: assignedDecryptors.map((decryptor) => decryptor.address)
  };
}

async function runDishonestNodeScenario(
  provider,
  game,
  availability,
  requester,
  localFhevm,
  dishonestOperator,
  auditors,
  decryptors,
  honestTree,
  dishonestTree,
  dishonestLeaves,
  honestLeaves,
  honestLeaf,
  dishonestLeaf,
  outputAttestationHash,
  fheHandles,
  leafDecision = null
) {
  const taskId = ethers.encodeBytes32String("dishonest-node");
  const binding = terminalOutputBinding(
    taskId,
    dishonestTree,
    dishonestLeaves,
    outputAttestationHash
  );
  const authenticatedPlan = await authorizeAuthenticatedTask({
    availability,
    requester,
    operatorAddress: dishonestOperator.address,
    taskId,
    tree: dishonestTree,
    leaves: dishonestLeaves,
    resultHash: binding.resultHash,
    outputAttestationHash,
    programLeaves: honestLeaves,
    recordTransaction: recordTx,
    fheHandles
  });
  await recordTx(
    "createTask:dishonest",
    game
      .connect(dishonestOperator)
      .createTask(
        ...boundCreateTaskArgs(taskId, dishonestTree, dishonestLeaves, outputAttestationHash)
      ),
    {
      taskId,
      operator: dishonestOperator.address,
      traceRoot: dishonestTree.root,
      leafCount: dishonestTree.leafCount
    }
  );
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(
    game,
    taskId,
    auditors,
    "getAssignedAuditors"
  );
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const challengeLeafHint = Number(honestLeaf.leaf_index ?? 4);
  const stageAuditorAddresses = await game.getAssignedAuditorsForLeaf(
    taskId,
    challengeLeafHint
  );
  const challenger = assignedAuditors.find(
    (auditor) =>
      auditor.address.toLowerCase() === stageAuditorAddresses[0].toLowerCase()
  );

  const commitments = [];
  let challengeAuditTranscript = null;
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const auditorCoversChallengedLeaf = await game.isAuditorAssignedToLeaf(
      taskId,
      auditor.address,
      challengeLeafHint
    );
    let podRootOverride;
    if (!supportsOperator) {
      const errorDigest = challengeErrorDigest(
        taskId,
        challengeLeafHint,
        dishonestLeaf,
        honestLeaf
      );
      const auditTraceLeaf = {
        leafIndex: challengeLeafHint,
        operatorLeafHash: leafHash(dishonestLeaf),
        recomputedLeafHash: leafHash(honestLeaf),
        errorDigest
      };
      challengeAuditTranscript = buildAuditTranscript({
        taskId,
        auditorAddress: auditor.address,
        operatorTraceRoot: dishonestTree.root,
        auditTraceLeaf,
        operatorLeaf: dishonestLeaf,
        recomputedLeaf: honestLeaf
      });
      podRootOverride = challengeAuditTranscript.root;
    }
    commitments.push(
      await submitCommittedAudit(
        game,
        taskId,
        auditor,
        supportsOperator,
        "dishonest-node",
        podRootOverride,
        auditorCoversChallengedLeaf ? challengeLeafHint : undefined,
        dishonestTree.leafCount
      )
    );
  }

  await advancePastTaskDeadline(provider, game, taskId, "commit");
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      commitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  const challengeError = {
    code: "CLAIMED_RESULT_MISMATCH",
    leafIndex: challengeLeafHint,
    expectedClaimed: Number(honestLeaf.claimed),
    observedClaimed: Number(dishonestLeaf.claimed),
    opcode: Number(honestLeaf.opcode)
  };
  const challengeErrorDigestValue = challengeErrorDigest(
    taskId,
    challengeLeafHint,
    dishonestLeaf,
    honestLeaf
  );

  await advancePastTaskDeadline(provider, game, taskId, "open");

  await recordTx(
    "sealDiligenceRandomness",
    game.sealDiligenceRandomness(taskId),
    { taskId }
  );
  const diligenceCheckpointIndex = await game.getRequiredDiligenceCheckpointIndex(
    taskId,
    challenger.address
  );
  const selectedDiligence = selectAuditDiligenceCheckpoint(
    challengeAuditTranscript,
    diligenceCheckpointIndex
  );
  await recordTx(
    "proveAuditDiligence",
    game.connect(challenger).proveAuditDiligence(
      taskId,
      selectedDiligence.diligenceCheckpoint,
      selectedDiligence.diligenceProof,
      selectedDiligence.diligenceProofSiblingOnLeft
    ),
    {
      taskId,
      auditor: challenger.address,
      podRoot: challengeAuditTranscript.root,
      checkpointIndex: Number(diligenceCheckpointIndex)
    }
  );

  printLine("");
  printLine("    ┌────────────────────────────────────────────────────────────────┐");
  printLine("    │  ⚔  DISPUTE OPENED — openChallenge                            │");
  printLine("    ├────────────────────────────────────────────────────────────────┤");
  printLine(`    │  What was detected:  operator claimed=${dishonestLeaf.claimed}`);
  printLine(`    │                      but the recomputation says claimed=${honestLeaf.claimed}`);
  printLine(`    │  Disputed operation: opcode=${honestLeaf.opcode} (${honestLeaf.opcode_name ?? "?"})  lhs=${honestLeaf.lhs}  rhs=${honestLeaf.rhs}`);
  printLine(`    │  Manipulated leaf:   leaf_index=${challengeLeafHint}`);
  printLine(`    │  Who disputes:       dissenting auditor ${shortHash(challenger.address)}`);
  printLine(`    │  Against whom:       dishonest operator ${shortHash(dishonestOperator.address)}`);
  printLine("    │  Even if the majority of auditors back the operator, the");
  printLine("    │  challenger reveals evidence and forces bisection on-chain.");
  printLine("    └────────────────────────────────────────────────────────────────┘");
  printLine("");

  await recordTx(
    "openChallenge",
    game.connect(challenger).openChallenge(
      taskId,
      honestTree.root,
      challengeLeafHint,
      challengeErrorDigestValue,
      challengeAuditTranscript.leaves[0],
      challengeAuditTranscript.proof,
      challengeAuditTranscript.proofSiblingOnLeft
    ),
    {
      taskId,
      challenger: challenger.address,
      challengerTraceRoot: honestTree.root,
      challengeLeafHint,
      challengeErrorDigest: challengeErrorDigestValue
    }
  );

  printLine("    Publishing the full trace and its authenticated provenance before bisection...");
  const disclosureBatchSize = 8;
  for (let index = 0; index < authenticatedPlan.disclosureLeaves.length; index += disclosureBatchSize) {
    const batch = authenticatedPlan.disclosureLeaves.slice(index, index + disclosureBatchSize);
    await recordTx(
      "publishDisputedTraceBatch",
      availability.connect(dishonestOperator).publishDisputedTraceBatch(
        taskId,
        batch.map((disclosure) => disclosure.leaf),
        batch.map((disclosure) => disclosure.lhsInputProof),
        batch.map((disclosure) => disclosure.rhsInputProof),
        { gasLimit: 8_000_000n }
      ),
      { taskId, firstLeafIndex: index, leafCount: batch.length }
    );
  }
  if (!(await availability.isDisputeReady(taskId))) {
    throw new Error("full trace disclosure did not satisfy authenticated roots");
  }

  const challengeClaim = await game.getChallengeClaim(taskId);

  const dishonestStakeBefore = await game.getParticipantStake(dishonestOperator.address);
  const challengerStakeBefore = await game.getParticipantStake(challenger.address);
  const disputeResult = await runDispute(
    game,
    localFhevm,
    taskId,
    dishonestOperator,
    challenger,
    dishonestTree,
    honestTree,
    dishonestLeaf,
    honestLeaf,
    authenticatedPlan.provenanceLeaves[challengeLeafHint],
    // Everything the isolated leaf needs to be adjudicated homomorphically:
    // the manifest, where the ciphertexts are, and which executed variant holds
    // each party's claimed result ciphertext. Null when no ciphertext manifest
    // covers this run, in which case the handles are clear values and handle
    // equality is plaintext equality.
    leafDecision
  );
  const dishonestStakeAfter = await game.getParticipantStake(dishonestOperator.address);
  const challengerStakeAfter = await game.getParticipantStake(challenger.address);
  const status = await game.getTaskStatus(taskId);

  if (Number(status.decision) !== 2) {
    throw new Error(`Dishonest node should be slashed, got decision ${status.decision}`);
  }

  return {
    taskId,
    challenger: challenger.address,
    assignedAuditors: assignedAuditors.map((auditor) => auditor.address),
    assignedDecryptors: assignedDecryptors.map((decryptor) => decryptor.address),
    honestRoot: honestTree.root,
    dishonestRoot: dishonestTree.root,
    decision: Number(status.decision),
    finalized: Number(status.status) === 3,
    dishonestStakeDeltaWei: (dishonestStakeAfter - dishonestStakeBefore).toString(),
    challengerStakeDeltaWei: (challengerStakeAfter - challengerStakeBefore).toString(),
    challenge: {
      leafHint: Number(challengeClaim.challengeLeafHint),
      errorDigest: challengeClaim.challengeErrorDigest,
      podRoot: challengeClaim.challengePodRoot,
      auditLeafHash: challengeClaim.challengeAuditLeafHash,
      auditTranscript: challengeAuditTranscript,
      error: challengeError
    },
    leafCheck: disputeResult.leafCheck,
    fhevmResolution: disputeResult.fhevmResolution,
    bisectionRounds: disputeResult.rounds
  };
}

// FHE_POD_NETWORK selects the chain: "hardhat" (in-process simulated EVM,
// default) or "vcfhe" (external JSON-RPC node, see hardhat.config.js).
const networkName = process.env.FHE_POD_NETWORK ?? "hardhat";
const connection = await hre.network.create(networkName);
try {
  const provider = new ethers.BrowserProvider(connection.provider);
  // Receipts are discovered by polling, and ethers defaults to 4000 ms. That
  // interval lands inside the measured latency of EVERY transaction, and the
  // per-transaction latency is what dominates the dispute wall clock this run
  // reports: measured over the previous pinned run, 85--89% of the wall clock
  // was time between sending a transaction and observing its receipt, on a
  // chain whose blocks are two seconds apart. Leaving the default in place
  // would publish a decision-latency figure inflated by this client's polling
  // loop rather than by the protocol or the chain. 500 ms keeps the
  // quantization well below the block period.
  provider.pollingInterval = 500;
  const {
    game,
    verifier,
    availability,
    requester,
    localFhevm,
    honestOperator,
    dishonestOperator,
    auditors,
    decryptors
  } = await deployProtocol(provider);
  const requestedRunDir = process.env.FHE_POD_RUN_DIR;
  const { runDir, attestationPayload, microTraceBundle } = await loadRunArtifacts(requestedRunDir);
  const honestWitnesses = microTraceBundle.witnesses;
  const manipulatedLeafIndex = demoConfig.manipulatedLeafIndex;
  if (manipulatedLeafIndex >= honestWitnesses.length) {
    throw new Error(
      `DEMO_MANIPULATED_LEAF_INDEX=${manipulatedLeafIndex} is outside the trace length ${honestWitnesses.length}`
    );
  }
  const dishonestWitnesses = deriveDishonestLeaves(honestWitnesses, manipulatedLeafIndex);

  // ---- ciphertext handles of the two committed traces ---------------------
  //
  // Every operand and every leaf result the two tasks register on-chain is a
  // 32-byte handle. They come from the TFHE executor's manifest, by default
  // artifacts/fhe/ciphertext-manifest.json and otherwise wherever
  // VCFHE_CIPHERTEXT_MANIFEST points (the ANATEL demonstrations keep their own,
  // so they cannot touch the evaluation's). Whichever it is, it covers BOTH traces:
  // the honest one under the workload id, the corrupted one under
  // "<workloadId>#corrupted".
  //
  // The dishonest task needs both variants at once, and the split is dictated
  // by buildAuthenticatedTracePlan: it registers input records from the PROGRAM
  // leaves (the honest trace -- the statement the requester authorised, which
  // the dishonest operator cannot change) and takes every result/claim handle
  // from the EXECUTION leaves (the corrupted trace it actually published). So
  // input handles come from the honest variant and leaf-result handles from the
  // corrupted one.
  const workloadId = process.env.DEMO_FHE_WORKLOAD_ID || microTraceBundle.workload || null;
  if (!workloadId && requireFheHandles) {
    throw new Error(
      "VCFHE_REQUIRE_FHE_HANDLES=1 but this run directory names no workload; "
      + "set DEMO_FHE_WORKLOAD_ID or regenerate the run artifacts."
    );
  }
  const honestFheHandles = workloadId
    ? fheHandlesForWorkload(workloadId, honestWitnesses.length, "honest")
    : null;
  const corruptedFheHandles = workloadId
    ? fheHandlesForWorkload(workloadId, dishonestWitnesses.length, "corrupted")
    : null;
  assertHandlesMatchTrace(honestFheHandles, honestWitnesses, `${workloadId} honest trace`);
  assertHandlesMatchTrace(corruptedFheHandles, dishonestWitnesses, `${workloadId} corrupted trace`);
  if (requireFheHandles && !(honestFheHandles && corruptedFheHandles)) {
    throw new Error(
      `VCFHE_REQUIRE_FHE_HANDLES=1 but the ciphertext manifest does not cover both variants of ${workloadId}.`
    );
  }
  // Both variants or neither: a run that had handles for one task and clear
  // values for the other would report a confidentiality property that only half
  // the evidence supports.
  const fheHandlesReady = Boolean(honestFheHandles && corruptedFheHandles);
  // Result ciphertexts the dishonest operator publishes: the honest ones,
  // except at the leaf it manipulated, where it publishes the ciphertext of the
  // wrong value taken from the corrupted variant of the manifest.
  //
  // WHY NOT THE WHOLE CORRUPTED VARIANT. In a real FHEVM a handle is a
  // deterministic function of the computation, so two executions that agree on
  // a leaf agree on its handle, and an operator that corrupts ONE leaf differs
  // from the honest execution at that leaf (and downstream of it) only. The
  // local TFHE executor re-encrypts with fresh randomness per run, so its
  // corrupted variant carries a different handle for EVERY leaf, including the
  // 127 the operator did not touch. Committing those wholesale would make all
  // 128 trace leaves differ and bisection would isolate leaf 0 instead of the
  // leaf that was actually manipulated -- an artefact of the local executor's
  // randomness, not a property of the protocol. Splicing keeps the committed
  // trace faithful to "one manipulated micro-instruction".
  const dishonestFheHandles = fheHandlesReady
    ? {
        ...corruptedFheHandles,
        // Program-side operands: authorised inputs of the honest statement.
        inputHandle: (leafIndex, side) => honestFheHandles.inputHandle(leafIndex, side),
        isPublicConstant: (leafIndex, side) => honestFheHandles.isPublicConstant(leafIndex, side),
        leafResultHandles: honestFheHandles.leafResultHandles.map(
          (handle, leafIndex) =>
            (leafIndex === manipulatedLeafIndex
              ? corruptedFheHandles.leafResultHandles[leafIndex]
              : handle)
        )
      }
    : null;

  // ---- how the isolated leaf will be adjudicated --------------------------
  //
  // The two decision bits are produced by recomputing the disputed leaf
  // homomorphically from its operand ciphertexts and evaluating
  // `FHE.eq(recomputed, claimed)` against each party's claimed result
  // ciphertext, decrypting only the bits (scripts/leaf-decision.mjs). The
  // operands are the honest variant's: they are the authorised statement.
  // Which variant holds a given CLAIM is resolved by handle, so a claim is
  // always adjudicated against the very ciphertext whose digest is on chain.
  const leafDecisionContext = fheHandlesReady
    ? {
        manifest: loadCiphertextManifest(),
        ciphertextDir: ciphertextDirPath,
        referenceKey: honestFheHandles.manifestKey,
        variants: [
          {
            manifestKey: honestFheHandles.manifestKey,
            resultHandles: honestFheHandles.leafResultHandles
          },
          {
            manifestKey: corruptedFheHandles.manifestKey,
            resultHandles: corruptedFheHandles.leafResultHandles
          }
        ],
        // DIV/MOD/SHR take a public scalar of the program on the right; it is
        // never encrypted, so the recomputation needs its value.
        publicScalarFor: (leafIndex) => Number(honestWitnesses[leafIndex]?.rhs ?? 0)
      }
    : null;

  // ---- committed trace leaves --------------------------------------------
  //
  // The trace Merkle tree commits to (opcode, lhsHandle, rhsHandle,
  // claimedHandle), so the handles must be resolved BEFORE the tree exists.
  // `attachTraceHandles` runs the same dataflow resolution the authenticated
  // plan runs, so the tree the task commits and the provenance leaves the
  // operator later discloses agree by construction. The clear witnesses stay
  // on the objects for this script's own narration and reference checks; only
  // `traceLeafClaim` shapes what is sent on chain.
  const honestLeaves = attachTraceHandles(
    honestWitnesses,
    honestWitnesses,
    fheHandlesReady ? honestFheHandles : null
  );
  const dishonestLeaves = attachTraceHandles(
    dishonestWitnesses,
    honestWitnesses,
    dishonestFheHandles
  );
  const honestTree = buildMerkleTree(honestLeaves);
  const dishonestTree = buildMerkleTree(dishonestLeaves);
  // The attestation digest of the published encrypted output. The on-chain
  // result hash is now DERIVED from it plus the terminal trace leaf, so the
  // published output is cryptographically bound to the committed trace.
  const outputAttestationHash = resultHashFromAttestation(attestationPayload);

  printTitle("Minimal on-chain FHE dispute demo");
  printStep("1", "Architecture under test", [
    "tfhe-rs computes off-chain and records a micro-trace.",
    "Hardhat deploys the dispute game, the local FHEVM runtime and the FHEVM verifier.",
    "A dishonest node manipulates one micro-instruction.",
    "A dissenting auditor opens a challenge.",
    "The contract bisects down to one leaf and decides on-chain using FHEVM operations.",
    `config=${JSON.stringify(demoConfig)}`
  ]);
  printSupportedOperations();

  const objectiveOperationSurfaceChecks = demoConfig.skipSurfaceChecks
    ? []
    : await verifyExpandedOperationSurface(verifier);
  const fhevmOperationSurfaceChecks = demoConfig.skipSurfaceChecks
    ? []
    : await verifyFhevmOperationSurface(localFhevm);
  printStep("3", "Verifier surface checked", [
    demoConfig.skipSurfaceChecks
      ? "Full surface check skipped for repeated cost evaluation."
      : `${objectiveOperationSurfaceChecks.length} opcodes accepted correct claims and rejected wrong ones in the deterministic verifier.`,
    demoConfig.skipSurfaceChecks
      ? "Run npm run test:evm or npm run demo:hardhat without DEMO_SKIP_SURFACE_CHECKS to validate the surface."
      : `${fhevmOperationSurfaceChecks.length} opcodes went through request/finalize in the on-chain local FHEVM verifier.`,
    `objectiveVerifier=${await verifier.getAddress()}`,
    `localFhevmVerifier=${await localFhevm.fhevmVerifier.getAddress()}`,
    `localFhevmExecutor=${await localFhevm.executor.getAddress()}`
  ]);

  printStep("4", "Trace roots prepared", [
    `sourceRunDir=${runDir}`,
    `honestRoot=${honestTree.root}`,
    `dishonestRoot=${dishonestTree.root}`,
    `manipulatedLeafIndex=${manipulatedLeafIndex}`,
    `manipulatedOperation=${honestLeaves[manipulatedLeafIndex].opcode_name}`,
    fheHandlesReady
      ? `ciphertextHandles=TFHE ${honestFheHandles.tfheVersion} keyDigest=${honestFheHandles.keyDigest} `
        + `honest=${honestFheHandles.manifestKey} corrupted=${corruptedFheHandles.manifestKey}`
      : "ciphertextHandles=clear-value fallback (no TFHE manifest; run npm run fhe:export && npm run fhe:execute)"
  ]);

  const honestScenario = await runHonestNodeScenario(
    provider,
    game,
    availability,
    requester,
    honestOperator,
    auditors,
    decryptors,
    honestTree,
    honestLeaves,
    outputAttestationHash,
    fheHandlesReady ? honestFheHandles : null
  );
  printStep("5", "Honest node finalized", [
    "The honest node used the micro-trace unmodified.",
    `decision=${honestScenario.decision} (OperatorAccepted)`,
    `root=${honestScenario.root}`
  ]);

  printStep("6", "Dishonest node submitted a manipulated trace", [
    `Leaf ${manipulatedLeafIndex} was manipulated by the dishonest operator.`,
    `Operation: ${honestLeaves[manipulatedLeafIndex].opcode_name} (opcode=${honestLeaves[manipulatedLeafIndex].opcode})`,
    `Inputs:    lhs=${honestLeaves[manipulatedLeafIndex].lhs}  rhs=${honestLeaves[manipulatedLeafIndex].rhs}`,
    `Correct result:    claimed=${honestLeaves[manipulatedLeafIndex].claimed}`,
    `Fraudulent result: claimed=${dishonestLeaves[manipulatedLeafIndex].claimed}`,
    `A dissenting auditor detects the error and prepares a challenge.`,
    `2 of 3 auditors back the dishonest operator — majority does not decide in this protocol.`
  ]);
  const dishonestScenario = await runDishonestNodeScenario(
    provider,
    game,
    availability,
    requester,
    localFhevm,
    dishonestOperator,
    auditors,
    decryptors,
    honestTree,
    dishonestTree,
    dishonestLeaves,
    honestLeaves,
    honestLeaves[manipulatedLeafIndex],
    dishonestLeaves[manipulatedLeafIndex],
    outputAttestationHash,
    dishonestFheHandles,
    leafDecisionContext
  );

  const slashETH = (n) => `${(Number(n) / 1e18).toFixed(2)} ETH`;
  printStep("7", "RESULT — Objective decision without a majority", [
    `decision=${dishonestScenario.decision} (OperatorSlashed)`,
    `Dishonest operator lost: ${slashETH(dishonestScenario.dishonestStakeDeltaWei)}`,
    `Challenger gained:       ${slashETH(dishonestScenario.challengerStakeDeltaWei)}`,
    `Bisection rounds:        ${dishonestScenario.bisectionRounds.length}`,
    `Resolved leaf:           leaf_index=${dishonestScenario.leafCheck?.leafIndex ?? "?"}  opcode=${dishonestScenario.leafCheck?.opcode ?? "?"}`,
    `Operator valid:          ${dishonestScenario.leafCheck?.operatorValid}`,
    `Challenger valid:        ${dishonestScenario.leafCheck?.challengerValid}`,
    `Decision attested by:    ${leafDecisionState.threshold} of ${leafDecisionState.cores.length} EIP-712 signatures (t+1)`,
    "The final truth came from FHE.eq evaluated under encryption, with only the bit",
    "decrypted and threshold-attested — not from an auditor majority. No operand was published."
  ]);

  const output = {
    network: networkName,
    chainId: Number((await provider.getNetwork()).chainId),
    secureTraceMode: await game.secureTraceMode(),
    ciphertextHandlesReady: fheHandlesReady,
    architecture: "authenticated-full-trace-dispute-verifier",
    config: demoConfig,
    contractAddress: await game.getAddress(),
    objectiveVerifier: await verifier.getAddress(),
    authenticatedTraceAvailability: await availability.getAddress(),
    verdictOpening: kmsState.enabled
      ? {
          backend: "openVerdictViaKMS",
          mode: kmsState.mode,
          verifier: kmsState.verifierAddress,
          threshold: kmsState.threshold,
          coreCount:
            kmsState.mode === "synthetic"
              ? kmsState.cores.length
              : (kmsState.artifact?.cores?.length ?? null),
          artifactPath: demoConfig.kmsArtifactPath,
          consumedOpenings: kmsState.consumed.length
        }
      : { backend: "openVerdict (commit-reveal committee)" },
    // How the terminal leaf was settled. The two equality bits are decided
    // off-chain by checked FHE value equality and accepted on-chain from t+1
    // EIP-712 core signatures; no transaction of this run carries an operand.
    leafDecisionAttestation: {
      backend: "settleLeafViaAttestedDecision",
      verifier: leafDecisionState.verifierAddress,
      domain: leafDecisionState.domain,
      threshold: leafDecisionState.threshold,
      coreCount: leafDecisionState.cores.length,
      typehash: "PublicDecryptVerification(bytes32[] ctHandles,bytes decryptedResult,bytes extraData)",
      bindingTag: "FHE_POD_LEAF_DECISION_V1"
    },
    transactions: transactionLog,
    localFhevm: {
      acl: await localFhevm.acl.getAddress(),
      executor: await localFhevm.executor.getAddress(),
      kms: await localFhevm.kms.getAddress(),
      verifier: await localFhevm.fhevmVerifier.getAddress()
    },
    supportedOperations: objectiveOperationSurfaceChecks,
    supportedFhevmOperations: fhevmOperationSurfaceChecks,
    sourceRunDir: runDir,
    // Provenance of the 32-byte handles registered on-chain: which manifest
    // entry each task's handles came from, and under which TFHE key. Absent
    // only on a fallback run (forbidden by VCFHE_REQUIRE_FHE_HANDLES=1).
    //
    // `source` reports the manifest this run actually read, resolved from
    // VCFHE_CIPHERTEXT_MANIFEST. It used to be the hardcoded canonical path,
    // which was right for the evaluation's evaluations and wrong for every run
    // that points the variable elsewhere — the ANATEL demonstrations keep their
    // own manifest precisely so they cannot touch the canonical one, and the
    // record has to be able to show that rather than assert the opposite.
    ciphertextHandles: fheHandlesReady
      ? {
          source: path.relative(podRootPath, ciphertextManifestPath),
          tfheVersion: honestFheHandles.tfheVersion,
          keyDigest: honestFheHandles.keyDigest,
          determinismVerified: honestFheHandles.determinismVerified,
          honestTask: honestFheHandles.manifestKey,
          dishonestTaskInputs: honestFheHandles.manifestKey,
          dishonestTaskResults: corruptedFheHandles.manifestKey
        }
      : { source: "clear-value fallback (ciphertextHandleForClear)" },
    manipulatedLeafIndex,
    honestLeaf: honestLeaves[manipulatedLeafIndex],
    dishonestLeaf: dishonestLeaves[manipulatedLeafIndex],
    honestNode: honestScenario,
    dishonestNode: dishonestScenario,
    decisions: {
      none: 0,
      operatorAccepted: 1,
      operatorSlashed: 2,
      challengerSlashed: 3
    },
    note:
      "Hardhat run using a real tfhe-rs micro-trace and a local open-source FHEVM adapter. The task is bound to owner-origin records plus program and provenance roots. On challenge, the operator publishes the complete committed trace before bisection. Majority support for the dishonest operator does not decide the case; handle-bound FHEVM leaf checks determine slashing."
  };

  await writeJson(path.join(runDir, "hardhat_dispute_result.json"), output);
  printStep("8", "Artifact written", [
    `output=${path.join(runDir, "hardhat_dispute_result.json")}`,
    `transactions=${transactionLog.length}`,
    `honestDecision=${honestScenario.decision}`,
    `dishonestDecision=${dishonestScenario.decision}`
  ]);
} finally {
  await connection.close();
}
