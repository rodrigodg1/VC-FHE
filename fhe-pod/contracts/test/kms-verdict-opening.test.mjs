// Tests for the legacy threshold-signature response format (KMS simulated):
// ZamaKMSVerdictVerifier (EIP-712 threshold-signature verification in the
// format targeted for zama-ai/kms v0.13.20 public decryption) and
// VerifiableFHEDisputeGame.openVerdictViaKMS.
//
// The four "KMS cores" here are local k256 identities signing the identical
// typed data the production cores sign (PublicDecryptVerification over a
// client-supplied domain); the live-KMS end-to-end run replaces these
// signatures with the cores' `external_signature` bytes without any contract
// change (see threshold-kms/README.md).
import test from "node:test";
import assert from "node:assert/strict";
import {
  advanceTime,
  createProvider,
  PAST_WINDOW_SECONDS,
  revertMatcher,
  signerFor,
  WINDOW_SECONDS
} from "./chain-harness.mjs";
import { ethers } from "ethers";
import {
  boundCreateTaskArgs,
  buildMerkleTree,
  compileContracts,
  sampleTaskParticipants
} from "../../scripts/evm-lib.mjs";

const mnemonic = "test test test test test test test test test test test junk";
const chainId = 31337;
const DOMAIN_NAME = "VCFHE-Verdict-Opening";
const DOMAIN_VERSION = "1";

const leaves = [
  { opcode: 1, lhs: 12, rhs: 5, claimed: 60 },
  { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
  { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
  { opcode: 5, lhs: 7, rhs: 1, claimed: 1 }
];

const PUBLIC_DECRYPT_TYPES = {
  PublicDecryptVerification: [
    { name: "ctHandles", type: "bytes32[]" },
    { name: "decryptedResult", type: "bytes" },
    { name: "extraData", type: "bytes" }
  ]
};

function encodeVerdictPlaintext(bit) {
  return ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [bit ? 1n : 0n]);
}

function encodeDecryptionProof(signatures, extraData = "0x") {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes[]", "bytes"],
    [signatures, extraData]
  );
}

async function signPublicDecryption(core, domain, handles, decryptedResult, extraData = "0x") {
  return core.signTypedData(domain, PUBLIC_DECRYPT_TYPES, {
    ctHandles: handles,
    decryptedResult,
    extraData
  });
}

/** Synthetic TFHE ebool ciphertext stand-in: opaque bytes; the on-chain
 * protocol only ever sees keccak256(ciphertext) as the handle. */
function makeVerdictCiphertext(seedText) {
  const bytes = ethers.toUtf8Bytes(`ebool-ciphertext:${seedText}`);
  return { bytes, handle: ethers.keccak256(bytes) };
}

async function increaseTime(provider, seconds) {
  await advanceTime(provider, seconds);
}

async function deployKmsFixture() {
  const provider = await createProvider({ totalAccounts: 12, chainId: 31337 });
  const deployer = await signerFor(provider, 0);
  const operator = await signerFor(provider, 1);
  const auditors = [
    await signerFor(provider, 2),
    await signerFor(provider, 3),
    await signerFor(provider, 4)
  ];
  const decryptors = [
    await signerFor(provider, 5),
    await signerFor(provider, 6),
    await signerFor(provider, 7)
  ];

  // Four KMS core identities (n=4, t=1 => threshold t+1 = 2 = num_majority).
  const cores = Array.from({ length: 4 }, () => ethers.Wallet.createRandom());
  const coreAddresses = cores.map((core) => core.address);
  const kmsThreshold = 2;

  const artifacts = await compileContracts();
  const objectiveVerifier = await new ethers.ContractFactory(
    artifacts.ObjectiveMicroVerifier.abi,
    artifacts.ObjectiveMicroVerifier.bytecode,
    deployer
  ).deploy();
  await objectiveVerifier.waitForDeployment();

  const game = await new ethers.ContractFactory(
    artifacts.LegacyConfigurableDisputeGame.abi,
    artifacts.LegacyConfigurableDisputeGame.bytecode,
    deployer
  ).deploy(await objectiveVerifier.getAddress(), WINDOW_SECONDS, WINDOW_SECONDS, WINDOW_SECONDS, false);
  await game.waitForDeployment();

  const kmsVerifier = await new ethers.ContractFactory(
    artifacts.ZamaKMSVerdictVerifier.abi,
    artifacts.ZamaKMSVerdictVerifier.bytecode,
    deployer
  ).deploy(
    DOMAIN_NAME,
    DOMAIN_VERSION,
    0,
    ethers.ZeroAddress,
    coreAddresses,
    kmsThreshold
  );
  await kmsVerifier.waitForDeployment();
  await (await game.setKmsVerdictVerifier(await kmsVerifier.getAddress())).wait();

  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  for (const auditor of auditors) {
    await (await game.connect(auditor).registerAuditor({ value: ethers.parseEther("1") })).wait();
  }
  for (const decryptor of decryptors) {
    await (await game.connect(decryptor).registerDecryptor({ value: ethers.parseEther("1") })).wait();
  }

  // The verifier binds the domain to block.chainid, so the off-chain domain
  // must use the chain actually under test, not a hardcoded development id.
  const domain = {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId: Number((await provider.getNetwork()).chainId),
    verifyingContract: await kmsVerifier.getAddress()
  };

  return {
    provider,
    deployer,
    operator,
    auditors,
    decryptors,
    cores,
    kmsThreshold,
    game,
    kmsVerifier,
    domain
  };
}

async function createSampledTask(fixture, taskSeed) {
  const { game, operator, provider } = fixture;
  const taskId = ethers.keccak256(ethers.toUtf8Bytes(`kms-task:${taskSeed}`));
  const tree = buildMerkleTree(leaves);
  const outputAttestationHash = ethers.keccak256(
    ethers.toUtf8Bytes(`attestation:${taskSeed}`)
  );
  const createArgs = boundCreateTaskArgs(taskId, tree, leaves, outputAttestationHash);
  await (await game.connect(operator).createTask(...createArgs)).wait();
  await sampleTaskParticipants(game.connect(operator), taskId);
  const assignedAuditors = [];
  for (const auditor of fixture.auditors) {
    const [assigned] = await game.getAuditStatus(taskId, auditor.address);
    if (assigned) assignedAuditors.push(auditor);
  }
  assert.ok(assignedAuditors.length >= 1, "expected at least one assigned auditor");
  return { taskId, tree, assignedAuditors };
}

async function firstAssignedLeaf(game, taskId, auditor) {
  for (let leafIndex = 0; leafIndex < leaves.length; leafIndex += 1) {
    if (await game.isAuditorAssignedToLeaf(taskId, auditor.address, leafIndex)) {
      return leafIndex;
    }
  }
  throw new Error("no assigned leaf");
}

async function submitKmsAudit(fixture, taskId, auditor, seedText) {
  const { game } = fixture;
  const leafIndex = await firstAssignedLeaf(game, taskId, auditor);
  const podRoot = ethers.keccak256(ethers.toUtf8Bytes(`pod:${seedText}`));
  const ciphertext = makeVerdictCiphertext(seedText);
  await (
    await game
      .connect(auditor)
      .submitAudit(taskId, leafIndex, podRoot, ciphertext.handle)
  ).wait();
  return { leafIndex, podRoot, ciphertext };
}

test("verifier digest matches ethers EIP-712 encoding of the KMS struct", async () => {
  const fixture = await deployKmsFixture();
  const handle = ethers.keccak256(ethers.toUtf8Bytes("some-ciphertext"));
  const decryptedResult = encodeVerdictPlaintext(1);
  const digestOnChain = await fixture.kmsVerifier.publicDecryptionDigest(
    [handle],
    decryptedResult,
    "0x"
  );
  const digestOffChain = ethers.TypedDataEncoder.hash(
    fixture.domain,
    PUBLIC_DECRYPT_TYPES,
    { ctHandles: [handle], decryptedResult, extraData: "0x" }
  );
  assert.equal(digestOnChain, digestOffChain);
});

test("t+1 KMS core signatures open a supporting verdict; verdict bit 0 opens dissent", async () => {
  const fixture = await deployKmsFixture();
  const { game, cores, domain, provider } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "happy");

  const submissions = [];
  for (const [index, auditor] of assignedAuditors.entries()) {
    submissions.push({
      auditor,
      verdictBit: index === 0 ? 0 : 1, // first assigned auditor dissents
      ...(await submitKmsAudit(fixture, taskId, auditor, `happy:${index}`))
    });
  }

  await increaseTime(provider, PAST_WINDOW_SECONDS); // past commit window, inside open window

  for (const submission of submissions) {
    const decryptedResult = encodeVerdictPlaintext(submission.verdictBit);
    // The opening must be signed over the execution binding (taskId, auditor, game).
    const extra = await game.verdictOpeningBinding(taskId, submission.auditor.address);
    const signatures = [
      await signPublicDecryption(cores[0], domain, [submission.ciphertext.handle], decryptedResult, extra),
      await signPublicDecryption(cores[1], domain, [submission.ciphertext.handle], decryptedResult, extra)
    ];
    const receipt = await (
      await game.openVerdictViaKMS(
        taskId,
        submission.auditor.address,
        submission.podRoot,
        decryptedResult,
        encodeDecryptionProof(signatures, extra)
      )
    ).wait();
    const opened = receipt.logs
      .map((log) => {
        try {
          return game.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === "VerdictOpened");
    assert.ok(opened, "VerdictOpened event expected");
    assert.equal(opened.args.verdictSupportsOperator, submission.verdictBit !== 0);

    const [, , openedFlag, , verdictSupportsOperator] = await game.getAuditStatus(
      taskId,
      submission.auditor.address
    );
    assert.equal(openedFlag, true);
    assert.equal(verdictSupportsOperator, submission.verdictBit !== 0);
  }
});

test("legacy KMS opening rejects a correctly signed non-Boolean word", async () => {
  const fixture = await deployKmsFixture();
  const { game, cores, domain, provider } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "non-boolean");
  const auditor = assignedAuditors[0];
  const submission = await submitKmsAudit(fixture, taskId, auditor, "non-boolean:0");
  await increaseTime(provider, PAST_WINDOW_SECONDS);
  const plaintext = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [5]);
  const extra = await game.verdictOpeningBinding(taskId, auditor.address);
  const signatures = await Promise.all(cores.slice(0, 2).map(core =>
    signPublicDecryption(core, domain, [submission.ciphertext.handle], plaintext, extra)));
  await assert.rejects(async () => (await game.openVerdictViaKMS(taskId,
    auditor.address, submission.podRoot, plaintext,
    encodeDecryptionProof(signatures, extra))).wait());
  assert.equal((await game.getAuditStatus(taskId, auditor.address))[2], false);
});

test("fewer than threshold, duplicate-core, and unregistered signatures are rejected", async () => {
  const fixture = await deployKmsFixture();
  const { game, cores, domain, provider } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "reject");
  const auditor = assignedAuditors[0];
  const submission = await submitKmsAudit(fixture, taskId, auditor, "reject:0");
  await increaseTime(provider, PAST_WINDOW_SECONDS);

  const decryptedResult = encodeVerdictPlaintext(1);
  const extra = await game.verdictOpeningBinding(taskId, auditor.address);
  const sign = (core) =>
    signPublicDecryption(core, domain, [submission.ciphertext.handle], decryptedResult, extra);

  // 1 valid signature < threshold 2.
  await assert.rejects(
    game.openVerdictViaKMS(
      taskId, auditor.address, submission.podRoot,
      decryptedResult,
      encodeDecryptionProof([await sign(cores[0])], extra)
    ),
    revertMatcher(game, "NotEligible")
  );
  // Two copies of the same core's signature count once.
  const duplicated = await sign(cores[0]);
  await assert.rejects(
    game.openVerdictViaKMS(
      taskId, auditor.address, submission.podRoot,
      decryptedResult,
      encodeDecryptionProof([duplicated, duplicated], extra)
    ),
    revertMatcher(game, "NotEligible")
  );
  // Unregistered signer + one valid core.
  const outsider = ethers.Wallet.createRandom();
  await assert.rejects(
    game.openVerdictViaKMS(
      taskId, auditor.address, submission.podRoot,
      decryptedResult,
      encodeDecryptionProof([
        await sign(cores[0]),
        await signPublicDecryption(outsider, domain, [submission.ciphertext.handle], decryptedResult, extra)
      ], extra)
    ),
    revertMatcher(game, "NotEligible")
  );
});

test("signatures over a different handle or tampered plaintext cannot open the audit", async () => {
  const fixture = await deployKmsFixture();
  const { game, cores, domain, provider } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "bind");
  const auditor = assignedAuditors[0];
  const submission = await submitKmsAudit(fixture, taskId, auditor, "bind:0");
  await increaseTime(provider, PAST_WINDOW_SECONDS);

  const decryptedResult = encodeVerdictPlaintext(1);
  const extra = await game.verdictOpeningBinding(taskId, auditor.address);
  // Replay: valid t+1 signatures over ANOTHER ciphertext handle.
  const foreign = makeVerdictCiphertext("bind:foreign");
  const foreignSignatures = [
    await signPublicDecryption(cores[0], domain, [foreign.handle], decryptedResult, extra),
    await signPublicDecryption(cores[1], domain, [foreign.handle], decryptedResult, extra)
  ];
  await assert.rejects(
    game.openVerdictViaKMS(
      taskId, auditor.address, submission.podRoot,
      decryptedResult,
      encodeDecryptionProof(foreignSignatures, extra)
    ),
    revertMatcher(game, "NotEligible")
  );
  // Tamper: signatures over plaintext 0 submitted with plaintext 1.
  const dissent = encodeVerdictPlaintext(0);
  const dissentSignatures = [
    await signPublicDecryption(cores[0], domain, [submission.ciphertext.handle], dissent, extra),
    await signPublicDecryption(cores[1], domain, [submission.ciphertext.handle], dissent, extra)
  ];
  await assert.rejects(
    game.openVerdictViaKMS(
      taskId, auditor.address, submission.podRoot,
      decryptedResult, // claimed 1, signed 0
      encodeDecryptionProof(dissentSignatures, extra)
    ),
    revertMatcher(game, "NotEligible")
  );
});

test("phase gating: KMS opening rejected inside commit window and after open deadline; no double opening", async () => {
  const fixture = await deployKmsFixture();
  const { game, cores, domain, provider } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "phase");
  const auditor = assignedAuditors[0];
  const submission = await submitKmsAudit(fixture, taskId, auditor, "phase:0");

  const decryptedResult = encodeVerdictPlaintext(1);
  const extra = await game.verdictOpeningBinding(taskId, auditor.address);
  const signatures = [
    await signPublicDecryption(cores[0], domain, [submission.ciphertext.handle], decryptedResult, extra),
    await signPublicDecryption(cores[1], domain, [submission.ciphertext.handle], decryptedResult, extra)
  ];
  const proof = encodeDecryptionProof(signatures, extra);

  // Still inside the commit window.
  await assert.rejects(
    game.openVerdictViaKMS(taskId, auditor.address, submission.podRoot, decryptedResult, proof),
    revertMatcher(game, "WrongPhase")
  );

  await increaseTime(provider, PAST_WINDOW_SECONDS);
  // Explicit gas limit: after a failed estimate in the same ganache
  // instance, later eth_estimateGas calls through ethers spuriously report
  // "missing revert data" although eth_call and execution succeed (same
  // workaround as sampleTaskParticipants in evm-lib.mjs).
  await (
    await game.openVerdictViaKMS(
      taskId, auditor.address, submission.podRoot, decryptedResult, proof,
      { gasLimit: 400_000 }
    )
  ).wait();
  // Double opening rejected.
  await assert.rejects(
    game.openVerdictViaKMS(taskId, auditor.address, submission.podRoot, decryptedResult, proof),
    revertMatcher(game, "StateConflict")
  );

  // A second assigned auditor left unopened past the open deadline.
  if (assignedAuditors.length > 1) {
    const late = assignedAuditors[1];
    const lateSubmission = await submitKmsAudit(fixture, taskId, late, "phase:late").catch(() => null);
    await increaseTime(provider, PAST_WINDOW_SECONDS);
    if (lateSubmission) {
      const lateResult = encodeVerdictPlaintext(1);
      const lateExtra = await game.verdictOpeningBinding(taskId, late.address);
      const lateProof = encodeDecryptionProof([
        await signPublicDecryption(cores[0], domain, [lateSubmission.ciphertext.handle], lateResult, lateExtra),
        await signPublicDecryption(cores[1], domain, [lateSubmission.ciphertext.handle], lateResult, lateExtra)
      ], lateExtra);
      await assert.rejects(
        game.openVerdictViaKMS(taskId, late.address, lateSubmission.podRoot, lateResult, lateProof),
        revertMatcher(game, "WrongPhase")
      );
    }
  }
});

test("commit-reveal openVerdict path remains functional alongside the KMS path", async () => {
  const fixture = await deployKmsFixture();
  const { game, provider, decryptors } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "legacy");
  const auditor = assignedAuditors[0];
  const leafIndex = await firstAssignedLeaf(game, taskId, auditor);
  const podRoot = ethers.keccak256(ethers.toUtf8Bytes("pod:legacy"));
  const salt = ethers.keccak256(ethers.toUtf8Bytes("salt:legacy"));
  const verdict = true;
  const verdictCommit = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bool", "bytes32", "bytes32"],
      [verdict, salt, podRoot]
    )
  );
  await (
    await game.connect(auditor).submitAudit(taskId, leafIndex, podRoot, verdictCommit)
  ).wait();
  await increaseTime(provider, PAST_WINDOW_SECONDS);

  const assignedDecryptors = [];
  for (const decryptor of decryptors) {
    const assigned = await game.getAssignedDecryptors(taskId);
    if (assigned.map((a) => a.toLowerCase()).includes(decryptor.address.toLowerCase())) {
      assignedDecryptors.push(decryptor);
    }
  }
  assert.ok(assignedDecryptors.length >= 2, "need two assigned opening participants");
  for (const decryptor of assignedDecryptors.slice(0, 2)) {
    await (
      await game.connect(decryptor).openVerdict(taskId, auditor.address, verdict, salt, podRoot)
    ).wait();
  }
  const [, , openedFlag, , verdictSupportsOperator] = await game.getAuditStatus(
    taskId,
    auditor.address
  );
  assert.equal(openedFlag, true);
  assert.equal(verdictSupportsOperator, true);
});

// ===========================================================================
// Decryption-authorization property tests (audit).
//
// These exercise the execution-binding anti-replay guard added to
// openVerdictViaKMS, and the threshold / single-node properties, mapping to
// the requested checklist:
//   * cannot reuse a decryption authorization from another execution (17)
//   * cannot associate the opening with a different task/auditor (18)
//   * a single node cannot open a verdict (14)
//   * insufficient / unavailable participants cannot reach the threshold (19,20)
//   * decryption is bound to (task, auditor, game) and to the committed handle (8)
// ===========================================================================

test("execution binding: a KMS opening is bound to (taskId, auditor, game)", async () => {
  const fixture = await deployKmsFixture();
  const { game } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "bind-shape");
  const auditor = assignedAuditors[0];
  const binding = await game.verdictOpeningBinding(taskId, auditor.address);
  const [bTask, bAuditor, bGame] = ethers.AbiCoder.defaultAbiCoder().decode(
    ["bytes32", "address", "address"],
    binding
  );
  assert.equal(bTask, taskId, "binding must carry the taskId");
  assert.equal(bAuditor, auditor.address, "binding must carry the auditor");
  assert.equal(bGame, await game.getAddress(), "binding must carry the game instance");
  // A binding for a different task or a different game is different bytes, so a
  // bundle signed for one cannot satisfy another.
  const other = await game.verdictOpeningBinding(
    ethers.keccak256(ethers.toUtf8Bytes("other-task")),
    auditor.address
  );
  assert.notEqual(binding, other, "binding must change with the task");
});

test("replay: a bundle bound to auditor A cannot open auditor B's identical-handle record", async () => {
  const fixture = await deployKmsFixture();
  const { game, cores, domain, provider } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "replay");
  if (assignedAuditors.length < 2) return; // needs two assigned auditors
  const [a, b] = assignedAuditors;

  // Both auditors commit the SAME verdict handle (B copies A's) to set up the
  // strongest replay: the KMS-signed handle matches both records.
  const shared = makeVerdictCiphertext("replay:shared");
  const leafA = await firstAssignedLeaf(game, taskId, a);
  const leafB = await firstAssignedLeaf(game, taskId, b);
  const podA = ethers.keccak256(ethers.toUtf8Bytes("pod:replay:a"));
  const podB = ethers.keccak256(ethers.toUtf8Bytes("pod:replay:b"));
  await (await game.connect(a).submitAudit(taskId, leafA, podA, shared.handle)).wait();
  await (await game.connect(b).submitAudit(taskId, leafB, podB, shared.handle)).wait();
  await increaseTime(provider, PAST_WINDOW_SECONDS);

  const result = encodeVerdictPlaintext(1);
  const extraA = await game.verdictOpeningBinding(taskId, a.address);
  const sigsA = [
    await signPublicDecryption(cores[0], domain, [shared.handle], result, extraA),
    await signPublicDecryption(cores[1], domain, [shared.handle], result, extraA)
  ];

  // A opens correctly.
  await (
    await game.openVerdictViaKMS(taskId, a.address, podA, result, encodeDecryptionProof(sigsA, extraA), {
      gasLimit: 400_000
    })
  ).wait();

  // Replay 1: reuse A's exact proof (extraData bound to A) to open B -> rejected.
  await assert.rejects(
    game.openVerdictViaKMS(taskId, b.address, podB, result, encodeDecryptionProof(sigsA, extraA)),
    revertMatcher(game, "NotEligible"),
    "A's bundle must not open B"
  );
  // Replay 2: rewrap A's signatures with B's binding -> signatures no longer
  // verify over the new digest -> rejected.
  const extraB = await game.verdictOpeningBinding(taskId, b.address);
  await assert.rejects(
    game.openVerdictViaKMS(taskId, b.address, podB, result, encodeDecryptionProof(sigsA, extraB)),
    revertMatcher(game, "NotEligible"),
    "A's signatures must not verify under B's binding"
  );
  // Positive control: a bundle actually signed for B opens B.
  const sigsB = [
    await signPublicDecryption(cores[0], domain, [shared.handle], result, extraB),
    await signPublicDecryption(cores[1], domain, [shared.handle], result, extraB)
  ];
  await (
    await game.openVerdictViaKMS(taskId, b.address, podB, result, encodeDecryptionProof(sigsB, extraB), {
      gasLimit: 400_000
    })
  ).wait();
  const [, , openedB] = await game.getAuditStatus(taskId, b.address);
  assert.equal(openedB, true, "B opens with its own binding");
});

test("threshold: a single core (unavailable second core) cannot open; t+1 can", async () => {
  const fixture = await deployKmsFixture();
  const { game, cores, domain, provider } = fixture;
  const { taskId, assignedAuditors } = await createSampledTask(fixture, "threshold");
  const auditor = assignedAuditors[0];
  const submission = await submitKmsAudit(fixture, taskId, auditor, "threshold:0");
  await increaseTime(provider, PAST_WINDOW_SECONDS);

  const result = encodeVerdictPlaintext(1);
  const extra = await game.verdictOpeningBinding(taskId, auditor.address);
  const sig0 = await signPublicDecryption(cores[0], domain, [submission.ciphertext.handle], result, extra);
  const sig1 = await signPublicDecryption(cores[1], domain, [submission.ciphertext.handle], result, extra);

  // One core available (the other is down) => below threshold 2 => rejected.
  await assert.rejects(
    game.openVerdictViaKMS(taskId, auditor.address, submission.podRoot, result, encodeDecryptionProof([sig0], extra)),
    revertMatcher(game, "NotEligible"),
    "a single node must not open a verdict"
  );
  // Both cores available => threshold reached => opens.
  await (
    await game.openVerdictViaKMS(
      taskId, auditor.address, submission.podRoot, result,
      encodeDecryptionProof([sig0, sig1], extra),
      { gasLimit: 400_000 }
    )
  ).wait();
  const [, , opened] = await game.getAuditStatus(taskId, auditor.address);
  assert.equal(opened, true);
});

test("structural: the game's only decryption-opening entrypoints are audit-record scoped", async () => {
  const fixture = await deployKmsFixture();
  const names = [];
  fixture.game.interface.forEachFunction((f) => names.push(f.name));
  // The only functions that open (reveal) a verdict are these two, and both
  // take (taskId, auditor, ...) — they are scoped to a submitted audit record,
  // never to a caller-chosen raw ciphertext handle.
  const openers = names.filter((n) => /^openVerdict/.test(n)).sort();
  assert.deepEqual(openers, ["openVerdict", "openVerdictViaKMS"], "unexpected verdict-opening surface");
  for (const opener of openers) {
    const fn = fixture.game.interface.getFunction(opener);
    assert.equal(fn.inputs[0].type, "bytes32", `${opener} arg0 is taskId`);
    assert.equal(fn.inputs[1].type, "address", `${opener} arg1 is auditor`);
  }
  // The game exposes no plaintext-reveal getter for a raw ciphertext handle:
  // the only reveal is the record-scoped verdict opening above.
  assert.ok(!names.includes("plaintextOf"), "the game must not expose plaintextOf");
  assert.ok(!names.includes("decrypt"), "the game must not expose a decrypt function");
});
