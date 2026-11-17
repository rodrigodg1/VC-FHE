// Verifies, empirically, WHERE the isolated disputed micro-instruction is
// resolved and whether the finalize step can be manipulated:
//  (1) the clear ObjectiveMicroVerifier re-executes the opcode natively in the
//      EVM (pure function, synchronous);
//  (2) the FHEVM-compatible path computes the validity bits on-chain via the
//      local executor during requestLeafCheck;
//  (3) a finalizer that submits INVERTED booleans with a dummy proof is
//      rejected on-chain (FHE.checkSignatures -> InvalidKMSSignatures),
//      because the local KMS verifier compares the claimed cleartexts against
//      the plaintexts stored by the on-chain executor;
//  (4) matching booleans finalize successfully.
//  (5) ADD_CHAIN performs 1--8 actual repeated additions in both backends;
//  (6) the FHEVM ABI carries external ciphertext handles/input proofs;
//  (7) both backends reject u64 overflow and out-of-range shifts.
import test from "node:test";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import {
  createProvider,
  signerFor
} from "./chain-harness.mjs";
import { compileContracts } from "../../scripts/evm-lib.mjs";

const OPCODE_MUL = 1;
const OPCODE_SHR = 2;
const OPCODE_ADD = 6;
const OPCODE_ADD_CHAIN = 15;

function handleOf(value) {
  return ethers.zeroPadValue(ethers.toBeHex(BigInt(value)), 32);
}

test("isolated leaf: on-chain enforcement of both verifier backends", async (t) => {
  const artifacts = await compileContracts();
  const provider = await createProvider({ totalAccounts: 3, chainId: 31337 });
  const deployer = await signerFor(provider, 0);

  async function deploy(name, args = []) {
    const artifact = artifacts[name];
    const factory = new ethers.ContractFactory(
      artifact.abi,
      artifact.bytecode,
      deployer
    );
    const contract = await factory.deploy(...args);
    await contract.waitForDeployment();
    return contract;
  }

  // (1) Clear verifier: native EVM re-execution, synchronous and pure.
  const clearVerifier = await deploy("ObjectiveMicroVerifier");
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_MUL, 6n, 7n, 42n), true);
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_MUL, 6n, 7n, 41n), false);
  for (const length of [1n, 4n, 8n]) {
    assert.equal(
      await clearVerifier.verifyLeaf(OPCODE_ADD_CHAIN, 10n, length, 10n + length),
      true
    );
  }
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_ADD_CHAIN, 10n, 0n, 10n), false);
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_ADD_CHAIN, 10n, 9n, 19n), false);
  const maxU64 = (1n << 64n) - 1n;
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_ADD, maxU64, 1n, 0n), false);
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_MUL, maxU64, 2n, maxU64 - 1n), false);
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_SHR, 1n, 64n, 0n), false);
  assert.equal(await clearVerifier.verifyLeaf(OPCODE_ADD, maxU64 + 1n, 0n, 0n), false);

  // FHEVM-compatible path over the EVM-local runtime.
  const acl = await deploy("LocalFhevmACL");
  const executor = await deploy("LocalFhevmExecutor");
  const kms = await deploy("LocalFhevmKMSVerifier", [
    await acl.getAddress(),
    await executor.getAddress()
  ]);
  const fhevmVerifier = await deploy("FhevmObjectiveMicroVerifier", [
    await acl.getAddress(),
    await executor.getAddress(),
    await kms.getAddress()
  ]);

  const requestFragment = fhevmVerifier.interface.getFunction("requestLeafCheck");
  assert.deepEqual(
    requestFragment.inputs[2].components.map((component) => component.type),
    [
      "uint8",
      "bytes32", "bytes32", "bytes32", "bytes32",
      "uint8", "uint8",
      "bytes", "bytes", "bytes", "bytes"
    ],
    "the backend ABI must carry committed ciphertext handles and input proofs"
  );
  assert.ok(
    requestFragment.inputs[2].components.every(
      (component) => component.type !== "uint256"
    ),
    "the backend ABI must carry NO cleartext operand"
  );

  const taskId = ethers.encodeBytes32String("leaf-enforcement");
  const pair = {
    opcode: OPCODE_MUL,
    lhsHandle: handleOf(6n),
    rhsHandle: handleOf(7n),
    operatorClaimedHandle: handleOf(41n),
    challengerClaimedHandle: handleOf(42n),
    lhsSourceKind: 0,
    rhsSourceKind: 0,
    lhsInputProof: "0x01",
    rhsInputProof: "0x01",
    operatorClaimedProof: "0x01",
    challengerClaimedProof: "0x01"
  };

  // (2) requestLeafCheck computes encrypted validity bits ON-CHAIN via the
  // local executor; read them back from the executor's storage.
  const requestTx = await fhevmVerifier.requestLeafCheck(taskId, 3, pair);
  const receipt = await requestTx.wait();
  const parsed = receipt.logs
    .map((log) => {
      try {
        return fhevmVerifier.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry?.name === "FhevmLeafCheckRequested");
  assert.ok(parsed, "FhevmLeafCheckRequested must be emitted");
  const opHandle = parsed.args.operatorValidHandle;
  const chHandle = parsed.args.challengerValidHandle;

  const operatorValid = (await executor.plaintextOf(opHandle)) !== 0n;
  const challengerValid = (await executor.plaintextOf(chHandle)) !== 0n;
  assert.equal(operatorValid, false, "operator claim 41 != 6*7 on-chain");
  assert.equal(challengerValid, true, "challenger claim 42 == 6*7 on-chain");

  // (3) A lying finalizer (inverted booleans, dummy proof) MUST be rejected:
  // the KMS verifier compares against the executor's on-chain plaintexts.
  await assert.rejects(
    (async () => {
      const tx = await fhevmVerifier.finalizeLeafCheck(
        taskId,
        3,
        opHandle,
        chHandle,
        true, // lie: operator valid
        false, // lie: challenger invalid
        "0x01",
        { gasLimit: 500_000n }
      );
      await tx.wait();
    })(),
    /InvalidKMSSignatures|revert|status=0|reverted/i,
    "inverted booleans must not finalize"
  );

  // (4) The truthful booleans finalize.
  const okTx = await fhevmVerifier.finalizeLeafCheck(
    taskId,
    3,
    opHandle,
    chHandle,
    operatorValid,
    challengerValid,
    "0x01",
    { gasLimit: 500_000n }
  );
  const okReceipt = await okTx.wait();
  const finalized = okReceipt.logs
    .map((log) => {
      try {
        return fhevmVerifier.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry?.name === "FhevmLeafCheckFinalized");
  assert.ok(finalized, "FhevmLeafCheckFinalized must be emitted");
  assert.equal(finalized.args.operatorValid, false);
  assert.equal(finalized.args.challengerValid, true);

  // (5) Eight additions are executed by the FHEVM backend for one compound
  // leaf. The wrong/right validity bits are read from the local executor.
  const compoundPair = {
    opcode: OPCODE_ADD_CHAIN,
    lhsHandle: handleOf(100n),
    rhsHandle: handleOf(8n),
    operatorClaimedHandle: handleOf(107n),
    challengerClaimedHandle: handleOf(108n),
    lhsSourceKind: 0,
    rhsSourceKind: 2,
    lhsInputProof: "0x01",
    rhsInputProof: "0x",
    operatorClaimedProof: "0x01",
    challengerClaimedProof: "0x01"
  };
  const compoundReceipt = await (
    await fhevmVerifier.requestLeafCheck(taskId, 4, compoundPair, { gasLimit: 3_000_000n })
  ).wait();
  const compoundEvent = compoundReceipt.logs
    .map((log) => {
      try {
        return fhevmVerifier.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry?.name === "FhevmLeafCheckRequested");
  assert.ok(compoundEvent);
  assert.equal(await executor.plaintextOf(compoundEvent.args.operatorValidHandle), 0n);
  assert.equal(await executor.plaintextOf(compoundEvent.args.challengerValidHandle), 1n);

  async function assertBothInvalid(leafIndex, invalidPair) {
    const invalidReceipt = await (
      await fhevmVerifier.requestLeafCheck(taskId, leafIndex, invalidPair, {
        // MUL now runs an encrypted overflow guard (three encrypted
        // multiplications plus comparisons), so the cap covers it.
        gasLimit: 3_000_000n
      })
    ).wait();
    const invalidEvent = invalidReceipt.logs
      .map((log) => {
        try {
          return fhevmVerifier.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((entry) => entry?.name === "FhevmLeafCheckRequested");
    assert.ok(invalidEvent);
    assert.equal(await executor.plaintextOf(invalidEvent.args.operatorValidHandle), 0n);
    assert.equal(await executor.plaintextOf(invalidEvent.args.challengerValidHandle), 0n);
  }

  const invalidBase = {
    operatorClaimedProof: "0x01",
    challengerClaimedProof: "0x01"
  };
  // ADD overflow: the guard is an ENCRYPTED predicate now (sum >= addend), so
  // the wrapped claim 0 is rejected for both parties without any operand being
  // revealed.
  await assertBothInvalid(5, {
    ...invalidBase,
    opcode: OPCODE_ADD,
    lhsHandle: handleOf(maxU64),
    rhsHandle: handleOf(1n),
    operatorClaimedHandle: handleOf(0n),
    challengerClaimedHandle: handleOf(0n),
    lhsSourceKind: 0,
    rhsSourceKind: 2,
    lhsInputProof: "0x01",
    rhsInputProof: "0x"
  });
  // SHR by 64: the shift amount is a PUBLIC scalar fixed by the program tree,
  // so this guard stays clear -- it is read out of the rhs handle, which for
  // such an operand IS the scalar. A violated public guard yields an encrypted
  // false for both parties rather than reverting, so the dispute still settles.
  await assertBothInvalid(6, {
    ...invalidBase,
    opcode: OPCODE_SHR,
    lhsHandle: handleOf(1n),
    rhsHandle: handleOf(64n),
    operatorClaimedHandle: handleOf(0n),
    challengerClaimedHandle: handleOf(0n),
    lhsSourceKind: 0,
    rhsSourceKind: 2,
    lhsInputProof: "0x01",
    rhsInputProof: "0x"
  });

  // MUL overflow: no clear operand and no 128-bit intermediate, so the guard is
  // the encrypted 32-bit-halves predicate of `_mulFitsInU64`. maxU64 * 2 wraps,
  // and both the wrapped product and any other claim must be rejected.
  await assertBothInvalid(7, {
    ...invalidBase,
    opcode: OPCODE_MUL,
    lhsHandle: handleOf(maxU64),
    rhsHandle: handleOf(2n),
    operatorClaimedHandle: handleOf(maxU64 - 1n),
    challengerClaimedHandle: handleOf(0n),
    lhsSourceKind: 0,
    rhsSourceKind: 0,
    lhsInputProof: "0x01",
    rhsInputProof: "0x01"
  });

  // The same encrypted guard must NOT reject a product that fits: 2^32 * 2^31
  // uses both 32-bit halves and stays inside uint64.
  const wideReceipt = await (
    await fhevmVerifier.requestLeafCheck(
      taskId,
      8,
      {
        ...invalidBase,
        opcode: OPCODE_MUL,
        lhsHandle: handleOf(1n << 32n),
        rhsHandle: handleOf(1n << 31n),
        operatorClaimedHandle: handleOf(1n << 63n),
        challengerClaimedHandle: handleOf(0n),
        lhsSourceKind: 0,
        rhsSourceKind: 0,
        lhsInputProof: "0x01",
        rhsInputProof: "0x01"
      },
      { gasLimit: 3_000_000n }
    )
  ).wait();
  const wideEvent = wideReceipt.logs
    .map((log) => {
      try {
        return fhevmVerifier.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry?.name === "FhevmLeafCheckRequested");
  assert.equal(await executor.plaintextOf(wideEvent.args.operatorValidHandle), 1n);
  assert.equal(await executor.plaintextOf(wideEvent.args.challengerValidHandle), 0n);
});
