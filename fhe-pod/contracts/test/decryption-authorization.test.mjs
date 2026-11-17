// Decryption-authorization properties that concern the LOCAL FHEVM runtime
// (the in-repository stand-in for the Zama coprocessor/KMS used on the dev
// chain). These tests DOCUMENT, empirically, the boundary of the model:
//
//  * On the dev chain the "ciphertexts" are the modeled local runtime's
//    cleartext store: `LocalFhevmExecutor.plaintextOf(handle)` returns the
//    value to ANY caller, and `LocalFhevmACL.allowForDecryption` is
//    permissionless. So on this backend the strong properties
//      P1 (no single node decrypts inputs) and
//      P2 (no single node decrypts intermediates)
//    do NOT hold: they hold only against a real threshold-KMS deployment
//    (threshold-kms/README.md). These tests assert the ACTUAL behaviour so the
//    limitation is measured, not assumed, and so a future hardening of the
//    runtime is caught by a red test here.
//
//  * The protection that DOES hold on-chain for the verdict path is that the
//    dispute game exposes no way to decrypt an arbitrary input/intermediate
//    handle: the only reveal is `openVerdictViaKMS`, bound to a submitted audit
//    record and (after the audit fix) to (taskId, auditor, game). That
//    structural property is asserted in kms-verdict-opening.test.mjs.
import test from "node:test";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import { createProvider, signerFor } from "./chain-harness.mjs";
import { compileContracts } from "../../scripts/evm-lib.mjs";

// FheType.Uint32 is used only to give the stored value a wide type so the
// plaintext survives the cast unchanged (we read the exact value back).
// The enum ordering is from @fhevm/solidity FheType; Uint32 is resolved from
// the compiled ABI at runtime rather than hardcoded.
async function deployRuntime() {
  const artifacts = await compileContracts();
  const provider = await createProvider({ totalAccounts: 4, chainId: 31337 });
  const deployer = await signerFor(provider, 0);
  const stranger = await signerFor(provider, 1);
  const deploy = async (name, args = []) => {
    const c = await new ethers.ContractFactory(
      artifacts[name].abi,
      artifacts[name].bytecode,
      deployer
    ).deploy(...args);
    await c.waitForDeployment();
    return c;
  };
  const acl = await deploy("LocalFhevmACL");
  const executor = await deploy("LocalFhevmExecutor");
  return { provider, deployer, stranger, acl, executor };
}

function handleOf(value) {
  return ethers.zeroPadValue(ethers.toBeHex(BigInt(value)), 32);
}

test("MODEL LIMIT: the dev FHEVM runtime lets any caller read an input/intermediate plaintext", async () => {
  const { executor, stranger } = await deployRuntime();
  // Register an "input" ciphertext the way the FHEVM path does (verifyInput
  // stores uint256(handle) as the plaintext; the input proof is ignored by the
  // local stand-in). FheType is passed as 4 (an unsigned integer type); the
  // stored value is read back exactly.
  const inputValue = 4242n;
  // trivialEncrypt stores the value and returns its runtime handle; predict the
  // handle with a static call, then persist it (the handle counter is stable
  // across the static call and the real tx).
  const storedHandle = await executor.trivialEncrypt.staticCall(inputValue, 4);
  await (await executor.trivialEncrypt(inputValue, 4)).wait();

  // A stranger (any unfunded account, via eth_call) reads the plaintext.
  const asStranger = executor.connect(stranger);
  const revealed = await asStranger.plaintextOf(storedHandle);
  assert.equal(
    revealed,
    inputValue,
    "on the dev runtime plaintextOf is world-readable — P1/P2 hold only against a real threshold KMS"
  );
});

test("MODEL LIMIT: LocalFhevmACL.allowForDecryption is permissionless on the dev runtime", async () => {
  const { acl, stranger } = await deployRuntime();
  const handle = handleOf(7n);
  assert.equal(await acl.isAllowedForDecryption(handle), false);
  // Anyone can mark any handle publicly decryptable.
  await (await acl.connect(stranger).allowForDecryption([handle])).wait();
  assert.equal(
    await acl.isAllowedForDecryption(handle),
    true,
    "any caller can flag any handle decryptable — a real deployment gates this"
  );
});
