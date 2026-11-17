// Privacy-preserving leaf resolution: a disputed micro-instruction is resolved
// PURELY over ciphertext handles. The call carries NO cleartext user operand;
// only the two encrypted validity bits are produced. This models the
// production FHEVM path and demonstrates that a dispute can reveal only the
// final validity result, never a user's data.
//
// This used to exercise a separate `requestLeafCheckPrivate` entry point, kept
// beside a clear-opening `requestLeafCheck`. There is no longer a clear-opening
// backend to sit beside: `requestLeafCheck` IS the handle-only check, so these
// cases now drive the one and only entry point.
//
// (On the local runtime the "ciphertext" is a stored plaintext, so we can read
// the validity bits back to check correctness; the point demonstrated here is
// the INTERFACE and the LOGIC — the disputed leaf is decided from handles with
// no cleartext operand in calldata.)
import test from "node:test";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import { createProvider, signerFor } from "./chain-harness.mjs";
import { compileContracts } from "../../scripts/evm-lib.mjs";

const OP = { MUL: 1, ADD: 6, SUB: 7, DIV: 8, GT: 12 };
const SOURCE_AUTHENTICATED_INPUT = 0;
const SOURCE_PUBLIC_CONSTANT = 2;

function handleOf(value) {
  return ethers.zeroPadValue(ethers.toBeHex(BigInt(value)), 32);
}

async function deploy() {
  const artifacts = await compileContracts();
  const provider = await createProvider({ totalAccounts: 3, chainId: 31337 });
  const deployer = await signerFor(provider, 0);
  const d = async (name, args = []) => {
    const c = await new ethers.ContractFactory(artifacts[name].abi, artifacts[name].bytecode, deployer).deploy(...args);
    await c.waitForDeployment();
    return c;
  };
  const acl = await d("LocalFhevmACL");
  const executor = await d("LocalFhevmExecutor");
  const kms = await d("LocalFhevmKMSVerifier", [await acl.getAddress(), await executor.getAddress()]);
  const verifier = await d("FhevmObjectiveMicroVerifier", [
    await acl.getAddress(),
    await executor.getAddress(),
    await kms.getAddress()
  ]);
  return { provider, executor, verifier };
}

async function resolvePrivate(verifier, executor, pair) {
  const tx = await verifier.requestLeafCheck(ethers.encodeBytes32String("t"), 0, pair, {
    gasLimit: 3_000_000n
  });
  const receipt = await tx.wait();
  const parsed = receipt.logs
    .map((log) => { try { return verifier.interface.parseLog(log); } catch { return null; } })
    .find((e) => e?.name === "FhevmLeafCheckRequested");
  assert.ok(parsed, "FhevmLeafCheckRequested must be emitted");
  const operatorValid = (await executor.plaintextOf(parsed.args.operatorValidHandle)) !== 0n;
  const challengerValid = (await executor.plaintextOf(parsed.args.challengerValidHandle)) !== 0n;
  return { operatorValid, challengerValid };
}

function inputPair(opcode, lhs, rhs, operatorClaimed, challengerClaimed) {
  return {
    opcode,
    lhsHandle: handleOf(lhs),
    rhsHandle: handleOf(rhs),
    operatorClaimedHandle: handleOf(operatorClaimed),
    challengerClaimedHandle: handleOf(challengerClaimed),
    lhsSourceKind: SOURCE_AUTHENTICATED_INPUT,
    rhsSourceKind: SOURCE_AUTHENTICATED_INPUT,
    lhsInputProof: "0x01",
    rhsInputProof: "0x01",
    operatorClaimedProof: "0x01",
    challengerClaimedProof: "0x01"
  };
}

test("private dispute: an ADD leaf over individual ratings is resolved from handles only", async () => {
  const { executor, verifier } = await deploy();
  // leaf 0 of a MOS sum tree: ADD(rating0=3, rating1=4). Operator claims 9
  // (wrong), challenger claims 7 (right). No rating is passed in cleartext.
  const pair = inputPair(OP.ADD, 3, 4, /*op*/ 9, /*ch*/ 7);
  const { operatorValid, challengerValid } = await resolvePrivate(verifier, executor, pair);
  assert.equal(operatorValid, false, "operator's wrong claim is rejected");
  assert.equal(challengerValid, true, "challenger's correct claim is accepted");

  // The interface carries no cleartext operand at all: every operand field is
  // a handle, and the only public scalar an opcode may need is read out of the
  // committed rhs handle rather than passed in.
  const frag = verifier.interface.getFunction("requestLeafCheck");
  const fields = frag.inputs[2].components.map((c) => c.name);
  assert.ok(!fields.some((n) => /^(operator|challenger)?[lL]hs$|Rhs$|Claimed$/.test(n) && !/Handle$|Proof$/.test(n)),
    "no cleartext operand fields in the leaf pair");
  assert.ok(fields.includes("lhsHandle") && fields.includes("operatorClaimedHandle"),
    "operands are handles");
  assert.ok(
    frag.inputs[2].components.every((c) => c.type !== "uint256"),
    "no uint256 field may survive in the disputed-leaf pair"
  );
});

test("private dispute: MUL (rating^2) resolves from handles only", async () => {
  const { executor, verifier } = await deploy();
  // rating^2 leaf: MUL(4,4)=16. Operator claims 15 (wrong), challenger 16 (right).
  const { operatorValid, challengerValid } = await resolvePrivate(
    verifier, executor, inputPair(OP.MUL, 4, 4, 15, 16)
  );
  assert.equal(operatorValid, false);
  assert.equal(challengerValid, true);
});

test("private dispute: DIV by the PUBLIC panel size n reveals no rating", async () => {
  const { executor, verifier } = await deploy();
  // mean leaf: DIV(sum=15, n=4) = 3 (floor). n is a public constant, not user
  // data. lhs (the aggregate sum) is a previous-output handle.
  const pair = {
    opcode: OP.DIV,
    lhsHandle: handleOf(15),
    // The divisor is a PUBLIC constant, so its "handle" is the scalar itself;
    // the backend reads n out of it, which is what keeps the divisor bound to
    // the committed leaf instead of being a free argument.
    rhsHandle: handleOf(4),
    operatorClaimedHandle: handleOf(4), // wrong (15/4 floor = 3)
    challengerClaimedHandle: handleOf(3), // right
    lhsSourceKind: SOURCE_AUTHENTICATED_INPUT, // previous-output handle, treated as ciphertext
    rhsSourceKind: SOURCE_PUBLIC_CONSTANT,
    lhsInputProof: "0x01",
    rhsInputProof: "0x",
    operatorClaimedProof: "0x01",
    challengerClaimedProof: "0x01"
  };
  const { operatorValid, challengerValid } = await resolvePrivate(verifier, executor, pair);
  assert.equal(operatorValid, false);
  assert.equal(challengerValid, true);
});

test("private dispute: a correct operator claim is accepted, a wrong challenger rejected", async () => {
  const { executor, verifier } = await deploy();
  // Honest operator: SUB(20,4)=16. Operator claims 16 (right), challenger 10 (wrong).
  const { operatorValid, challengerValid } = await resolvePrivate(
    verifier, executor, inputPair(OP.SUB, 20, 4, 16, 10)
  );
  assert.equal(operatorValid, true, "honest operator accepted");
  assert.equal(challengerValid, false, "wrong challenger rejected");
});
