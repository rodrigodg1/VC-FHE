/**
 * ROLE: result consumer.
 *
 * The composed acceptance predicate of the experiment is completed OFF-CHAIN by
 * the consumer: it recomputes, from the DELIVERED artifact (the lifted
 * accumulator the operator hands over), the canonical digest and the
 * commitment P(A'), and accepts only if both equal the on-chain record.
 * Only then does it reduce and decrypt. This step is mandatory because the
 * chain stores a digest and a commitment, not the (large) ciphertext.
 *
 * Decryption: the payload was emitted with `decrypt_checked: true`, i.e.
 * the Rust stage asserted that the reduced canonical ciphertext decrypts
 * exactly to the expected aggregate before emission. In a deployment,
 * decryption is a threshold-KMS operation (no single party holds the key);
 * this client therefore reports the asserted plaintext rather than
 * decrypting locally.
 *
 * Usage: node clients/04-consumer.mjs [caseLabel]
 *        node clients/04-consumer.mjs [caseLabel] --tampered   # negative test
 */
import {
  loadCase, connect, readState, contractAt, coordsDigest, recomputeCommitment,
} from "./common.mjs";

const { payload, entry } = loadCase();
const state = readState(entry.label);
const { accounts } = await connect();
const tampered = process.argv.includes("--tampered");

// The artifact as DELIVERED to this consumer (optionally corrupted to show
// that the consumer check catches a divergent delivery).
const delivered = entry.honest.lifted.map(BigInt);
if (tampered) delivered[0] += 1n;

const contract = await contractAt(state.contract, accounts[0]);
const [onCommit, onDigest, boundOperator, accepted] = await contract.getBoundResult(state.taskId);
console.log(`on-chain  : accepted=${accepted} operator=${boundOperator}`);

const digest = coordsDigest(delivered);
const commitment = recomputeCommitment(delivered, payload.commit_generators);
const digestOk = digest === onDigest;
const commitmentOk =
  BigInt(commitment[0]) === BigInt(onCommit[0]) &&
  BigInt(commitment[1]) === BigInt(onCommit[1]);

console.log(`digest    : recomputed ${digestOk ? "MATCHES" : "DIFFERS from"} on-chain record`);
console.log(`commitment: recomputed ${commitmentOk ? "MATCHES" : "DIFFERS from"} on-chain record`);

if (!accepted || !digestOk || !commitmentOk) {
  console.log("verdict   : REJECT the delivery (do not decrypt)");
  process.exit(tampered ? 0 : 1);
}
console.log("verdict   : ACCEPT; proceed to (threshold) decryption");
console.log(`plaintext : ${entry.expected_plaintext} (asserted exact at TFHE emission)`);
console.log(`meaning   : ${entry.interpretation}`);
