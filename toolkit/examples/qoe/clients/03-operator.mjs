/**
 * ROLE: operator (the untrusted compute node).
 *
 * The operator's job in the experiment's linear workflow: homomorphically
 * aggregate the encrypted records ENTIRELY OFF-CHAIN (it never decrypts and
 * never sees a plaintext), canonically serialize the lifted accumulator,
 * and submit only (taskId, digest, commitment) on-chain. The contract
 * accepts iff all N records are admitted and P(A) equals the accumulator it
 * built from the admitted records (O(1), pairing-free).
 *
 * The FHE aggregation itself is the tfhe-rs stage of this repository
 * (`npm run emit:tfhe`): its output, the lifted accumulator
 * `honest.lifted` in data/onchain_proofs_qoe_mk.json, is the encrypted
 * result this client picks up, exactly as an operator node would pick up
 * the output of its FHE engine. This client then performs the operator's
 * chain-facing steps: canonical serialization, Keccak digest, Pedersen
 * commitment over the emitted generators, stake, and submission.
 *
 * Usage: node clients/03-operator.mjs [caseLabel]
 */
import { ethers } from "ethers";
import {
  loadCase, connect, roles, readState, writeState, contractAt,
  coordsDigest, recomputeCommitment,
} from "./common.mjs";

const { payload, entry } = loadCase();
const state = readState(entry.label);
const { accounts } = await connect();
const { operator } = roles(accounts, entry.n);

// 1. Pick up the FHE engine's encrypted result (lifted accumulator).
const lifted = entry.honest.lifted;
console.log(`artifact  : lifted accumulator, ${lifted.length} coordinates (encrypted result)`);

// 2. Canonical serialization -> digest; Pedersen commitment over the
//    emitted generators. This must match what the consumer recomputes.
const digest = coordsDigest(lifted);
const commitment = recomputeCommitment(lifted, payload.commit_generators);
console.log(`digest    : ${digest}`);
console.log(`commitment: [${commitment[0].slice(0, 18)}..., ${commitment[1].slice(0, 18)}...]`);

// 3. Stake and submit (digest, commitment) for the assigned one-shot task.
const contract = await contractAt(state.contract, operator);
await (await contract.depositStake({ value: ethers.parseEther("1") })).wait();
const rcpt = await (await contract.submitResultBound(
  state.taskId, digest, commitment.map(BigInt)
)).wait();
console.log(`submitted : task ${state.taskId} (gas ${rcpt.gasUsed})`);

const [, , , accepted] = await contract.getBoundResult(state.taskId);
console.log(`accepted  : ${accepted}`);
if (!accepted) throw new Error("result not accepted on-chain");

writeState(entry.label, { ...state, submitted: true, digest, commitment });
console.log("next      : node clients/04-consumer.mjs " + entry.label);
