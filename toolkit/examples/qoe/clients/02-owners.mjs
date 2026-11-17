/**
 * ROLE: data owners.
 *
 * Each owner, from its own enrolled account: (1) self-registers its BLS G2
 * public key (G2 subgroup check on-chain), then (2) admits its signed
 * real-TFHE record (index, commitment P(c_i), signature sigma_i). Admission
 * runs the two-pairing BLS check of the experiment's Eq. (ob-check) and folds
 * w_i * P(c_i) into the on-chain accumulator; the index is consumed.
 *
 * The plaintext never leaves the owner: the record is a commitment to the
 * TFHE-LWE ciphertext vector emitted by the Rust stage, and the signature
 * covers the encrypted vector plus the (tag, index) label.
 *
 * Usage: node clients/02-owners.mjs [caseLabel]
 */
import { loadCase, connect, roles, readState, writeState, contractAt } from "./common.mjs";

const { entry } = loadCase();
const state = readState(entry.label);
const { accounts } = await connect();
const { ownerSigner } = roles(accounts, entry.n);

const contract = await contractAt(state.contract, accounts[0]);
let regGas = 0n, admitGas = 0n;

for (const r of entry.records) {
  const asOwner = contract.connect(ownerSigner(r.index));
  const reg = await (await asOwner.registerOwnerKey(r.index, r.pubkey.map(BigInt))).wait();
  regGas += reg.gasUsed;
  const adm = await (await asOwner.admitRecord(
    r.index, r.commitment.map(BigInt), r.signature.map(BigInt)
  )).wait();
  admitGas += adm.gasUsed;
  console.log(`owner ${String(r.index).padStart(2)}: key registered (gas ${reg.gasUsed}), record admitted (gas ${adm.gasUsed})`);
}

const admitted = await contract.admittedCount();
console.log(`admitted  : ${admitted}/${entry.n} (mean reg ${regGas / BigInt(entry.n)}, mean admit ${admitGas / BigInt(entry.n)})`);
if (Number(admitted) !== entry.n) throw new Error("not all records admitted");

writeState(entry.label, { ...state, admitted: true });
console.log("next      : node clients/03-operator.mjs " + entry.label);
