/**
 * Smoke-test payload generator for mklhs_tfhe_onchain.mjs.
 *
 * Emits the SAME JSON schema as the Rust real-TFHE emitter
 * (`emit-onchain-mk`), but with pseudorandom Fr coordinate vectors instead of
 * real TFHE-LWE ciphertexts (scheme: "output_binding_demo_multikey").
 *
 * Purpose: validate the on-chain wiring (deployment, key registration,
 * admission pairings, accumulator equality, adversarial rejections, consumer
 * recomputation) and collect contract-level gas WITHOUT the Rust toolchain.
 * On-chain gas is encoding-independent -- the contract sees only BN254
 * points -- so gas collected with this payload equals gas for the real-TFHE
 * payload. The real-TFHE payload additionally substantiates the end-to-end
 * correctness claim (genuine LWE vectors, leveled decryption); generate it
 * with:
 *   cargo run --release --bin output_binding_tfhe -- emit-onchain-mk onchain_proofs_tfhe_mk.json 10 50 100 200
 *
 * Usage: node scripts/mklhs_make_demo_payload.mjs [out.json] [sizes...]
 * Defaults: onchain_proofs_demo_mk.json, sizes 10 50 100 200
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { bn254 } from "@noble/curves/bn254";

const require = createRequire(import.meta.url);
const L = require("./mklhs-lib.js");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const outPath = process.argv[2] ?? path.join(root, "onchain_proofs_demo_mk.json");
const sizes = process.argv.length > 3 ? process.argv.slice(3).map(Number) : [10, 50, 100, 200];

const Fr = bn254.fields.Fr.ORDER;
// Coordinates are pseudorandom Fr elements, NOT ciphertexts: this payload
// exercises wiring and the acceptance predicate, never TFHE semantics.
//
// D defaults to 8, not to the real-TFHE D = 743. Every generator and every
// commitment here is built with pure-JS BN254 scalar multiplication, so D = 743
// over the default sizes costs tens of minutes, which made the two commands
// that consume this payload (`payload:demo-mk`, `verify:soundness`) unusable in
// practice. Nothing those commands check depends on D: on-chain gas is
// independent of it (the contract sees one G1 commitment per record) and
// cryptographic soundness is encoding-independent. Set DEMO_D=743 to reproduce
// the real-TFHE consumer-side cost profile.
const D = Number(process.env.DEMO_D ?? 8);
const TAG = "0x" + "c1".repeat(32);

const rng = L.makeRng(`demo-mk-payload`);
const gens = L.commitGenerators(D);

function g1Dec(p) {
  const a = p.toAffine();
  return [a.x.toString(), a.y.toString()];
}
function g2Dec(p) {
  const a = p.toAffine();
  return [a.x.c0.toString(), a.x.c1.toString(), a.y.c0.toString(), a.y.c1.toString()];
}
function randFr() {
  let v = 0n;
  const bytes = rng(32);
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v % Fr;
}

const entries = [];
for (const n of sizes) {
  for (const op of [0, 1]) {
    const weights = L.weightsFor(op, n); // signed BigInt +-1
    const coords = Array.from({ length: n }, () =>
      Array.from({ length: D }, () => randFr())
    );
    const owners = Array.from({ length: n }, () => L.keygen(rng));
    const commitments = coords.map((c) => L.commit(c, gens));
    // The authorized operation is inside the signed context (Eq. ctx_i), and the
    // contract recomputes M_i with its own `allowedOperation`. Signing under a
    // literal 0 therefore produced SUB entries whose records the SUB deployment
    // correctly refused with InvalidSignature; `op` is the entry's operation.
    const sigs = commitments.map((p, i) => L.sign(owners[i].sk, p, TAG, i, { pk: owners[i].pk, op, totalItems: n }));

    // Lifted accumulator over Fr and its commitment (accumulator equality).
    const lifted = Array.from({ length: D }, (_, d) => {
      let acc = 0n;
      for (let i = 0; i < n; i++) {
        acc = (acc + ((weights[i] === 1n ? coords[i][d] : Fr - coords[i][d]))) % Fr;
      }
      return acc;
    });
    const pLifted = L.commit(lifted, gens);
    const pAttack = L.commit(coords[0], gens);
    // Wrong-key adversarial record: the correct context (including `op`) signed
    // under another owner's key, so the rejection isolates the key, not the op.
    const wrongKeySig = L.sign(owners[n > 1 ? 1 : 0].sk, commitments[0], TAG, 0, { pk: owners[0].pk, op, totalItems: n });

    entries.push({
      n,
      allowed_op: op,
      expected_plaintext: 0, // demo payload has no plaintext semantics
      dataset_tag: TAG,
      records: coords.map((_, i) => ({
        index: i,
        commitment: g1Dec(commitments[i]),
        signature: g1Dec(sigs[i]),
        pubkey: g2Dec(owners[i].pk),
      })),
      honest: {
        commitment: g1Dec(pLifted),
        output_digest: L.coordsDigest(lifted),
        lifted: lifted.map(String),
      },
      attack: {
        commitment: g1Dec(pAttack),
        output_digest: L.coordsDigest(coords[0]),
      },
      wrong_key_signature: g1Dec(wrongKeySig),
    });
    console.log(`built n=${n} op=${op === 0 ? "SUM" : "SUB"}`);
  }
}

const payload = {
  curve: "BN254",
  hash_domain: "MKLHS_CTX_V1_",
  scheme: "output_binding_demo_multikey",
  dataset_tag: TAG,
  lwe_dimension: D - 1,
  ciphertext_dim: D,
  commit_generators: gens.map(g1Dec),
  sizes: entries,
};
fs.writeFileSync(outPath, JSON.stringify(payload));
console.log(`Wrote ${outPath}`);
