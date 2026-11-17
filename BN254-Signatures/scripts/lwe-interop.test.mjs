/**
 * Proves that the JavaScript leveled-LWE implementation and `tfhe-rs` are the
 * SAME cryptosystem, not merely similar ones.
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * `scripts/mklhs-lib.js` re-implements the leveled LWE encoding the implementation
 * defines (b = <a,s> + Delta*m + e mod q, with the lift phi into F_r and the
 * balanced reduction rho). Structural similarity to `tfhe-rs` -- binary secret
 * key, the same Delta, the same sigma, the native modulus -- is NOT evidence of
 * interoperability. An off-by-one in the rounding rule, an inverted secret-key
 * convention, a different coordinate order, or a sign error in the balanced
 * reduction would all survive a careful reading and silently model a different
 * scheme, which would make every JavaScript-side experiment describe something
 * the Rust artifact does not do.
 *
 * The only conclusive check is to decrypt genuine `tfhe-rs` output with the
 * JavaScript code. This test does exactly that, on three levels:
 *
 *   1. individual ciphertexts of known messages,
 *   2. the unreduced SUM accumulator A = sum_i phi(c_i),
 *   3. the unreduced SUB accumulator, which exercises signed weights and is the
 *      case that only works because rho takes the CENTERED representative.
 *
 * Regenerate the vectors (they are seeded, so the file is reproducible):
 *
 *     cargo run --release --bin output_binding_tfhe -- \
 *       emit-lwe-interop scripts/lwe_interop_vectors.json
 *
 * Run: node --test scripts/lwe-interop.test.mjs
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const L = require("./mklhs-lib.js");

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = process.env.LWE_INTEROP_VECTORS ?? path.join(here, "lwe_interop_vectors.json");
const REPO = path.resolve(here, "..", "..");                       // .../VC-FHE
const RUST = path.join(REPO, "BN254-Signatures", "src", "bin", "output_binding_tfhe.rs");
const DESIGN_CRATE = path.join(REPO, "output-binding-lhs", "src", "main.rs");

function loadVectors() {
  if (!fs.existsSync(VECTORS)) {
    throw new Error(
      `missing ${VECTORS}. Generate it with:\n` +
        "  cargo run --release --bin output_binding_tfhe -- " +
        "emit-lwe-interop scripts/lwe_interop_vectors.json"
    );
  }
  return JSON.parse(fs.readFileSync(VECTORS, "utf8"));
}

test("the JS parameters equal the tfhe-rs parameters", () => {
  const v = loadVectors();
  assert.equal(v.lwe_dimension, L.K, "LWE mask dimension k");
  assert.equal(v.ciphertext_dim, L.D, "ciphertext dimension D = k + 1");
  assert.equal(BigInt(v.msg_bits), L.MSG_BITS, "message bit-width l");
  assert.equal(BigInt(v.delta), L.DELTA, "scaling factor Delta");
  assert.equal(v.secret_key.length, L.K, "secret key length");
  assert.ok(
    v.secret_key.every((b) => b === 0 || b === 1),
    "tfhe-rs uses a BINARY secret key; the JS keygen must too"
  );
});

test("JS decrypts individual tfhe-rs ciphertexts", () => {
  const v = loadVectors();
  const key = { s: v.secret_key.map(BigInt) };
  for (const [i, m] of v.messages.entries()) {
    const ct = v.ciphertexts[i].map(BigInt);
    const got = L.heDec(key, ct);
    assert.equal(
      got,
      BigInt(m),
      `ciphertext ${i}: tfhe-rs encrypted ${m}, JS decrypted ${got}`
    );
  }
});

test("JS decrypts the unreduced SUM accumulator through rho", () => {
  const v = loadVectors();
  const key = { s: v.secret_key.map(BigInt) };
  // The accumulator is a signed integer per coordinate; it enters F_r through
  // the same reduction the operator's commitment uses.
  const lifted = v.lifted_sum.map((x) => L.mod(BigInt(x), L.R));
  assert.equal(L.heDec(key, lifted), BigInt(v.expect_sum));
});

test("JS decrypts the unreduced SUB accumulator (signed weights, centered rho)", () => {
  const v = loadVectors();
  const key = { s: v.secret_key.map(BigInt) };
  const lifted = v.lifted_sub.map((x) => L.mod(BigInt(x), L.R));
  const got = L.heDec(key, lifted);
  assert.equal(
    got,
    BigInt(v.expect_sub),
    "SUB only decrypts correctly if rho takes the centered representative"
  );
});

test("a wrong secret key does not decrypt, so the test is not vacuous", () => {
  const v = loadVectors();
  const flipped = v.secret_key.map((b, i) => (i === 0 ? BigInt(1 - b) : BigInt(b)));
  const ct = v.ciphertexts[0].map(BigInt);
  const wrong = L.heDec({ s: flipped }, ct);
  const right = L.heDec({ s: v.secret_key.map(BigInt) }, ct);
  assert.notEqual(
    wrong,
    right,
    "flipping one secret-key bit must change the decryption; if it does not, " +
      "the key is being ignored and these vectors prove nothing"
  );
});

test("all three implementations declare the same LWE parameters", () => {
  // The leveled LWE encoding exists in three places: the tfhe-rs binary that
  // produces the evaluation's numbers, the design-space crate, and this JavaScript
  // tooling. Two of the worst bugs found in this repository were exactly this
  // class of drift -- one implementation kept a noiseless stand-in after the
  // others were fixed, and both Rust crates kept a naive commitment loop after
  // the JavaScript one was optimised. Nothing structural prevented either.
  //
  // This test parses the constants out of both Rust crates and compares them
  // against the shared JavaScript table, so a parameter can no longer be
  // changed in one place alone.
  const tfhe = fs.readFileSync(RUST, "utf8");
  const crate = DESIGN_CRATE;

  const grab = (source, pattern) => {
    const match = new RegExp(pattern).exec(source);
    return match ? match[1] : null;
  };

  assert.equal(grab(tfhe, String.raw`const LWE_K: usize = (\d+)`), String(L.K),
    "LWE mask dimension k differs between the tfhe-rs binary and the JS table");
  assert.equal(grab(tfhe, String.raw`const MSG_BITS: u32 = (\d+)`), String(L.MSG_BITS),
    "message bit-width l differs between the tfhe-rs binary and the JS table");

  const sigma = String.raw`0\.000_007_069_849_454_709_433`;
  assert.match(grab(tfhe, String.raw`const LWE_STD_DEV: f64 = ([0-9_.]+)`) ?? "",
    new RegExp(sigma), "the tfhe-rs binary uses a different noise parameter");

  if (fs.existsSync(crate)) {
    const design = fs.readFileSync(crate, "utf8");
    assert.equal(grab(design, String.raw`const MSG_BITS: u32 = (\d+)`), String(L.MSG_BITS),
      "message bit-width l differs in output-binding-lhs");
    assert.match(design, new RegExp(sigma),
      "output-binding-lhs uses a different noise parameter");
    assert.match(design, /const DELTA: u64 = 1u64 << \(64 - MSG_BITS\)/,
      "output-binding-lhs derives Delta differently");
    // The encoding must be an encryption, not the noiseless stand-in it once was.
    assert.match(design, /sample_noise/,
      "output-binding-lhs encrypts without noise: that is an encoding, not an encryption");
  }
});
