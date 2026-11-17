/**
 * Per-owner BLS signatures and homomorphic commitment tooling for the linear
 * verification path on BN254. MKLHS is the retained component API name.
 *
 * Mirrors the conventions of the Rust artifact (`output-binding-lhs`):
 *   - hash-to-curve: MapToGroup (BLS01) with counter re-hash, 512-bit field
 *                    derivation and a root-selection bit;
 *   - signed context: "MKLHS_CTX_V1_" || pk || tag || i || op || N || P(c_i);
 *   - generators:    G_d over domain "OB_LHS_GEN_" || be8(d);
 *   - index labels:  H(tag, i) over domain "LHS_H2C_" || tag || be8(i), legacy;
 *   - digest:        keccak256 over fixed-width 32-byte BE coordinates;
 *   - encryption:    leveled LWE over the NATIVE modulus q = 2^64, exactly as
 *                    the implementation defines it:
 *                        c_i = (a_i, b_i) in Z_q^D,  D = k + 1,
 *                        b_i = <a_i, s> + Delta*m_i + e_i  (mod q),
 *                        Delta = 2^(64-l) for an l-bit message space.
 *                    Coordinates are lifted into F_r by the injective map
 *                    phi (q < r), summed UNREDUCED as A = sum_i w_i*phi(c_i),
 *                    and recovered by the balanced reduction rho before
 *                    decryption. Parameters mirror the Rust artifact
 *                    (k = 742, l = 10, Delta = 2^54, sigma_e ~ 2^46.9).
 *
 * Multi-key departure from the single-curator scheme: each data owner i holds
 * its own key pair (sk_i, pk_i = sk_i * G2) and signs its OWN record:
 *   sigma_i = sk_i * M_i,  M_i = MapToGroup(ctx_i) with P(c_i) inside ctx_i.
 * The commitment is inside the hash preimage, so the signature carries no
 * linear structure. The off-chain aggregate certificate is
 * sigma_agg = sum_i w_i * sigma_i, verifiable against all owner keys with an
 * (N+1)-pairing product. The on-chain path never pays that product: each
 * admission is verified once and folded into the contract accumulator.
 */
"use strict";

const { keccak256, solidityPacked } = require("ethers");
const { bn254 } = require("@noble/curves/bn254");

const Fp = bn254.fields.Fp;
const Fp12 = bn254.fields.Fp12;
const G1 = bn254.G1.ProjectivePoint;
const G2 = bn254.G2.ProjectivePoint;

const Q = Fp.ORDER; // BN254 base field
const R = bn254.fields.Fr.ORDER; // BN254 scalar field

// Leveled LWE parameters. These mirror src/bin/output_binding_tfhe.rs so the
// JavaScript tooling and the Rust artifact model the SAME cryptosystem; the
// previous stand-in had no noise and no Delta, which made it a linear encoding
// rather than an encryption and left the phi/rho steps of the implementation
// unexercised. MKLHS_LWE_K lowers the dimension for fast unit tests; it changes
// nothing about the construction, only the vector length.
const K = Number(process.env.MKLHS_LWE_K || 742); // LWE mask dimension k
const D = K + 1; // ciphertext vector dimension D = k + 1
const LWE_Q = 1n << 64n; // native modulus q
const MSG_BITS = 10n; // message bit-width l
const DELTA = 1n << (64n - MSG_BITS); // scaling factor Delta = 2^54
const MSG_SPACE = 1n << MSG_BITS; // 2^l
/** Gaussian sigma of the classic tfhe-rs parameter set, scaled to q. */
const LWE_SIGMA = 0.000_007_069_849_454_709_433 * 2 ** 64;

// --------------------------------------------------------------------------
// Utilities
// --------------------------------------------------------------------------

function be8(i) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(i));
  return b;
}

function be32(x) {
  const hex = BigInt(x).toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

function keccakBytes(buf) {
  return BigInt(keccak256(new Uint8Array(buf)));
}

function mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function randFr(rng) {
  // rng: function returning random bytes; deterministic in tests
  let x;
  do {
    x = mod(keccakBytes(rng()), R);
  } while (x === 0n);
  return x;
}

function makeRng(seedLabel) {
  let counter = 0n;
  return () =>
    Buffer.concat([Buffer.from(`MKLHS_TEST_RNG_${seedLabel}_`), be8(counter++)]);
}

// --------------------------------------------------------------------------
// MapToGroup, BLS01 (matches Solidity mapToG1 / Rust hash_to_g1 byte for byte)
// --------------------------------------------------------------------------

/**
 * MapToGroup trial bound. The counter is 8 bits wide (I = 8 in the notation of
 * BLS01), hence at most 2^8 = 256 trials; a preimage is unhashable with
 * probability below 2^-255.
 */
const MAP_TRIALS = 256;
const TWO_POW_256 = 1n << 256n;

/** One Keccak256 block of the expansion, over the 32-byte seed. */
function mapBlock(stream, trial, seed) {
  return keccakBytes(
    Buffer.concat([Buffer.from([stream, trial]), be32(seed)])
  );
}

/**
 * The caller derives `seed = keccak256(preimage)` and every trial expands that
 * seed. For each trial counter, two Keccak256 blocks give 512 bits reduced
 * modulo the base field, which bounds the reduction bias by about 2^-261, and a
 * third block gives the root-selection bit. On failure the counter is
 * incremented and the blocks are recomputed, so the accepted x-coordinate is
 * uniform over the coordinates satisfying the curve equation and the point is
 * uniform over G1 \ {O}. The cofactor of G1 on BN254 is one, so no cofactor
 * clearing runs.
 */
function mapToG1(seed) {
  for (let trial = 0; trial < MAP_TRIALS; trial++) {
    const t0 = mapBlock(0x00, trial, seed);
    const t1 = mapBlock(0x01, trial, seed);
    const x = mod(t0 * TWO_POW_256 + t1, Q);
    const b = mapBlock(0x02, trial, seed) & 1n;

    const ySq = Fp.add(Fp.mul(Fp.mul(x, x), x), 3n);
    let y;
    try {
      y = Fp.sqrt(ySq);
    } catch (_) {
      y = undefined;
    }
    if (y !== undefined && Fp.eql(Fp.mul(y, y), ySq)) {
      const negY = Fp.neg(y);
      const y0 = y <= negY ? y : negY;
      const point = G1.fromAffine({ x, y: b === 0n ? y0 : Fp.neg(y0) });
      point.assertValidity();
      return point;
    }
  }
  throw new Error("MapToGroup: unhashable message after 256 trials");
}

/** MapToGroup over a byte-string preimage. */
function hashToG1(domainBuf) {
  return mapToG1(keccakBytes(Buffer.from(domainBuf)));
}

/** H(tag, i): index-binding label with mandatory dataset/epoch tag. */
function indexPoint(tagHex, i) {
  const tag = Buffer.from(tagHex.replace(/^0x/, ""), "hex");
  if (tag.length !== 32) throw new Error("tag must be 32 bytes");
  return hashToG1(
    Buffer.concat([Buffer.from("LHS_H2C_"), tag, be8(i)])
  );
}

/** Independent commitment generators G_d (pairwise-unknown dlogs). */
/**
 * Commitment basis {U_d}, derived from public indices alone.
 *
 * Memoised: the basis is a deterministic, party-independent function of the
 * index, so recomputing 743 hash-to-curve operations per scenario is pure
 * waste. Correctness is unaffected -- the security matrix independently
 * recomputes the basis from the public rule and asserts it matches, which is
 * exactly the check that keeps this cache honest.
 */
const generatorCache = new Map();
function commitGenerators(d = D) {
  const cached = generatorCache.get(d);
  if (cached) return cached;
  const gens = [];
  for (let j = 0; j < d; j++) {
    gens.push(hashToG1(Buffer.concat([Buffer.from("OB_LHS_GEN_"), be8(j)])));
  }
  generatorCache.set(d, gens);
  return gens;
}

/** Pedersen-style vector commitment P(v) = sum_d v_d * G_d. */
/**
 * Unblinded Pedersen vector commitment P(v) = sum_d v_d * U_d.
 *
 * Uses multi-scalar multiplication. With the implementation's dimension
 * (D = k + 1 = 743) the naive loop costs 743 independent scalar
 * multiplications per commitment; Pippenger shares the doublings across the
 * whole vector and is roughly an order of magnitude faster. The result is
 * identical by definition -- the security matrix cross-checks the basis, and
 * the map-agreement test cross-checks P against the Solidity and Rust
 * implementations.
 */
function commit(v, gens) {
  const points = [];
  const scalars = [];
  for (let d = 0; d < v.length; d++) {
    if (v[d] === 0n) continue;
    points.push(gens[d]);
    scalars.push(mod(v[d], R));
  }
  if (points.length === 0) return G1.ZERO;
  return G1.msm(points, scalars);
}

// --------------------------------------------------------------------------
// Per-owner MKLHS keys and signatures
// --------------------------------------------------------------------------

function keygen(rng) {
  const sk = randFr(rng);
  const pk = G2.BASE.multiply(sk);
  return { sk, pk };
}

/**
 * Context-bound message point, mirroring the Solidity `hashContextToG1`:
 *   M_i = H2C( "MKLHS_CTX_V1_" || pk_i || tag || i || op || N || P(c_i) )
 * The commitment sits inside the hash preimage, so the signature carries no
 * exploitable linear structure.
 */
function contextPoint(pk, tagHex, index, op, totalItems, commitmentPoint) {
  const k = g2ToContract(pk);
  const c = g1ToContract(commitmentPoint);
  const tag = Buffer.from(tagHex.replace(/^0x/, ""), "hex");
  if (tag.length !== 32) throw new Error("tag must be 32 bytes");
  const buf = Buffer.concat([
    Buffer.from("MKLHS_CTX_V1_"),
    be32(k[0]), be32(k[1]), be32(k[2]), be32(k[3]),
    tag,
    be8(index),
    Buffer.from([Number(op) & 0xff]),
    be8(totalItems),
    be32(c[0]), be32(c[1]),
  ]);
  return hashToG1(buf);
}

/** sigma_i = sk_i * M_i, with M_i the context-bound message point. */
function sign(sk, commitmentPoint, tagHex, index, opts = {}) {
  const { pk, op, totalItems } = opts;
  if (pk === undefined || op === undefined || totalItems === undefined) {
    throw new Error("sign requires { pk, op, totalItems } for context binding");
  }
  return contextPoint(pk, tagHex, index, op, totalItems, commitmentPoint).multiply(sk);
}

/** Contract encoding helpers. */
function g1ToContract(point) {
  const a = point.toAffine();
  return [a.x, a.y];
}

function g2ToContract(point) {
  const a = point.toAffine();
  // Contract stores [x0, x1, y0, y1] (c0 first, matching authorizedPublicKey).
  return [a.x.c0, a.x.c1, a.y.c0, a.y.c1];
}

// --------------------------------------------------------------------------
// Leveled additively-homomorphic stand-in (mirrors the Rust demo encoding)
// --------------------------------------------------------------------------

/**
 * Binary LWE secret key, as tfhe-rs `LweSecretKey` uses.
 */
function heKeygen(rng) {
  return { s: Array.from({ length: K }, () => (randFr(rng) & 1n)) };
}

/** Centered integer representative of x modulo m, in (-m/2, m/2]. */
function centered(x, m) {
  const v = mod(x, m);
  return v > m / 2n ? v - m : v;
}

/**
 * Discrete Gaussian noise, sampled by Box-Muller from the deterministic rng so
 * every scenario stays reproducible.
 */
function sampleNoise(rng) {
  const u1 = Number(randFr(rng) % 1_000_000_007n) / 1_000_000_007 || 1e-12;
  const u2 = Number(randFr(rng) % 1_000_000_007n) / 1_000_000_007;
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return BigInt(Math.round(z * LWE_SIGMA));
}

/**
 * Leveled LWE encryption over the native modulus:
 *     b = <a, s> + Delta*m + e  (mod q),   c = (a, b) in Z_q^D.
 * The returned coordinates are canonical integer representatives in [0, q),
 * which is exactly what the implementation's phi maps injectively into F_r.
 */
function heEnc(key, m, rng) {
  const a = Array.from({ length: K }, () => mod(randFr(rng), LWE_Q));
  let b = mod(DELTA * mod(m, MSG_SPACE) + sampleNoise(rng), LWE_Q);
  for (let j = 0; j < K; j++) b = mod(b + a[j] * key.s[j], LWE_Q);
  return [...a, b];
}

/**
 * Decryption. `v` may be either a native ciphertext in Z_q^D or an UNREDUCED
 * accumulator in F_r^D; in the second case the balanced reduction rho of the
 * implementation is applied first (centered representative, then mod q), which is
 * what lets signed weights work. The phase is then rounded to the nearest
 * multiple of Delta, so the result is exact only inside the leveled budgets.
 */
function heDec(key, v) {
  const c = v.map((x) => mod(centered(x, R), LWE_Q)); // rho
  let phase = c[K];
  for (let j = 0; j < K; j++) phase = mod(phase - c[j] * key.s[j], LWE_Q);
  const centeredPhase = centered(phase, LWE_Q);
  // Round to nearest multiple of Delta.
  const half = DELTA / 2n;
  const rounded =
    centeredPhase >= 0n
      ? (centeredPhase + half) / DELTA
      : -((-centeredPhase + half) / DELTA);
  return mod(rounded, MSG_SPACE);
}

/** Coordinate-wise weighted combination over Fr. */
/**
 * Operator aggregation: the UNREDUCED output vector A = sum_i w_i*phi(c_i).
 * phi is the injective lift Z_q -> F_r (valid because q < r), so the sum stays
 * in F_r and is NOT reduced modulo q here. The consumer applies rho.
 */
function heCombine(vs, weights) {
  const out = new Array(D).fill(0n);
  for (let i = 0; i < vs.length; i++) {
    for (let d = 0; d < D; d++) {
      out[d] = mod(out[d] + weights[i] * vs[i][d], R);
    }
  }
  return out;
}

/** SUM: all +1. SUB: w_0 = +1, w_{i>0} = -1 (as signed BigInt). */
function weightsFor(op, n) {
  return Array.from({ length: n }, (_, i) =>
    op === 0 || i === 0 ? 1n : -1n
  );
}

/** keccak256 over fixed-width 32-byte BE coordinates (Rust coords_digest_hex). */
function coordsDigest(v) {
  return keccak256(new Uint8Array(Buffer.concat(v.map(be32))));
}

// --------------------------------------------------------------------------
// Off-chain BLS aggregate certificate over authenticated record contexts
// --------------------------------------------------------------------------

/** sigma_agg = sum_i w_i * sigma_i  (w_i in {+1, -1}). */
function aggregate(signatures, weights) {
  let acc = G1.ZERO;
  for (let i = 0; i < signatures.length; i++) {
    acc = acc.add(weights[i] === 1n ? signatures[i] : signatures[i].negate());
  }
  return acc;
}

/**
 * Verify the aggregate certificate against all owner keys:
 *   e(sigma_agg, G2) == prod_i e(w_i * MapToGroup(ctx_i), pk_i).
 * ctx_i includes the owner key, tag, index, operation, count and commitment.
 * This authenticates the input contexts, not a homomorphic output signature.
 * Costs an (N+1)-pairing product and is used off-chain only.
 */
function verifyAggregate(sigmaAgg, commitments, pubkeys, tagHex, weights, op = 0) {
  const pairs = [
    { g1: sigmaAgg.negate(), g2: G2.BASE },
  ];
  for (let i = 0; i < commitments.length; i++) {
    let m = contextPoint(pubkeys[i], tagHex, i, op, commitments.length, commitments[i]);
    if (weights[i] !== 1n) m = m.negate();
    pairs.push({ g1: m, g2: pubkeys[i] });
  }
  const gt = bn254.pairingBatch(pairs);
  return Fp12.eql(gt, Fp12.ONE);
}

// --------------------------------------------------------------------------
// End-to-end fixture builder for tests and gas measurements
// --------------------------------------------------------------------------

/**
 * Build a complete multi-key scenario: N owners, each with its own key,
 * encrypting m_i and signing its record.
 */
function buildScenario({ n, op, tagHex, seed = "default" }) {
  const rng = makeRng(seed);
  const gens = commitGenerators();
  const he = heKeygen(rng);
  const weights = weightsFor(op, n);

  const owners = [];
  for (let i = 0; i < n; i++) {
    const { sk, pk } = keygen(rng);
    const m = BigInt(1 + (i % 5)); // ratings 1..5
    const ct = heEnc(he, m, rng);
    const commitment = commit(ct, gens);
    const signature = sign(sk, commitment, tagHex, i, { pk, op, totalItems: n });
    owners.push({ index: i, sk, pk, m, ct, commitment, signature });
  }

  // Honest operator aggregation.
  const outputCt = heCombine(owners.map((o) => o.ct), weights);
  const outputCommitment = commit(outputCt, gens);
  const outputDigest = coordsDigest(outputCt);
  // The true integer result, reduced into the l-bit message space, which is
  // what a correct decryption of rho(A) returns.
  const expectedPlain = mod(
    owners.reduce((acc, o, i) => acc + weights[i] * o.m, 0n),
    MSG_SPACE
  );

  return {
    gens,
    he,
    weights,
    owners,
    outputCt,
    outputCommitment,
    outputDigest,
    expectedPlain,
  };
}

module.exports = {
  Q,
  R,
  K,
  D,
  LWE_Q,
  DELTA,
  MSG_BITS,
  MSG_SPACE,
  LWE_SIGMA,
  centered,
  be32,
  mod,
  makeRng,
  hashToG1,
  mapToG1,
  indexPoint,
  contextPoint,
  commitGenerators,
  commit,
  keygen,
  sign,
  g1ToContract,
  g2ToContract,
  heKeygen,
  heEnc,
  heDec,
  heCombine,
  weightsFor,
  coordsDigest,
  aggregate,
  verifyAggregate,
  buildScenario,
  G1,
  G2,
};
