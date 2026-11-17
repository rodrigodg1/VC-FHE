//! # Output-Bound Multi-Key Linear Verification (field-level mirror)
//!
//! Mirror of the construction of Section "Output-Bound Multi-Key Linear
//! Verification", over `F_r` instead of over
//! real TFHE-LWE ciphertexts. It runs anywhere (no `tfhe-rs` toolchain) and
//! reproduces the deployed algebra byte for byte:
//!
//! ```text
//!   commitment   P(v)   = Σ_d v_d · U_d                     U_d = MapToGroup("OB_LHS_GEN_" ‖ be8(d))
//!   context      ctx_i  = "MKLHS_CTX_V1_" ‖ pk_i ‖ τ ‖ i ‖ op ‖ N ‖ P(c_i)
//!   message      M_i    = MapToGroup(keccak256(ctx_i))
//!   signature    σ_i    = sk_i · M_i                        per-owner key, no curator
//!   admission    e(σ_i, G_2) == e(M_i, pk_i)                one check per record
//!   accumulator  P_agg  += w_i · P(c_i)                     folded on admission
//!   result       P(A')  == P_agg                            O(1), pairing-free
//!   consumer     recompute P(A') and keccak256(ser(A')) and compare on-chain
//! ```
//!
//! The commitment sits *inside* the signed preimage, so the signature carries no
//! exploitable linear structure; the linear structure that the aggregation needs
//! lives in `P` alone. This is the point of the construction and the reason the
//! delivered output is bound: a substituted `A'` changes `P(A')` and fails the
//! result check, while the earlier input-hash relation
//! `H_agg = Σ w_i · Hash(C_i^in)` never references the delivered output at all.
//! The demo runs both relations side by side and asserts the expected verdicts.
//!
//! ## What this mirror is and is not
//!
//! * The authenticator, the hash-to-curve map, the context encoding, the
//!   generators and the acceptance predicate are identical to
//!   `../BN254-Signatures/contract/MKLHS-Verification.sol`,
//!   `../BN254-Signatures/scripts/mklhs-lib.js` and
//!   `../BN254-Signatures/src/bin/output_binding_tfhe.rs`. `emit-onchain-mk`
//!   writes a payload the Hardhat harness accepts, so the agreement is machine
//!   checked rather than asserted in prose.
//! * The FHE layer is the leveled LWE encoding of the implementation, over the
//!   native modulus q = 2^64, with the scaling factor Delta = 2^(64-l) and
//!   Gaussian noise at the parameter set of `tfhe-rs` -- the same construction
//!   `../BN254-Signatures/scripts/mklhs-lib.js` implements and that
//!   `scripts/lwe-interop.test.mjs` proves interoperable with genuine `tfhe-rs`
//!   ciphertexts. It is an independent implementation, not a stand-in: what it
//!   does NOT provide is the rest of the `tfhe-rs` scheme (bootstrapping, key
//!   switching, the full parameter machinery), which the linear path never
//!   uses. The end-to-end run driven by the `tfhe-rs` library itself, with the
//!   message and noise budgets of the correctness lemma, lives in
//!   `../BN254-Signatures/src/bin/output_binding_tfhe.rs`.
//!
//! ## Modes
//!
//! ```text
//!   (default)                       self-validating security demo
//!   bench <out.csv>                 off-chain multi-key metrics
//!   emit-onchain-mk <out.json> [N…] payload for scripts/mklhs_tfhe_onchain.js
//! ```
//!
//! Every mode asserts its expected verdicts and exits non-zero on any failure.
//!
//! ## Scientific basis
//!
//! Homomorphic authenticator that binds the evaluated output: Fiore, Gennaro,
//! Pastro, CCS 2014 (`10.1145/2660267.2660366`). Pairing signature: Boneh, Lynn,
//! Shacham, ASIACRYPT 2001, including the MapToGroup encoding used here.
//! Multi-key linearly homomorphic signatures: Aranha and Pagnin, LATINCRYPT 2019.
//! Vector commitment: Pedersen, CRYPTO '91, binding under the discrete-log
//! relation assumption (Bünz et al., IEEE S&P 2018).

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, CurveGroup, Group};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::{UniformRand, Zero};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha3::{Digest, Keccak256};
use std::io::Write as _;
use std::time::Instant;

// =============================================================================
// PARAMETERS
// =============================================================================

/// LWE mask dimension of the benchmark instance. The deployed parameter set
/// uses k = 742; this crate sweeps the commitment cost over D independently,
/// so its default is small and the dimension is a benchmark axis, not a
/// security parameter.
const K: usize = 4;
/// Ciphertext vector dimension `D = K + 1` (mask `a ∈ F_r^K`, body `b ∈ F_r`).
const D: usize = K + 1;
/// MapToGroup trial bound, `I = 8` in the notation of Boneh-Lynn-Shacham.
/// Matches `MAP_TRIALS` in the contract and the 8-bit counter of the implementation.
const MAP_TRIALS: usize = 256;

/// Authorized operation code. The deployed surface fixes `(op, N)`, and that
/// pair determines the weight vector completely.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Sum,
    Sub,
}

impl Op {
    fn code(self) -> u8 {
        match self {
            Op::Sum => 0,
            Op::Sub => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Op::Sum => "SUM",
            Op::Sub => "SUB",
        }
    }

    /// `w_i = +1` for SUM; `w_0 = +1` and `w_i = -1` for SUB.
    fn weights(self, n: usize) -> Vec<Fr> {
        (0..n)
            .map(|i| {
                if self == Op::Sum || i == 0 {
                    Fr::from(1u64)
                } else {
                    -Fr::from(1u64)
                }
            })
            .collect()
    }
}

// =============================================================================
// MapToGroup (Boneh-Lynn-Shacham) over BN254
//
// Byte-identical to `mapToG1` in MKLHS-Verification.sol, `mapToG1` in
// mklhs-lib.js and `map_to_g1` in output_binding_tfhe.rs: the preimage is hashed
// once to a seed, each trial expands that seed into two Keccak256 blocks that
// are reduced as a single 512-bit integer modulo the base field, and a third
// block supplies the root-selection bit. Re-hashing on failure keeps the trials
// independent, so the accepted coordinate is uniform over the coordinates that
// satisfy the curve equation. The cofactor of G1 on BN254 is one, so no cofactor
// clearing is applied.
// =============================================================================

fn map_block(domain: u8, trial: u8, seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update([domain]);
    hasher.update([trial]);
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn map_to_g1(seed: &[u8; 32]) -> G1Projective {
    for trial in 0..MAP_TRIALS {
        let t = trial as u8;
        // x = (t0 · 2^256 + t1) mod p, an exact wide reduction of 512 bits.
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&map_block(0x00, t, seed));
        wide[32..].copy_from_slice(&map_block(0x01, t, seed));
        let x = Fq::from_be_bytes_mod_order(&wide);
        let b = map_block(0x02, t, seed)[31] & 1;

        let y_sq = x * x * x + Fq::from(3u64); // BN254: y^2 = x^3 + 3
        if let Some(y) = y_sq.sqrt() {
            let neg_y = -y;
            let y_be = y.into_bigint().to_bytes_be();
            let neg_be = neg_y.into_bigint().to_bytes_be();
            // y0 is the root with the smaller canonical integer representative.
            let (y0, y1) = if y_be <= neg_be { (y, neg_y) } else { (neg_y, y) };
            let affine = G1Affine::new_unchecked(x, if b == 0 { y0 } else { y1 });
            assert!(affine.is_on_curve(), "MapToGroup: point not on curve");
            return affine.into();
        }
    }
    panic!("MapToGroup: unhashable preimage after {MAP_TRIALS} trials");
}

/// MapToGroup over a byte-string preimage.
fn hash_to_g1(preimage: &[u8]) -> G1Projective {
    let mut hasher = Keccak256::new();
    hasher.update(preimage);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    map_to_g1(&seed)
}

/// Fixed-width big-endian encoding of a base-field coordinate.
fn be32(v: Fq) -> [u8; 32] {
    let bytes = v.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Dataset/epoch tag. The contract requires it to be non-zero and binds it into
/// every context, so records from one dataset or epoch do not verify against
/// another.
fn dataset_tag() -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"vc-fhe/output-binding/v1");
    let digest = hasher.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&digest);
    tag
}

/// Independent commitment generators `U_d`, derived by a public procedure with
/// no chosen parameter, so no party holds a trapdoor.
fn commit_generators(d: usize) -> Vec<G1Projective> {
    (0..d)
        .map(|j| {
            let mut preimage = b"OB_LHS_GEN_".to_vec();
            preimage.extend_from_slice(&(j as u64).to_be_bytes());
            hash_to_g1(&preimage)
        })
        .collect()
}

/// Unblinded Pedersen vector commitment `P(v) = Σ_d v_d · U_d`.
/// Computationally binding under the discrete-log relation assumption; it is not
/// hiding, and record confidentiality rests on the FHE layer.
fn commit(v: &[Fr], gens: &[G1Projective]) -> G1Projective {
    assert_eq!(v.len(), gens.len(), "commitment dimension mismatch");
    // Multi-scalar multiplication, not a loop of independent scalar
    // multiplications. At the deployed dimension (D = k + 1 = 743) the naive
    // loop costs D separate scalar multiplications, which dominated both the
    // owner-side record cost and the consumer's mandatory output check and made
    // the measured figures roughly an order of magnitude worse than the
    // construction actually requires. Pippenger shares the doublings across the
    // whole vector; the result is identical by definition.
    let bases: Vec<G1Affine> = gens.iter().map(|g| g.into_affine()).collect();
    let scalars: Vec<<Fr as PrimeField>::BigInt> = v.iter().map(|c| c.into_bigint()).collect();
    G1Projective::msm_bigint(&bases, &scalars)
}

/// Context-bound message point
/// `M_i = MapToGroup("MKLHS_CTX_V1_" ‖ pk_i ‖ τ ‖ i ‖ op ‖ N ‖ P(c_i))`.
///
/// The encoding is fixed width and therefore injective, so distinct commitments
/// give distinct preimages and hence independent random-oracle points. The owner
/// key, tag, index, authorized operation and input count are all inside the
/// preimage, so a signature cannot be moved across any of them.
fn context_point(
    pk: &G2Projective,
    tag: &[u8; 32],
    index: u64,
    op: u8,
    total_items: u64,
    commitment: &G1Projective,
) -> G1Projective {
    let k = pk.into_affine();
    let c = commitment.into_affine();
    let mut preimage = b"MKLHS_CTX_V1_".to_vec();
    preimage.extend_from_slice(&be32(k.x.c0));
    preimage.extend_from_slice(&be32(k.x.c1));
    preimage.extend_from_slice(&be32(k.y.c0));
    preimage.extend_from_slice(&be32(k.y.c1));
    preimage.extend_from_slice(tag);
    preimage.extend_from_slice(&index.to_be_bytes());
    preimage.push(op);
    preimage.extend_from_slice(&total_items.to_be_bytes());
    preimage.extend_from_slice(&be32(c.x));
    preimage.extend_from_slice(&be32(c.y));
    hash_to_g1(&preimage)
}

// =============================================================================
// PER-OWNER KEYS AND THE DEPLOYED ACCEPTANCE PREDICATE
// =============================================================================

/// One data owner. There is no curator and no shared signing key.
#[derive(Clone)]
struct Owner {
    sk: Fr,
    pk: G2Projective,
}

impl Owner {
    fn keygen(rng: &mut StdRng) -> Self {
        let sk = Fr::rand(rng);
        Owner {
            sk,
            pk: G2Projective::generator() * sk,
        }
    }

    /// `σ_i = sk_i · M_i`.
    fn sign(
        &self,
        tag: &[u8; 32],
        index: u64,
        op: u8,
        total_items: u64,
        commitment: &G1Projective,
    ) -> G1Projective {
        context_point(&self.pk, tag, index, op, total_items, commitment) * self.sk
    }
}

/// Admission check `e(σ_i, G_2) == e(M_i, pk_i)`, run once per record.
/// The verifier derives `M_i` itself from the registered key and the submitted
/// commitment and never accepts `M_i` as an input.
fn admit(
    pk: &G2Projective,
    tag: &[u8; 32],
    index: u64,
    op: u8,
    total_items: u64,
    commitment: &G1Projective,
    sigma: &G1Projective,
) -> bool {
    if commitment.is_zero() || sigma.is_zero() {
        return false; // the contract rejects the point at infinity
    }
    let m = context_point(pk, tag, index, op, total_items, commitment);
    Bn254::pairing(sigma.into_affine(), G2Projective::generator().into_affine())
        == Bn254::pairing(m.into_affine(), pk.into_affine())
}

/// On-chain accumulator: `P_agg = Σ_i w_i · P(c_i)` over exactly the admitted
/// records. One entry per index, consumed once.
struct Accumulator {
    total_items: usize,
    admitted: Vec<bool>,
    p_agg: G1Projective,
}

impl Accumulator {
    fn new(total_items: usize) -> Self {
        Accumulator {
            total_items,
            admitted: vec![false; total_items],
            p_agg: G1Projective::zero(),
        }
    }

    /// Returns false on a rejected or replayed admission, leaving state untouched.
    #[allow(clippy::too_many_arguments)]
    fn admit_record(
        &mut self,
        pk: &G2Projective,
        tag: &[u8; 32],
        index: u64,
        op: Op,
        commitment: &G1Projective,
        sigma: &G1Projective,
        weight: Fr,
    ) -> bool {
        let i = index as usize;
        if i >= self.total_items || self.admitted[i] {
            return false;
        }
        if !admit(
            pk,
            tag,
            index,
            op.code(),
            self.total_items as u64,
            commitment,
            sigma,
        ) {
            return false;
        }
        self.admitted[i] = true;
        self.p_agg += *commitment * weight;
        true
    }

    fn complete(&self) -> bool {
        self.admitted.iter().all(|a| *a)
    }

    /// `submitResultBound`: requires every record admitted, then compares the
    /// submitted commitment with the accumulator. Constant in `D` and in `N`.
    fn accepts_result(&self, submitted: &G1Projective) -> bool {
        self.complete() && !submitted.is_zero() && *submitted == self.p_agg
    }
}

/// What the contract records when a result is accepted.
struct OnChainRecord {
    commitment: G1Projective,
    output_digest: String,
}

/// Consumer check. The contract verifies a commitment, not every ciphertext
/// coordinate, so this recomputation is part of the protocol and not an optional
/// application convention.
fn consumer_accepts(
    delivered: &[Fr],
    gens: &[G1Projective],
    record: &OnChainRecord,
) -> bool {
    delivered.len() == gens.len()
        && commit(delivered, gens) == record.commitment
        && coords_digest_hex(delivered) == record.output_digest
}

/// Off-chain aggregate certificate `σ_agg = Σ_i w_i · σ_i`, verified against all
/// owner keys with one `(N+1)`-pairing product. The on-chain path never pays
/// this product: each admission is verified once and folded into the accumulator.
/// The deployed surface uses `w_i ∈ {+1, -1}`.
fn verify_aggregate_certificate(
    sigma_agg: &G1Projective,
    commitments: &[G1Projective],
    pubkeys: &[G2Projective],
    tag: &[u8; 32],
    op: Op,
    weights: &[Fr],
) -> bool {
    let n = commitments.len();
    if pubkeys.len() != n || weights.len() != n {
        return false;
    }
    let mut g1s: Vec<G1Affine> = Vec::with_capacity(n + 1);
    let mut g2s: Vec<G2Affine> = Vec::with_capacity(n + 1);
    g1s.push((-*sigma_agg).into_affine());
    g2s.push(G2Projective::generator().into_affine());
    for i in 0..n {
        let mut m = context_point(
            &pubkeys[i],
            tag,
            i as u64,
            op.code(),
            n as u64,
            &commitments[i],
        );
        if weights[i] != Fr::from(1u64) {
            m = -m;
        }
        g1s.push(m.into_affine());
        g2s.push(pubkeys[i].into_affine());
    }
    Bn254::multi_pairing(g1s, g2s).is_zero()
}

/// Canonical artifact serialization: each coordinate as one fixed-width 32-byte
/// big-endian value. The digest is an independent content identifier; the
/// commitment already binds the delivered vector.
fn coords_digest_hex(coords: &[Fr]) -> String {
    let mut hasher = Keccak256::new();
    for coordinate in coords {
        let bytes = coordinate.into_bigint().to_bytes_be();
        let mut canonical = [0u8; 32];
        canonical[32 - bytes.len()..].copy_from_slice(&bytes);
        hasher.update(canonical);
    }
    format!("0x{}", hex::encode(hasher.finalize()))
}

// =============================================================================
// LEGACY INPUT-HASH RELATION (kept only for the contrast of Section 4.3)
//
// Signing only ciphertext hashes h_i = Hash(C_i^in) authenticates the selected
// inputs and weights but leaves the delivered output outside the verified
// statement. The relation below therefore never reads the delivered vector,
// which is exactly the flaw the output-binding construction removes.
// =============================================================================

fn hash_ciphertext(v: &[Fr]) -> Fr {
    let mut hasher = Keccak256::new();
    for coordinate in v {
        hasher.update(coordinate.into_bigint().to_bytes_be());
    }
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

/// Legacy context: the scalar hash of the input ciphertext replaces `P(c_i)`.
fn legacy_context_point(
    pk: &G2Projective,
    tag: &[u8; 32],
    index: u64,
    op: u8,
    total_items: u64,
    h: Fr,
) -> G1Projective {
    context_point(
        pk,
        tag,
        index,
        op,
        total_items,
        &(G1Projective::generator() * h),
    )
}

/// Legacy acceptance: every record admitted under the hash-bound context and the
/// claimed aggregate hash equal to `Σ w_i h_i`. The delivered output vector is
/// not an argument of this function, which is the point.
fn legacy_accepts(
    owners: &[Owner],
    tag: &[u8; 32],
    op: Op,
    hashes: &[Fr],
    signatures: &[G1Projective],
    weights: &[Fr],
    claimed_h_agg: Fr,
) -> bool {
    let n = hashes.len();
    if owners.len() != n || signatures.len() != n {
        return false;
    }
    for i in 0..n {
        let m = legacy_context_point(
            &owners[i].pk,
            tag,
            i as u64,
            op.code(),
            n as u64,
            hashes[i],
        );
        let ok = Bn254::pairing(
            signatures[i].into_affine(),
            G2Projective::generator().into_affine(),
        ) == Bn254::pairing(m.into_affine(), owners[i].pk.into_affine());
        if !ok {
            return false;
        }
    }
    let h_agg: Fr = hashes.iter().zip(weights.iter()).map(|(h, w)| *h * *w).sum();
    h_agg == claimed_h_agg
}

// =============================================================================
// LEVELED LWE (native modulus q = 2^64, Delta-scaled, Gaussian noise)
//
// Enc(m) = (a ∈ Z_q^K, b = <a,s> + Delta*m + e), coordinates lifted into F_r by
// the injective map phi. Coordinate-wise linear, which is the property the
// linear path uses; decryption applies the balanced reduction rho and rounds
// the phase to the nearest multiple of Delta.
// =============================================================================


fn he_keygen(rng: &mut StdRng, k: usize) -> Vec<Fr> {
    (0..k).map(|_| Fr::rand(rng)).collect()
}


// ---------------------------------------------------------------- leveled LWE
// Parameters mirrored from `BN254-Signatures/src/bin/output_binding_tfhe.rs`
// and `scripts/mklhs-lib.js`, so all three model the same cryptosystem.
/// Message bit-width l.
const MSG_BITS: u32 = 10;
/// Scaling factor Delta = 2^(64 - l).
const DELTA: u64 = 1u64 << (64 - MSG_BITS);
/// Gaussian sigma of the classic tfhe-rs parameter set, scaled to q = 2^64.
const LWE_SIGMA: f64 = 0.000_007_069_849_454_709_433f64 * 18_446_744_073_709_551_616f64;

/// Low 64 bits of a field element's canonical representative.
fn fr_to_u64_low(x: &Fr) -> u64 {
    x.into_bigint().0[0]
}

/// Balanced reduction rho: centered representative of `x` in F_r, then mod q.
fn fr_to_zq_centered_local(x: &Fr) -> u64 {
    let bi = x.into_bigint();
    let low = bi.0[0];
    if bi > Fr::MODULUS_MINUS_ONE_DIV_TWO {
        low.wrapping_sub(Fr::MODULUS.0[0])
    } else {
        low
    }
}

/// Discrete Gaussian noise by Box-Muller, drawn from the seeded rng so every
/// benchmark and emission stays reproducible.
fn sample_noise(rng: &mut StdRng) -> u64 {
    let u1: f64 = (rng.gen::<u64>() as f64 / u64::MAX as f64).max(1e-12);
    let u2: f64 = rng.gen::<u64>() as f64 / u64::MAX as f64;
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    let e = (z * LWE_SIGMA).round();
    if e < 0.0 { (-e as u64).wrapping_neg() } else { e as u64 }
}

/// Leveled LWE encryption over the native modulus q = 2^64, matching the
/// implementation and the `tfhe-rs` artifact:
///
///     b = <a, s> + Delta*m + e   (mod q),    c = (a, b) in Z_q^D
///
/// The coordinates are returned already lifted into F_r by phi (injective
/// because q < r), which is the representation the commitment and the operator
/// aggregation consume.
///
/// This replaces a stand-in that computed `b = <a,s> + m` over F_r with no
/// noise and no Delta. That was a linear encoding, not an encryption: it left
/// the phi and rho steps of the implementation unexercised and made any
/// "cost of verifiability over FHE" ratio computed from these benchmarks
/// meaningless, because the denominator was not an encryption cost.
/// `BN254-Signatures/scripts/mklhs-lib.js` carries the same construction, and
/// `scripts/lwe-interop.test.mjs` proves that implementation interoperable with
/// genuine `tfhe-rs` ciphertexts.
fn he_enc(s: &[Fr], m: Fr, rng: &mut StdRng) -> Vec<Fr> {
    let a_q: Vec<u64> = (0..s.len()).map(|_| rng.gen::<u64>()).collect();
    let mut b = DELTA.wrapping_mul(fr_to_u64_low(&m) % (1u64 << MSG_BITS));
    b = b.wrapping_add(sample_noise(rng));
    for (ai, si) in a_q.iter().zip(s.iter()) {
        b = b.wrapping_add(ai.wrapping_mul(fr_to_u64_low(si)));
    }
    let mut v: Vec<Fr> = a_q.iter().map(|x| Fr::from(*x)).collect();
    v.push(Fr::from(b));
    v
}

/// Decryption: apply the balanced reduction rho to each coordinate, recover the
/// phase, and round to the nearest multiple of Delta.
fn he_dec(s: &[Fr], v: &[Fr]) -> Fr {
    let c: Vec<u64> = v.iter().map(fr_to_zq_centered_local).collect();
    let (a, b) = c.split_at(s.len());
    let mut phase = b[0];
    for (ai, si) in a.iter().zip(s.iter()) {
        phase = phase.wrapping_sub(ai.wrapping_mul(fr_to_u64_low(si)));
    }
    let centered = phase as i64;
    let half = (DELTA / 2) as i64;
    let rounded = if centered >= 0 {
        ((centered + half) as u64) / DELTA
    } else {
        (((-centered + half) as u64) / DELTA).wrapping_neg()
    };
    Fr::from(rounded % (1u64 << MSG_BITS))
}

/// `Σ_i w_i · c_i`, coordinate-wise.
fn he_combine(vs: &[Vec<Fr>], w: &[Fr], d: usize) -> Vec<Fr> {
    let mut out = vec![Fr::zero(); d];
    for (v, wi) in vs.iter().zip(w.iter()) {
        for j in 0..d {
            out[j] += v[j] * *wi;
        }
    }
    out
}

// =============================================================================
// HELPERS
// =============================================================================

/// Small-plaintext readout. Demo results are tiny, so the low 64 bits suffice.
fn fr_to_i128(x: &Fr) -> i128 {
    let neg = -*x;
    let to_u128 = |v: &Fr| -> Option<u128> {
        let raw = v.into_bigint().to_bytes_be();
        let mut bytes = [0u8; 32];
        bytes[32 - raw.len()..].copy_from_slice(&raw);
        if bytes[..16].iter().any(|b| *b != 0) {
            return None;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes[16..32]);
        Some(u128::from_be_bytes(arr))
    };
    match (to_u128(x), to_u128(&neg)) {
        (Some(p), _) if p <= i128::MAX as u128 => p as i128,
        (_, Some(q)) if q <= i128::MAX as u128 => -(q as i128),
        _ => i128::MIN,
    }
}

fn verdict(accept: bool) -> &'static str {
    if accept {
        "ACCEPT"
    } else {
        "REJECT"
    }
}

fn ms(dur: std::time::Duration) -> f64 {
    dur.as_secs_f64() * 1000.0
}

fn parse_usize_list(s: &str) -> Vec<usize> {
    s.split(|c| c == ',' || c == ' ')
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse::<usize>().ok())
        .collect()
}

fn g1_serialized_len(p: &G1Projective, compress: bool) -> usize {
    p.into_affine().serialized_size(if compress {
        Compress::Yes
    } else {
        Compress::No
    })
}

fn g2_serialized_len(p: &G2Projective, compress: bool) -> usize {
    p.into_affine().serialized_size(if compress {
        Compress::Yes
    } else {
        Compress::No
    })
}

fn g1_dec(p: &G1Projective) -> (String, String) {
    let a = p.into_affine();
    (a.x.to_string(), a.y.to_string())
}

/// G2 key in the contract's `[x0, x1, y0, y1]` limb order.
fn g2_dec(p: &G2Projective) -> [String; 4] {
    let a = p.into_affine();
    [
        a.x.c0.to_string(),
        a.x.c1.to_string(),
        a.y.c0.to_string(),
        a.y.c1.to_string(),
    ]
}

// =============================================================================
// A COMPLETE DEPLOYMENT, HONEST OR ADVERSARIAL
// =============================================================================

/// Everything one deployment produces honestly, before any adversary acts.
struct Deployment {
    tag: [u8; 32],
    op: Op,
    n: usize,
    d: usize,
    gens: Vec<G1Projective>,
    he_secret: Vec<Fr>,
    owners: Vec<Owner>,
    ciphertexts: Vec<Vec<Fr>>,
    commitments: Vec<G1Projective>,
    signatures: Vec<G1Projective>,
    weights: Vec<Fr>,
    output: Vec<Fr>,
    expected_plaintext: i128,
}

impl Deployment {
    fn build(rng: &mut StdRng, plaintexts: &[i128], op: Op, d: usize) -> Self {
        let n = plaintexts.len();
        let k = d - 1;
        let tag = dataset_tag();
        let gens = commit_generators(d);
        let he_secret = he_keygen(rng, k);
        let owners: Vec<Owner> = (0..n).map(|_| Owner::keygen(rng)).collect();
        let weights = op.weights(n);

        let ciphertexts: Vec<Vec<Fr>> = plaintexts
            .iter()
            .map(|m| he_enc(&he_secret, Fr::from(*m as u64), rng))
            .collect();
        let commitments: Vec<G1Projective> =
            ciphertexts.iter().map(|c| commit(c, &gens)).collect();
        let signatures: Vec<G1Projective> = (0..n)
            .map(|i| owners[i].sign(&tag, i as u64, op.code(), n as u64, &commitments[i]))
            .collect();
        let output = he_combine(&ciphertexts, &weights, d);
        let expected_plaintext = plaintexts
            .iter()
            .zip(weights.iter())
            .map(|(m, w)| if *w == Fr::from(1u64) { *m } else { -*m })
            .sum();

        Deployment {
            tag,
            op,
            n,
            d,
            gens,
            he_secret,
            owners,
            ciphertexts,
            commitments,
            signatures,
            weights,
            output,
            expected_plaintext,
        }
    }

    fn pubkeys(&self) -> Vec<G2Projective> {
        self.owners.iter().map(|o| o.pk).collect()
    }

    /// Run the deployed acceptance predicate over a set of submitted records and
    /// a delivered output vector. Returns (admissions accepted, on-chain result
    /// accepted, consumer accepted).
    fn compose(
        &self,
        records: &[(u64, G1Projective, G1Projective)],
        submitted_commitment: &G1Projective,
        submitted_digest: &str,
        delivered: &[Fr],
    ) -> (bool, bool, bool) {
        let mut acc = Accumulator::new(self.n);
        let mut all_admitted = true;
        for (index, commitment, sigma) in records {
            let weight = self
                .weights
                .get(*index as usize)
                .copied()
                .unwrap_or_else(|| Fr::from(1u64));
            if !acc.admit_record(
                &self.owners[(*index as usize).min(self.n - 1)].pk,
                &self.tag,
                *index,
                self.op,
                commitment,
                sigma,
                weight,
            ) {
                all_admitted = false;
            }
        }
        let on_chain = acc.accepts_result(submitted_commitment);
        let record = OnChainRecord {
            commitment: *submitted_commitment,
            output_digest: submitted_digest.to_string(),
        };
        let consumer = on_chain && consumer_accepts(delivered, &self.gens, &record);
        (all_admitted, on_chain, consumer)
    }

    /// The honest submission: every record as signed, the true aggregate output.
    fn honest_records(&self) -> Vec<(u64, G1Projective, G1Projective)> {
        (0..self.n)
            .map(|i| (i as u64, self.commitments[i], self.signatures[i]))
            .collect()
    }
}

// =============================================================================
// MAIN
// =============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        None | Some("demo") => run_demo(),
        Some("bench") => run_bench(&args),
        Some("emit-onchain-mk") => run_emit_mk(&args),
        // Fail loudly. The removed `emit-onchain` mode used to fall through to
        // the demo silently, so a documented command appeared to succeed while
        // writing nothing.
        Some(other) => {
            eprintln!("unknown subcommand `{other}`");
            eprintln!(
                "usage: output-binding-lhs [demo | bench <out.csv> | emit-onchain-mk <out.json> [N...]]"
            );
            std::process::exit(2);
        }
    }
}

// =============================================================================
// DEMO: the deployed acceptance predicate against the threat set of Section 4.3
// =============================================================================

fn run_demo() {
    let mut rng = StdRng::seed_from_u64(0x0B1_0DED_0);

    println!("========================================================================");
    println!(" Output-Bound Multi-Key Linear Verification  —  field-level mirror");
    println!(
        " Curve: BN254 | ciphertext dim D = {D} | MapToGroup trials <= {MAP_TRIALS}"
    );
    println!(" Per-owner keys, no curator. Commitment inside the signed context.");
    println!("========================================================================\n");

    let mut all_ok = true;
    for (op, plaintexts) in [
        (Op::Sum, vec![3i128, 1, 2, 5, 4]),
        (Op::Sub, vec![20i128, 3, 5, 2]),
    ] {
        let dep = Deployment::build(&mut rng, &plaintexts, op, D);
        println!(
            "{} over {:?}  =>  expected {}",
            op.label(),
            plaintexts,
            dep.expected_plaintext
        );
        all_ok &= run_scenarios(&mut rng, &dep);
        println!();
    }

    if all_ok {
        println!("RESULT: all security assertions passed.");
    } else {
        eprintln!("RESULT: security assertions FAILED.");
        std::process::exit(1);
    }
}

/// Expected outcome of one scenario under the composed verifier.
struct Expect {
    admissions: bool,
    on_chain: bool,
    consumer: bool,
}

fn run_scenarios(rng: &mut StdRng, dep: &Deployment) -> bool {
    let n = dep.n;
    let d = dep.d;
    let honest_digest = coords_digest_hex(&dep.output);
    let honest_commitment = commit(&dep.output, &dep.gens);

    // Legacy input-hash material, for the contrast column only.
    let hashes: Vec<Fr> = dep.ciphertexts.iter().map(|c| hash_ciphertext(c)).collect();
    let legacy_sigs: Vec<G1Projective> = (0..n)
        .map(|i| {
            legacy_context_point(
                &dep.owners[i].pk,
                &dep.tag,
                i as u64,
                dep.op.code(),
                n as u64,
                hashes[i],
            ) * dep.owners[i].sk
        })
        .collect();
    let legacy_h_agg: Fr = hashes
        .iter()
        .zip(dep.weights.iter())
        .map(|(h, w)| *h * *w)
        .sum();

    let mut scenarios: Vec<(
        &str,
        Vec<(u64, G1Projective, G1Projective)>,
        G1Projective,
        String,
        Vec<Fr>,
        Expect,
    )> = Vec::new();

    // 1. Honest run.
    scenarios.push((
        "honest",
        dep.honest_records(),
        honest_commitment,
        honest_digest.clone(),
        dep.output.clone(),
        Expect {
            admissions: true,
            on_chain: true,
            consumer: true,
        },
    ));

    // 2. Output substitution: deliver c_0, keep the accepted accumulator.
    //    The on-chain check still passes because the operator submits P_agg, but
    //    the consumer's recomputation from the delivered vector fails.
    scenarios.push((
        "output_substitution",
        dep.honest_records(),
        honest_commitment,
        honest_digest.clone(),
        dep.ciphertexts[0].clone(),
        Expect {
            admissions: true,
            on_chain: true,
            consumer: false,
        },
    ));

    // 3. Substituted output commitment: the operator submits P(c_0) instead of
    //    P_agg. Rejected on-chain by the accumulator equality.
    scenarios.push((
        "substituted_output_commitment",
        dep.honest_records(),
        dep.commitments[0],
        coords_digest_hex(&dep.ciphertexts[0]),
        dep.ciphertexts[0].clone(),
        Expect {
            admissions: true,
            on_chain: false,
            consumer: false,
        },
    ));

    // 4. Forged signature: a different key signs owner 0's context.
    {
        let rogue = Owner::keygen(rng);
        let mut records = dep.honest_records();
        records[0].2 = context_point(
            &dep.owners[0].pk,
            &dep.tag,
            0,
            dep.op.code(),
            n as u64,
            &dep.commitments[0],
        ) * rogue.sk;
        scenarios.push((
            "forged_signature",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 5. Substituted commitment: a valid signature over a DIFFERENT commitment.
    {
        let mut records = dep.honest_records();
        records[0].1 = dep.commitments[n - 1];
        scenarios.push((
            "substituted_commitment",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 6. Cross-index replay: owner 0's signature presented at index 1.
    {
        let mut records = dep.honest_records();
        records[1] = (1, dep.commitments[0], dep.signatures[0]);
        scenarios.push((
            "cross_index_replay",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 7. Cross-tag replay: a signature produced under another dataset tag.
    {
        let mut other_tag = dep.tag;
        other_tag[31] ^= 0x01;
        let mut records = dep.honest_records();
        records[0].2 = dep.owners[0].sign(
            &other_tag,
            0,
            dep.op.code(),
            n as u64,
            &dep.commitments[0],
        );
        scenarios.push((
            "cross_tag_replay",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 8. Cross-operation replay: a signature bound to the other authorized op.
    {
        let other_op = if dep.op == Op::Sum { Op::Sub } else { Op::Sum };
        let mut records = dep.honest_records();
        records[0].2 = dep.owners[0].sign(
            &dep.tag,
            0,
            other_op.code(),
            n as u64,
            &dep.commitments[0],
        );
        scenarios.push((
            "cross_operation_replay",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 9. Cross-size replay: a signature bound to a different input count N.
    {
        let mut records = dep.honest_records();
        records[0].2 = dep.owners[0].sign(
            &dep.tag,
            0,
            dep.op.code(),
            (n + 1) as u64,
            &dep.commitments[0],
        );
        scenarios.push((
            "cross_size_replay",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 10. Mauled signature: sigma + G1.
    {
        let mut records = dep.honest_records();
        records[0].2 = dep.signatures[0] + G1Projective::generator();
        scenarios.push((
            "mauled_signature",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 11. Scalar-derived admission: (k*P_0, k*sigma_0). Valid for the additive
    //     message point of the earlier scheme, rejected here because the
    //     commitment is inside the hash preimage.
    {
        let k = Fr::from(7u64);
        let mut records = dep.honest_records();
        records[0] = (0, dep.commitments[0] * k, dep.signatures[0] * k);
        scenarios.push((
            "scalar_derived_admission",
            records,
            honest_commitment,
            honest_digest.clone(),
            dep.output.clone(),
            Expect {
                admissions: false,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 12. Input omission: drop the last record from both the admissions and the
    //     output. Self-consistent, and still rejected because the result check
    //     requires every index admitted.
    {
        let records: Vec<_> = dep.honest_records()[..n - 1].to_vec();
        let subset_out = he_combine(
            &dep.ciphertexts[..n - 1],
            &dep.weights[..n - 1],
            d,
        );
        let subset_commitment = commit(&subset_out, &dep.gens);
        scenarios.push((
            "input_omission",
            records,
            subset_commitment,
            coords_digest_hex(&subset_out),
            subset_out,
            Expect {
                admissions: true,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 13. Wrong coefficient: aggregate with [2,1,...] instead of the authorized
    //     weights. The contract folds the authorized weight, so the submitted
    //     commitment no longer equals the accumulator.
    {
        let mut bad_w = dep.weights.clone();
        bad_w[0] = Fr::from(2u64);
        let bad_out = he_combine(&dep.ciphertexts, &bad_w, d);
        scenarios.push((
            "wrong_coefficient",
            dep.honest_records(),
            commit(&bad_out, &dep.gens),
            coords_digest_hex(&bad_out),
            bad_out,
            Expect {
                admissions: true,
                on_chain: false,
                consumer: false,
            },
        ));
    }

    // 14. Bogus digest: the honest commitment recorded with a wrong digest. The
    //     on-chain check passes; only the consumer catches it. This is the
    //     delivery-griefing case documented in Section 4.3: an availability
    //     failure, never an integrity failure.
    scenarios.push((
        "bogus_digest",
        dep.honest_records(),
        honest_commitment,
        coords_digest_hex(&dep.ciphertexts[0]),
        dep.output.clone(),
        Expect {
            admissions: true,
            on_chain: true,
            consumer: false,
        },
    ));

    println!(
        "  {:<32} {:>10} {:>10} {:>10} {:>12}",
        "scenario", "admit", "on-chain", "consumer", "decrypt"
    );
    println!("  {}", "-".repeat(80));

    let mut ok = true;
    for (name, records, submitted, digest, delivered, expect) in &scenarios {
        let (admissions, on_chain, consumer) =
            dep.compose(records, submitted, digest, delivered);
        let decrypted = fr_to_i128(&he_dec(&dep.he_secret, delivered));

        println!(
            "  {:<32} {:>10} {:>10} {:>10} {:>12}",
            name,
            verdict(admissions),
            verdict(on_chain),
            verdict(consumer),
            decrypted
        );

        if admissions != expect.admissions
            || on_chain != expect.on_chain
            || consumer != expect.consumer
        {
            eprintln!(
                "    !! FAIL[{name}]: got ({}, {}, {}), expected ({}, {}, {})",
                verdict(admissions),
                verdict(on_chain),
                verdict(consumer),
                verdict(expect.admissions),
                verdict(expect.on_chain),
                verdict(expect.consumer)
            );
            ok = false;
        }
        if *name == "honest" && decrypted != dep.expected_plaintext {
            eprintln!(
                "    !! FAIL[honest]: decrypt {decrypted} != expected {}",
                dep.expected_plaintext
            );
            ok = false;
        }
        if *name == "output_substitution" {
            // The legacy input-hash relation is evaluated on exactly the same
            // submission. It takes no delivered vector as an argument, so it
            // cannot distinguish this substitution from the honest delivery.
            let legacy = legacy_accepts(
                &dep.owners,
                &dep.tag,
                dep.op,
                &hashes,
                &legacy_sigs,
                &dep.weights,
                legacy_h_agg,
            );
            if !(on_chain && !consumer && legacy) {
                eprintln!("    !! FAIL: output substitution must pass the legacy relation, pass on-chain, and be caught by the consumer");
                ok = false;
            } else {
                println!(
                    "    -> legacy input-hash relation on this same delivery: ACCEPT (the delivered"
                );
                println!(
                    "       vector is not an argument of that statement); composed verifier: REJECT"
                );
                println!(
                    "       at the consumer recomputation, since P(delivered) != P_agg."
                );
            }
        }
    }

    // Off-chain aggregate certificate (Aranha-Pagnin style), honest and mutated.
    let sigma_agg = dep
        .signatures
        .iter()
        .zip(dep.weights.iter())
        .fold(G1Projective::zero(), |acc, (s, w)| acc + *s * *w);
    let pubkeys = dep.pubkeys();
    let cert_ok = verify_aggregate_certificate(
        &sigma_agg,
        &dep.commitments,
        &pubkeys,
        &dep.tag,
        dep.op,
        &dep.weights,
    );
    let mut mutated = dep.commitments.clone();
    mutated[0] += G1Projective::generator();
    let cert_bad = verify_aggregate_certificate(
        &sigma_agg,
        &mutated,
        &pubkeys,
        &dep.tag,
        dep.op,
        &dep.weights,
    );
    println!(
        "  {:<32} {:>10} {:>10}",
        "aggregate certificate",
        verdict(cert_ok),
        verdict(!cert_bad)
    );
    if !cert_ok || cert_bad {
        eprintln!("    !! FAIL: aggregate certificate must accept the honest set and reject mutations");
        ok = false;
    }

    ok
}

// =============================================================================
// BENCH: off-chain metrics of the multi-key path
// =============================================================================

fn run_bench(args: &[String]) {
    let out_path = args.get(2).cloned().unwrap_or_else(|| {
        std::env::var("OB_METRICS_CSV").unwrap_or_else(|_| "metrics_output_binding.csv".to_string())
    });
    let sizes = std::env::var("OB_SIZES")
        .ok()
        .map(|s| parse_usize_list(&s))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![10, 50, 100, 200]);
    let dims = std::env::var("OB_DIMS")
        .ok()
        .map(|s| parse_usize_list(&s))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![5, 64, 256, 1024]);
    let repeats: usize = std::env::var("OB_REPEATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let mut rng = StdRng::seed_from_u64(0xBE_11C_0DE_u64);
    let tag = dataset_tag();
    let op = Op::Sum;

    let mut file = std::fs::File::create(&out_path).expect("cannot create metrics CSV");
    writeln!(
        file,
        "scheme,cipher_dim_D,dataset_size,repeat,owner_keygen_ms,encrypt_ms,commit_inputs_ms,\
sign_ms,sign_per_input_us,legacy_sign_ms,admit_verify_ms,admit_verify_per_record_ms,\
accumulate_ms,commit_output_ms,result_check_ms,agg_certificate_ms,\
single_sig_bytes,agg_sig_bytes,output_commitment_bytes,pubkey_bytes"
    )
    .unwrap();

    println!("Multi-key output-binding off-chain metrics -> {out_path}");
    println!("sizes={sizes:?} dims={dims:?} repeats={repeats}");

    for &d in &dims {
        let k = d - 1;
        let gens = commit_generators(d);
        for &n in &sizes {
            for rep in 0..repeats {
                let weights = op.weights(n);

                // ---- per-owner key generation (no curator) ----
                let t = Instant::now();
                let owners: Vec<Owner> = (0..n).map(|_| Owner::keygen(&mut rng)).collect();
                let owner_keygen_ms = ms(t.elapsed());
                let pubkeys: Vec<G2Projective> = owners.iter().map(|o| o.pk).collect();

                // ---- encryption ----
                let s = he_keygen(&mut rng, k);
                let inputs: Vec<Fr> = (0..n).map(|i| Fr::from((i as u64 % 7) + 1)).collect();
                let t = Instant::now();
                let cts: Vec<Vec<Fr>> = inputs
                    .iter()
                    .map(|m| he_enc(&s, *m, &mut rng))
                    .collect();
                let encrypt_ms = ms(t.elapsed());

                // ---- P(c_i), the O(D) part of the owner's work ----
                let t = Instant::now();
                let commitments: Vec<G1Projective> =
                    cts.iter().map(|c| commit(c, &gens)).collect();
                let commit_inputs_ms = ms(t.elapsed());

                // ---- sigma_i = sk_i * M_i ----
                let t = Instant::now();
                let signatures: Vec<G1Projective> = (0..n)
                    .map(|i| {
                        owners[i].sign(&tag, i as u64, op.code(), n as u64, &commitments[i])
                    })
                    .collect();
                let sign_ms = ms(t.elapsed());
                let sign_per_input_us = (sign_ms * 1000.0) / n as f64;

                // ---- legacy input-hash signing, for the cost-of-fix delta ----
                let t = Instant::now();
                let _legacy: Vec<G1Projective> = (0..n)
                    .map(|i| {
                        legacy_context_point(
                            &owners[i].pk,
                            &tag,
                            i as u64,
                            op.code(),
                            n as u64,
                            hash_ciphertext(&cts[i]),
                        ) * owners[i].sk
                    })
                    .collect();
                let legacy_sign_ms = ms(t.elapsed());

                // ---- admission: one 2-pairing check per record, O(N) total ----
                let t = Instant::now();
                let mut admitted = 0usize;
                for i in 0..n {
                    if admit(
                        &pubkeys[i],
                        &tag,
                        i as u64,
                        op.code(),
                        n as u64,
                        &commitments[i],
                        &signatures[i],
                    ) {
                        admitted += 1;
                    }
                }
                let admit_verify_ms = ms(t.elapsed());
                assert_eq!(admitted, n, "bench: every honest admission must be accepted");

                // ---- accumulator fold ----
                let t = Instant::now();
                let mut p_agg = G1Projective::zero();
                for (c, w) in commitments.iter().zip(weights.iter()) {
                    p_agg += *c * *w;
                }
                let accumulate_ms = ms(t.elapsed());

                // ---- operator: commit the delivered output ----
                let output = he_combine(&cts, &weights, d);
                let t = Instant::now();
                let p_out = commit(&output, &gens);
                let commit_output_ms = ms(t.elapsed());

                // ---- result check: O(1), pairing free ----
                let t = Instant::now();
                let result_ok = p_out == p_agg;
                let result_check_ms = ms(t.elapsed());
                assert!(result_ok, "bench: honest result must be accepted");

                // ---- off-chain aggregate certificate: (N+1) pairings ----
                let sigma_agg = signatures
                    .iter()
                    .zip(weights.iter())
                    .fold(G1Projective::zero(), |acc, (s, w)| acc + *s * *w);
                let t = Instant::now();
                let cert_ok = verify_aggregate_certificate(
                    &sigma_agg,
                    &commitments,
                    &pubkeys,
                    &tag,
                    op,
                    &weights,
                );
                let agg_certificate_ms = ms(t.elapsed());
                assert!(cert_ok, "bench: honest aggregate certificate must verify");

                let single_sig_bytes = g1_serialized_len(&signatures[0], true);
                let agg_sig_bytes = g1_serialized_len(&sigma_agg, true);
                let output_commitment_bytes = g1_serialized_len(&p_out, true);
                let pubkey_bytes = g2_serialized_len(&pubkeys[0], true);

                writeln!(
                    file,
                    "output_binding_multikey,{d},{n},{rep},{owner_keygen_ms:.4},{encrypt_ms:.4},\
{commit_inputs_ms:.4},{sign_ms:.4},{sign_per_input_us:.4},{legacy_sign_ms:.4},\
{admit_verify_ms:.4},{:.4},{accumulate_ms:.4},{commit_output_ms:.4},{result_check_ms:.6},\
{agg_certificate_ms:.4},{single_sig_bytes},{agg_sig_bytes},{output_commitment_bytes},\
{pubkey_bytes}",
                    admit_verify_ms / n as f64
                )
                .unwrap();
            }
            println!("  D={d:<4} N={n:<4} done ({repeats} repeats)");
        }
    }

    println!("Wrote {out_path}");
}

// =============================================================================
// EMIT: multi-key payload for scripts/mklhs_tfhe_onchain.js
//
// Same schema as the real-TFHE emitter, with `scheme = output_binding_demo_multikey`.
// Feeding this file to the Hardhat harness checks that this Rust map, the JS
// tooling and the Solidity contract agree on the generators, the context
// encoding and the acceptance predicate.
// =============================================================================

fn run_emit_mk(args: &[String]) {
    let out_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "onchain_proofs_mirror_mk.json".to_string());
    let sizes: Vec<usize> = if args.len() > 3 {
        args[3..].iter().filter_map(|s| s.parse().ok()).collect()
    } else {
        std::env::var("OB_SIZES")
            .ok()
            .map(|s| parse_usize_list(&s))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![10, 50, 100, 200])
    };

    // The on-chain relation only sees the commitment point, so D does not affect
    // gas. A small D keeps the payload readable; the emission is seeded, so the
    // file is byte-reproducible across runs and machines.
    let d = D;
    let k = d - 1;
    let mut rng = StdRng::seed_from_u64(0x0C_C0FFEE_u64);
    let tag = dataset_tag();
    let tag_hex = format!("0x{}", hex::encode(tag));
    let gens = commit_generators(d);

    let gens_json: Vec<String> = gens
        .iter()
        .map(|g| {
            let (x, y) = g1_dec(g);
            format!("[\"{x}\",\"{y}\"]")
        })
        .collect();

    let mut entries: Vec<String> = Vec::new();
    for &n in &sizes {
        for op in [Op::Sum, Op::Sub] {
            let plaintexts: Vec<i128> = (0..n).map(|i| ((i as i128) % 7) + 1).collect();
            let dep = Deployment::build(&mut rng, &plaintexts, op, d);

            // Self-validating fixtures: the emitter refuses to write a payload
            // whose verdicts are wrong, so a bad fixture cannot reach Hardhat.
            let honest_commitment = commit(&dep.output, &dep.gens);
            let (adm, chain, cons) = dep.compose(
                &dep.honest_records(),
                &honest_commitment,
                &coords_digest_hex(&dep.output),
                &dep.output,
            );
            assert!(adm && chain && cons, "emit: honest fixture must be accepted");
            let (_, attack_chain, _) = dep.compose(
                &dep.honest_records(),
                &dep.commitments[0],
                &coords_digest_hex(&dep.ciphertexts[0]),
                &dep.ciphertexts[0],
            );
            assert!(
                !attack_chain,
                "emit: output-substitution fixture must be rejected on-chain"
            );

            let rogue = Owner::keygen(&mut rng);
            let wrong_key_sig = context_point(
                &dep.owners[0].pk,
                &tag,
                0,
                op.code(),
                n as u64,
                &dep.commitments[0],
            ) * rogue.sk;
            assert!(
                !admit(
                    &dep.owners[0].pk,
                    &tag,
                    0,
                    op.code(),
                    n as u64,
                    &dep.commitments[0],
                    &wrong_key_sig
                ),
                "emit: wrong-key signature must be rejected"
            );

            let records: Vec<String> = (0..n)
                .map(|i| {
                    let (cx, cy) = g1_dec(&dep.commitments[i]);
                    let (sx, sy) = g1_dec(&dep.signatures[i]);
                    let pk = g2_dec(&dep.owners[i].pk);
                    format!(
                        "        {{ \"index\": {i}, \"commitment\": [\"{cx}\",\"{cy}\"], \"signature\": [\"{sx}\",\"{sy}\"], \"pubkey\": [\"{}\",\"{}\",\"{}\",\"{}\"] }}",
                        pk[0], pk[1], pk[2], pk[3]
                    )
                })
                .collect();

            let lifted: Vec<String> = dep
                .output
                .iter()
                .map(|c| format!("\"{}\"", c.into_bigint()))
                .collect();
            let (hx, hy) = g1_dec(&honest_commitment);
            let (ax, ay) = g1_dec(&dep.commitments[0]);
            let (wx, wy) = g1_dec(&wrong_key_sig);
            let expected = dep.expected_plaintext;

            entries.push(format!(
                "    {{\n      \"n\": {n},\n      \"allowed_op\": {},\n      \"expected_plaintext\": {expected},\n      \"dataset_tag\": \"{tag_hex}\",\n      \"records\": [\n{}\n      ],\n      \"wrong_key_signature\": [\"{wx}\",\"{wy}\"],\n      \"honest\": {{ \"commitment\": [\"{hx}\",\"{hy}\"], \"output_digest\": \"{}\", \"lifted\": [{}] }},\n      \"attack\": {{ \"commitment\": [\"{ax}\",\"{ay}\"], \"output_digest\": \"{}\" }}\n    }}",
                op.code(),
                records.join(",\n"),
                coords_digest_hex(&dep.output),
                lifted.join(","),
                coords_digest_hex(&dep.ciphertexts[0]),
            ));
        }
    }

    let json = format!(
        "{{\n  \"curve\": \"BN254\",\n  \"hash_domain\": \"MKLHS_CTX_V1_\",\n  \"scheme\": \"output_binding_demo_multikey\",\n  \"dataset_tag\": \"{tag_hex}\",\n  \"lwe_dimension\": {k},\n  \"ciphertext_dim\": {d},\n  \"commit_generators\": [{}],\n  \"sizes\": [\n{}\n  ]\n}}\n",
        gens_json.join(","),
        entries.join(",\n")
    );
    std::fs::write(&out_path, json).expect("cannot write multi-key payload");
    println!("Wrote {out_path} (multi-key mirror, sizes {sizes:?}, dataset_tag {tag_hex})");
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed vectors of the MapToGroup map. These values are the ones the
    /// Solidity contract and the JS tooling derive for the same preimages;
    /// `test/mklhs-map-agreement.test.js` re-checks the generators and one
    /// context point against a payload emitted by `emit-onchain-mk`.
    #[test]
    fn map_to_group_is_deterministic_and_on_curve() {
        for d in 0..8u64 {
            let mut preimage = b"OB_LHS_GEN_".to_vec();
            preimage.extend_from_slice(&d.to_be_bytes());
            let g = hash_to_g1(&preimage);
            assert!(g.into_affine().is_on_curve());
            assert!(!g.is_zero());
            assert_eq!(g, hash_to_g1(&preimage), "map must be deterministic");
        }
    }

    #[test]
    fn generators_are_pairwise_distinct() {
        let gens = commit_generators(64);
        for i in 0..gens.len() {
            for j in (i + 1)..gens.len() {
                assert_ne!(gens[i], gens[j], "generators {i} and {j} collide");
            }
        }
    }

    #[test]
    fn commitment_is_linear_so_the_aggregate_binds_the_output() {
        let mut rng = StdRng::seed_from_u64(0x11FE);
        for op in [Op::Sum, Op::Sub] {
            let plaintexts: Vec<i128> = (0..6).map(|i| i + 1).collect();
            let dep = Deployment::build(&mut rng, &plaintexts, op, D);
            let p_agg = dep
                .commitments
                .iter()
                .zip(dep.weights.iter())
                .fold(G1Projective::zero(), |acc, (c, w)| acc + *c * *w);
            assert_eq!(commit(&dep.output, &dep.gens), p_agg);
        }
    }

    #[test]
    fn commitment_rejects_mismatched_dimensions() {
        let gens = commit_generators(2);
        for values in [vec![3u64], vec![3, 5, 7]] {
            let vector: Vec<Fr> = values.into_iter().map(Fr::from).collect();
            assert!(std::panic::catch_unwind(|| commit(&vector, &gens)).is_err());
        }
    }

    #[test]
    fn consumer_rejects_extra_coordinates_even_with_a_matching_digest() {
        let gens = commit_generators(2);
        let vector = vec![Fr::from(3u64), Fr::from(5u64)];
        let commitment = commit(&vector, &gens);
        let honest = OnChainRecord {
            commitment,
            output_digest: coords_digest_hex(&vector),
        };
        assert!(consumer_accepts(&vector, &gens, &honest));
        for extra in [Fr::zero(), Fr::from(7u64)] {
            let mut delivered = vector.clone();
            delivered.push(extra);
            let record = OnChainRecord {
                commitment,
                output_digest: coords_digest_hex(&delivered),
            };
            assert!(!consumer_accepts(&delivered, &gens, &record));
        }
    }

    #[test]
    fn consumer_rejects_truncation_even_when_the_omitted_coordinate_is_zero() {
        let gens = commit_generators(3);
        let vector = vec![Fr::from(3u64), Fr::from(5u64), Fr::zero()];
        let delivered = &vector[..2];
        let record = OnChainRecord {
            commitment: commit(&vector, &gens),
            output_digest: coords_digest_hex(delivered),
        };
        assert!(!consumer_accepts(delivered, &gens, &record));
    }

    #[test]
    fn honest_flow_is_accepted_and_decrypts_exactly() {
        let mut rng = StdRng::seed_from_u64(0x5EED);
        for op in [Op::Sum, Op::Sub] {
            let plaintexts = vec![3i128, 1, 2, 5, 4];
            let dep = Deployment::build(&mut rng, &plaintexts, op, D);
            let commitment = commit(&dep.output, &dep.gens);
            let (adm, chain, cons) = dep.compose(
                &dep.honest_records(),
                &commitment,
                &coords_digest_hex(&dep.output),
                &dep.output,
            );
            assert!(adm && chain && cons);
            // Real decryption returns a value in the l-bit message space, so the
            // signed reference must be reduced into the same domain. The old
            // stand-in had no message space, which is why a bare i128
            // comparison used to work.
            let msg_space = 1i128 << MSG_BITS;
            assert_eq!(
                fr_to_i128(&he_dec(&dep.he_secret, &dep.output)),
                ((dep.expected_plaintext % msg_space) + msg_space) % msg_space
            );
        }
    }

    #[test]
    fn every_single_coordinate_mutation_of_the_output_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0xC0DE);
        let dep = Deployment::build(&mut rng, &[1i128, 2, 3, 4], Op::Sum, D);
        let honest = commit(&dep.output, &dep.gens);
        for coordinate in 0..D {
            let mut mutated = dep.output.clone();
            mutated[coordinate] += Fr::from(1u64);
            // Delivered vector mutated, honest commitment submitted: the
            // consumer's recomputation must catch it.
            let (_, chain, cons) = dep.compose(
                &dep.honest_records(),
                &honest,
                &coords_digest_hex(&dep.output),
                &mutated,
            );
            assert!(chain, "on-chain check sees only the commitment");
            assert!(!cons, "coordinate {coordinate} mutation must be caught");
            // Commitment recomputed from the mutated vector: rejected on-chain.
            let (_, chain2, _) = dep.compose(
                &dep.honest_records(),
                &commit(&mutated, &dep.gens),
                &coords_digest_hex(&mutated),
                &mutated,
            );
            assert!(!chain2, "coordinate {coordinate} mutation must fail P_agg");
        }
    }

    #[test]
    fn signature_does_not_move_across_index_tag_operation_or_size() {
        let mut rng = StdRng::seed_from_u64(0xA11CE);
        let n = 5usize;
        let dep = Deployment::build(&mut rng, &[1i128, 2, 3, 4, 5], Op::Sum, D);
        let other_op = Op::Sub;
        let mut other_tag = dep.tag;
        other_tag[0] ^= 0xff;

        // The honest admission is accepted.
        assert!(admit(
            &dep.owners[0].pk,
            &dep.tag,
            0,
            dep.op.code(),
            n as u64,
            &dep.commitments[0],
            &dep.signatures[0]
        ));
        // Every single-field change breaks it.
        assert!(!admit(&dep.owners[0].pk, &dep.tag, 1, dep.op.code(), n as u64, &dep.commitments[0], &dep.signatures[0]));
        assert!(!admit(&dep.owners[0].pk, &other_tag, 0, dep.op.code(), n as u64, &dep.commitments[0], &dep.signatures[0]));
        assert!(!admit(&dep.owners[0].pk, &dep.tag, 0, other_op.code(), n as u64, &dep.commitments[0], &dep.signatures[0]));
        assert!(!admit(&dep.owners[0].pk, &dep.tag, 0, dep.op.code(), (n + 1) as u64, &dep.commitments[0], &dep.signatures[0]));
        assert!(!admit(&dep.owners[1].pk, &dep.tag, 0, dep.op.code(), n as u64, &dep.commitments[0], &dep.signatures[0]));
        assert!(!admit(&dep.owners[0].pk, &dep.tag, 0, dep.op.code(), n as u64, &dep.commitments[1], &dep.signatures[0]));
    }

    #[test]
    fn signature_has_no_exploitable_linear_structure() {
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let dep = Deployment::build(&mut rng, &[1i128, 2, 3], Op::Sum, D);
        // Scalar multiples of a valid pair are not valid for the scaled commitment.
        for k in [2u64, 3, 7, 1 << 20] {
            let s = Fr::from(k);
            assert!(!admit(
                &dep.owners[0].pk,
                &dep.tag,
                0,
                dep.op.code(),
                dep.n as u64,
                &(dep.commitments[0] * s),
                &(dep.signatures[0] * s)
            ));
        }
        // Sums of two pairs under one key are not valid for the summed commitment.
        let mut rng2 = StdRng::seed_from_u64(0xBEE2);
        let owner = Owner::keygen(&mut rng2);
        let c0 = commit(&he_enc(&dep.he_secret, Fr::from(1u64), &mut rng2), &dep.gens);
        let c1 = commit(&he_enc(&dep.he_secret, Fr::from(2u64), &mut rng2), &dep.gens);
        let s0 = owner.sign(&dep.tag, 0, dep.op.code(), dep.n as u64, &c0);
        let s1 = owner.sign(&dep.tag, 0, dep.op.code(), dep.n as u64, &c1);
        assert!(!admit(&owner.pk, &dep.tag, 0, dep.op.code(), dep.n as u64, &(c0 + c1), &(s0 + s1)));
    }

    #[test]
    fn input_omission_is_rejected_even_when_self_consistent() {
        let mut rng = StdRng::seed_from_u64(0x0511);
        let n = 5usize;
        let dep = Deployment::build(&mut rng, &[1i128, 2, 3, 4, 5], Op::Sum, D);
        for omitted in 0..n {
            let records: Vec<_> = dep
                .honest_records()
                .into_iter()
                .filter(|(i, _, _)| *i != omitted as u64)
                .collect();
            let subset_cts: Vec<Vec<Fr>> = (0..n)
                .filter(|i| *i != omitted)
                .map(|i| dep.ciphertexts[i].clone())
                .collect();
            let subset_w = vec![Fr::from(1u64); n - 1];
            let subset_out = he_combine(&subset_cts, &subset_w, D);
            let (_, chain, _) = dep.compose(
                &records,
                &commit(&subset_out, &dep.gens),
                &coords_digest_hex(&subset_out),
                &subset_out,
            );
            assert!(!chain, "omission of index {omitted} must be rejected");
        }
    }

    #[test]
    fn double_admission_of_one_index_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0xD0B1);
        let dep = Deployment::build(&mut rng, &[1i128, 2, 3], Op::Sum, D);
        let mut acc = Accumulator::new(dep.n);
        assert!(acc.admit_record(&dep.owners[0].pk, &dep.tag, 0, dep.op, &dep.commitments[0], &dep.signatures[0], dep.weights[0]));
        assert!(!acc.admit_record(&dep.owners[0].pk, &dep.tag, 0, dep.op, &dep.commitments[0], &dep.signatures[0], dep.weights[0]));
    }

    #[test]
    fn point_at_infinity_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0x1FF1);
        let dep = Deployment::build(&mut rng, &[1i128, 2, 3], Op::Sum, D);
        assert!(!admit(&dep.owners[0].pk, &dep.tag, 0, dep.op.code(), dep.n as u64, &G1Projective::zero(), &dep.signatures[0]));
        assert!(!admit(&dep.owners[0].pk, &dep.tag, 0, dep.op.code(), dep.n as u64, &dep.commitments[0], &G1Projective::zero()));
        // A cancelling accumulator must not be accepted as a result.
        let acc = Accumulator::new(0);
        assert!(!acc.accepts_result(&G1Projective::zero()));
    }

    #[test]
    fn aggregate_certificate_accepts_the_honest_set_and_rejects_mutations() {
        let mut rng = StdRng::seed_from_u64(0xA66);
        for op in [Op::Sum, Op::Sub] {
            let dep = Deployment::build(&mut rng, &[1i128, 2, 3, 4], op, D);
            let pubkeys = dep.pubkeys();
            let sigma_agg = dep
                .signatures
                .iter()
                .zip(dep.weights.iter())
                .fold(G1Projective::zero(), |acc, (s, w)| acc + *s * *w);
            assert!(verify_aggregate_certificate(&sigma_agg, &dep.commitments, &pubkeys, &dep.tag, op, &dep.weights));
            let mut swapped = pubkeys.clone();
            swapped.swap(0, 1);
            assert!(!verify_aggregate_certificate(&sigma_agg, &dep.commitments, &swapped, &dep.tag, op, &dep.weights));
            let other_op = if op == Op::Sum { Op::Sub } else { Op::Sum };
            assert!(!verify_aggregate_certificate(&sigma_agg, &dep.commitments, &pubkeys, &dep.tag, other_op, &other_op.weights(dep.n)));
        }
    }

    #[test]
    fn legacy_input_hash_relation_cannot_see_an_output_substitution() {
        // The contrast of Section 4.3: the legacy relation authenticates the
        // inputs and weights and accepts regardless of what is delivered.
        let mut rng = StdRng::seed_from_u64(0x1E6);
        let dep = Deployment::build(&mut rng, &[3i128, 1, 2], Op::Sum, D);
        let hashes: Vec<Fr> = dep.ciphertexts.iter().map(|c| hash_ciphertext(c)).collect();
        let sigs: Vec<G1Projective> = (0..dep.n)
            .map(|i| {
                legacy_context_point(&dep.owners[i].pk, &dep.tag, i as u64, dep.op.code(), dep.n as u64, hashes[i])
                    * dep.owners[i].sk
            })
            .collect();
        let h_agg: Fr = hashes.iter().zip(dep.weights.iter()).map(|(h, w)| *h * *w).sum();
        assert!(legacy_accepts(&dep.owners, &dep.tag, dep.op, &hashes, &sigs, &dep.weights, h_agg));

        // The composed verifier rejects the same substituted delivery.
        let honest = commit(&dep.output, &dep.gens);
        let (_, chain, cons) = dep.compose(
            &dep.honest_records(),
            &honest,
            &coords_digest_hex(&dep.output),
            &dep.ciphertexts[0],
        );
        assert!(chain, "the contract sees only the commitment");
        assert!(!cons, "the consumer must reject the substituted delivery");
    }

    #[test]
    fn artifact_digest_is_fixed_width_and_detects_coordinate_changes() {
        let original = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let mut modified = original.clone();
        modified[1] += Fr::from(1u64);
        let digest = coords_digest_hex(&original);
        assert_eq!(digest.len(), 66);
        assert_ne!(digest, coords_digest_hex(&modified));
    }

    #[test]
    fn emission_is_reproducible() {
        // The emitter is seeded, so two runs write identical payloads. This is
        // what makes the on-chain gas measurement reproducible.
        let args1 = vec![
            "x".to_string(),
            "emit-onchain-mk".to_string(),
            "/tmp/mirror_mk_a.json".to_string(),
            "4".to_string(),
        ];
        let args2 = vec![
            "x".to_string(),
            "emit-onchain-mk".to_string(),
            "/tmp/mirror_mk_b.json".to_string(),
            "4".to_string(),
        ];
        run_emit_mk(&args1);
        run_emit_mk(&args2);
        let a = std::fs::read("/tmp/mirror_mk_a.json").unwrap();
        let b = std::fs::read("/tmp/mirror_mk_b.json").unwrap();
        assert_eq!(a, b, "seeded emission must be byte-reproducible");
    }
}
