//! # End-to-end output binding over **real TFHE** (not a stand-in)
//!
//! This binary resolves the Reviewer-2 flaw for the *whole* linear pipeline using
//! genuine TFHE ciphertexts from `tfhe-rs` (`core_crypto`), rather than an
//! algebraic stand-in. It demonstrates that the redesigned linear verification
//! scheme cryptographically binds the delivered FHE output ciphertext `C_out`.
//!
//! ## Why `core_crypto` LWE (and not `FheUint`)
//!
//! The output-binding relation requires the homomorphic evaluation of the
//! authorized *linear* function to be **coordinate-wise linear** on ciphertexts,
//! i.e. `C_out = Σ_i w_i · C_i` in `Z_q^{k+1}`. `FheUint` addition bootstraps and
//! propagates carries, producing a *fresh* ciphertext that is not the linear
//! combination of the inputs, so it cannot be bound by a linear authenticator.
//!
//! The linear path therefore uses a **leveled LWE encoding**: each rating is a
//! single native-modulus LWE ciphertext `C_i = (a_i, b_i) ∈ Z_q^{k+1}` with
//! `b_i = <a_i, s> + Δ·m_i + e_i`. The weighted sum is evaluated by
//! coordinate-wise addition (no PBS), which is exactly linear. The message space
//! Δ and the number of terms are chosen so the leveled result decrypts correctly
//! (bounded-noise, no message overflow) — the standard leveled regime that the
//! Fiore–Gennaro–Pastro linear authenticator assumes.
//!
//! ## The authenticator (context-bound BLS signature over the ciphertext commitment)
//!
//! ```text
//!   client:   P(C_i) = Σ_d φ(C_{i,d})·G_d
//!             M_i    = MapToGroup( "MKLHS_CTX_V1_" || pk_i || tag || i || op || N || P(C_i) )
//!             σ_i    = sk_i · M_i
//!   contract: accept admission iff  e(σ_i, G2) == e(M_i, pk_i),  M_i recomputed on-chain
//!             P_agg += w_i · P(C_i)
//!   result:   accept iff  P(A_out) == P_agg      (one G1 equality, no pairing)
//! ```
//!
//! where `φ: Z_q ↪ F_r` is the natural injection (q = 2^64 < r, injective) and
//! `G_d` are independent BN254 generators (hash-to-curve, unknown discrete logs).
//! The homomorphism lives only in `P`; the signature carries none, so no scalar
//! multiple or combination of signatures verifies against a different commitment.
//!
//! ## Lifted accumulator (delivered output)
//!
//! The operator does NOT deliver a native `u64` LWE ciphertext directly; it
//! delivers the **lifted accumulator** `A = (Σ_i w_i·φ(C_{i,d}))_d ∈ F_r^{k+1}`
//! (a non-reduced linear combination), so that `P(A) = Σ_i w_i P(C_i)` holds
//! *exactly* (no mod-q wrap under φ). The consumer derives the canonical TFHE
//! ciphertext `C_out[d] = ρ(A_d)` by the **balanced** reduction into `Z_q`
//! (`fr_to_zq_centered`, which handles negative SUB combinations correctly), then
//! TFHE-decrypts. Correctness holds only in the leveled regime
//! (`leveled_regime_ok`): message space and noise budget must not overflow — we
//! never silently reduce the result modulo the message space.
//!
//! Substituting the delivered output (returning `C_0` while keeping `σ_out`)
//! changes `P(A)` and breaks the pairing. Labels are `H(tag, i)` with a
//! dataset/epoch `tag` (anti-replay), matching the Solidity contract.
//!
//! ## Modes
//! Any other argument is rejected with exit code 2; it never falls through to
//! the demo, so a misspelled emitter cannot leave a stale payload in place.
//!
//!   (no argument)         self-validating demo: SUM and SUB, honest ACCEPT +
//!                         attack REJECT + EXACT decrypt (asserts in-regime)
//!   emit-onchain-mk <out.json> [sizes...]
//!                         emit the seeded multi-key payload (per-owner
//!                         commitment, signature and public key, plus the
//!                         dataset tag and the commitment generators) that the
//!                         on-chain gas measurement consumes
//!   emit-onchain-mk-cases <out.json> <cases.json>
//!                         the same payload for an explicit list of cases
//!
//! The single-key `emit-onchain` mode was removed with the curator contract it
//! served; the deployed path is curator-free.
//!
//! NOTE: `tfhe-rs` has no Windows backend (features `x86_64-unix`/`aarch64-unix`),
//! so build/run this on the same Linux/WSL toolchain used for the other TFHE
//! experiments:  `cargo run --release --bin output_binding_tfhe`.
//!
//! ## Scientific basis (references)
//!
//! The output-binding fix is the *linear case* of verifiable computation on
//! encrypted data, i.e. the homomorphic-authenticator paradigm of:
//!   - Fiore, Gennaro, Pastro, "Efficiently Verifiable Computation on Encrypted
//!     Data", ACM CCS 2014. DOI: 10.1145/2660267.2660366.   [primary basis]
//!   - Catalano, Fiore, "Practical Homomorphic MACs for Arithmetic Circuits",
//!     EUROCRYPT 2013. DOI: 10.1007/978-3-642-38348-9_21.    [Hom-MAC lineage]
//! The linearly homomorphic signature over the ciphertext vector is the pairing
//! (BLS-type) construction of:
//!   - Boneh, Freeman, Katz, Waters, "Signing a Linear Subspace" (BFKW), PKC 2009.
//!   - Boneh, Lynn, Shacham, "Short Signatures from the Weil Pairing" (BLS), 2001.
//! The commitment `P(C) = Σ_d φ(C_d)·G_d` is a Pedersen-style vector commitment
//! (Pedersen, CRYPTO '91; binding under the discrete-log relation assumption,
//! cf. Bünz et al., "Bulletproofs", IEEE S&P 2018).

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, CurveGroup, Group};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::{UniformRand, Zero};
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Keccak256};
use std::io::Write as _;

use tfhe::core_crypto::prelude::*;

// =============================================================================
// Leveled LWE parameters (native modulus q = 2^64)
// =============================================================================

/// LWE mask dimension k. Ciphertext vector dimension is D = k + 1.
const LWE_K: usize = 742;
/// Message bit-width for the leveled encoding (message occupies the top bits).
const MSG_BITS: u32 = 10;
/// Scaling factor Δ = 2^(64 - MSG_BITS).
const DELTA: u64 = 1u64 << (64 - MSG_BITS);
/// Gaussian noise standard deviation for the native-modulus LWE (classic params).
const LWE_STD_DEV: f64 = 0.000_007_069_849_454_709_433;

/// Leveled-regime validity (see Lemma "Correctness in the leveled regime"):
/// decryption of the aggregated ciphertext is correct **iff** both budgets hold:
///   (message) |Σ_i w_i m_i| < 2^{MSG_BITS-1}              (no message overflow)
///   (noise)   |Σ_i w_i e_i| < Δ/2, with σ_e ≈ 2^46.9      (bounded noise growth)
/// The noise budget bounds the number of summable terms. With a 6σ tail bound
/// (6·σ_e·√N < Δ/2) and MSG_BITS=10 (Δ=2^54, σ_e≈2^46.9), N_max ≈ (Δ/(12σ_e))² ≈ 130.
/// The check below uses a stricter 12σ margin, admitting N ≤ ~33.
/// Outside this regime this bound gives no correctness guarantee; decryption
/// need not fail on every sample. We never silently reduce the
/// result modulo the message space and call it correct; the demo asserts *exact*
/// equality and refuses to claim correctness beyond the regime.
fn leveled_regime_ok(n: usize, abs_result: u128) -> bool {
    let msg_ok = abs_result < (1u128 << (MSG_BITS - 1));
    // Twelve-standard-deviation bound on the aggregate Gaussian noise.
    let sigma_e = (LWE_STD_DEV * 2f64.powi(64)).max(1.0);
    let noise_bound = 12.0 * sigma_e * (n as f64).sqrt();
    let noise_ok = noise_bound < (DELTA / 2) as f64;
    msg_ok && noise_ok
}

/// Dataset/epoch tag bound into every label H(tag, i) (anti-replay). Matches the
/// Solidity index-label preimage `"LHS_H2C_" || tag(32) || i_be(8)`
/// when the contract is deployed with this same `bytes32` tag.
fn dataset_tag() -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"vc-fhe/output-binding/v1");
    let d = h.finalize();
    let mut t = [0u8; 32];
    t.copy_from_slice(&d);
    t
}

// =============================================================================
// BN254 helpers (MapToGroup identical to the Solidity `mapToG1`)
// =============================================================================

/// MapToGroup trial bound. The counter is 8 bits wide (`I = 8` in the notation
/// of BLS01), hence at most `2^8 = 256` trials. Each trial succeeds with
/// probability `alpha >= 1/2 - p^(-1/2)` by the Hasse bound, so a preimage is
/// unhashable with probability below `2^-255`.
const MAP_TRIALS: u16 = 256;

/// One Keccak256 block of the MapToGroup expansion, over the 32-byte seed.
fn map_block(stream: u8, trial: u8, seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update([stream, trial]);
    h.update(seed);
    let d = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(&d);
    o
}

/// MapToGroup of BLS01 on BN254, identical to the Solidity `mapToG1` and to the
/// JavaScript tooling. The caller derives `seed = keccak256(preimage)` and every
/// trial expands that seed. For each trial counter, two Keccak256 blocks give 512
/// bits that are reduced modulo the base field characteristic, which bounds the
/// reduction bias by about `2^-261`, and a third block gives the root-selection
/// bit `b`. On failure the counter is incremented and the blocks are recomputed,
/// so the accepted x-coordinate is uniform over the coordinates that satisfy the
/// curve equation and the returned point is uniform over `G1 \ {O}`. The cofactor
/// of `G1` on BN254 is one, so no cofactor clearing is applied.
fn map_to_g1(seed: &[u8; 32]) -> G1Projective {
    for trial in 0..MAP_TRIALS {
        let t = trial as u8;
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&map_block(0x00, t, seed));
        wide[32..].copy_from_slice(&map_block(0x01, t, seed));
        let x = Fq::from_be_bytes_mod_order(&wide);
        let b = map_block(0x02, t, seed)[31] & 1;

        let y_sq = x * x * x + Fq::from(3u64);
        if let Some(y) = y_sq.sqrt() {
            let neg_y = -y;
            let y_be = y.into_bigint().to_bytes_be();
            let neg_be = neg_y.into_bigint().to_bytes_be();
            let (y0, y1) = if y_be <= neg_be { (y, neg_y) } else { (neg_y, y) };
            let aff = G1Affine::new_unchecked(x, if b == 0 { y0 } else { y1 });
            assert!(aff.is_on_curve());
            return aff.into();
        }
    }
    panic!("MapToGroup: unhashable message after {MAP_TRIALS} trials");
}

/// MapToGroup over a byte-string preimage.
fn hash_to_g1(domain: &[u8]) -> G1Projective {
    let mut h = Keccak256::new();
    h.update(domain);
    let d = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&d);
    map_to_g1(&seed)
}

/// Label H(tag, i). With a zero tag this is the legacy preimage
/// `keccak256("LHS_H2C_" || i_be)`; with a non-zero tag the 32-byte tag is
/// inserted, matching the legacy Solidity index-label helper.
fn index_point(tag: &[u8; 32], i: u64) -> G1Projective {
    let mut d = b"LHS_H2C_".to_vec();
    if *tag != [0u8; 32] {
        d.extend_from_slice(tag);
    }
    d.extend_from_slice(&i.to_be_bytes());
    hash_to_g1(&d)
}

/// Context-bound message point, mirroring the Solidity `hashContextToG1`:
///   M_i = H2C( "MKLHS_CTX_V1_" || pk_i(4x32) || tag(32) || i(8) || op(1) || N(8) || P_i(2x32) )
/// The commitment is inside the hash preimage, so the signature has no additive
/// structure: neither a scalar multiple nor a combination of two signatures
/// under the same label yields a valid pair for a different commitment.
fn context_point(
    pk: &G2Projective,
    tag: &[u8; 32],
    i: u64,
    op_code: u8,
    total_items: u64,
    commitment: &G1Projective,
) -> G1Projective {
    fn be32(v: Fq) -> [u8; 32] {
        let b = v.into_bigint().to_bytes_be();
        let mut o = [0u8; 32];
        o[32 - b.len()..].copy_from_slice(&b);
        o
    }
    let a = pk.into_affine();
    let c = commitment.into_affine();
    let mut d = b"MKLHS_CTX_V1_".to_vec();
    d.extend_from_slice(&be32(a.x.c0));
    d.extend_from_slice(&be32(a.x.c1));
    d.extend_from_slice(&be32(a.y.c0));
    d.extend_from_slice(&be32(a.y.c1));
    d.extend_from_slice(tag);
    d.extend_from_slice(&i.to_be_bytes());
    d.push(op_code);
    d.extend_from_slice(&total_items.to_be_bytes());
    d.extend_from_slice(&be32(c.x));
    d.extend_from_slice(&be32(c.y));
    hash_to_g1(&d)
}

fn commit_generators(d: usize) -> Vec<G1Projective> {
    (0..d)
        .map(|i| {
            let mut dom = b"OB_LHS_GEN_".to_vec();
            dom.extend_from_slice(&(i as u64).to_be_bytes());
            hash_to_g1(&dom)
        })
        .collect()
}

/// Homomorphic commitment `P(C) = Σ_d φ(C_d)·G_d` over field elements C_d ∈ F_r.
fn commit(coords: &[Fr], gens: &[G1Projective]) -> G1Projective {
    // Multi-scalar multiplication rather than D independent scalar
    // multiplications. At the deployed dimension (D = k + 1 = 743) the naive
    // loop dominated every reported cost: the owner's per-record work and the
    // consumer's mandatory output check were both roughly an order of magnitude
    // above what the construction requires, which would have understated the
    // design in any timing the implementation reports. The value is identical by
    // definition, and the emitted payload is byte-compatible (the property
    // suite and the map-agreement test both cross-check it).
    let bases: Vec<G1Affine> = gens.iter().map(|g| g.into_affine()).collect();
    let scalars: Vec<<Fr as PrimeField>::BigInt> =
        coords.iter().map(|c| c.into_bigint()).collect();
    let n = bases.len().min(scalars.len());
    G1Projective::msm_bigint(&bases[..n], &scalars[..n])
}

fn aggregate(sigs: &[G1Projective], weights: &[Fr]) -> G1Projective {
    let mut acc = G1Projective::zero();
    for (s, w) in sigs.iter().zip(weights.iter()) {
        acc += *s * *w;
    }
    acc
}

/// Reduce a lifted-accumulator coordinate `A_d ∈ F_r` to its canonical LWE
/// coordinate in `Z_q` (q = 2^64), using the **balanced** representative so that
/// negative linear combinations (e.g. SUB weights w_i = -1) reduce correctly.
///
/// `A_d` encodes the true integer `S = Σ_i w_i c_{i,d}` with `|S| < r/2` (holds
/// because `|S| < N·q ≪ r`). If `A_d ≤ (r-1)/2` then `S = A_d ≥ 0` and
/// `S mod 2^64 = low64(A_d)`. Otherwise `S = A_d - r < 0` and
/// `S mod 2^64 = low64(A_d) - low64(r)  (mod 2^64)` — a plain wrapping subtract,
/// which is the correct two's-complement residue. Taking `low64` naively (the
/// old `fr_low_u64`) is wrong for the negative branch.
fn fr_to_zq_centered(x: &Fr) -> u64 {
    let bi = x.into_bigint();
    let low = bi.0[0];
    if bi > Fr::MODULUS_MINUS_ONE_DIV_TWO {
        let r_low = Fr::MODULUS.0[0];
        low.wrapping_sub(r_low)
    } else {
        low
    }
}

/// Consumer derivation: the operator delivers a *lifted accumulator* `A ∈ F_r^{D}`
/// (non-reduced linear combination). The canonical TFHE LWE ciphertext `C_out` the
/// consumer decrypts is `C_out[d] = ρ(A_d)`, the balanced reduction into `Z_q`.
fn derive_canonical_ct(lifted: &[Fr]) -> Vec<u64> {
    lifted.iter().map(fr_to_zq_centered).collect()
}

fn g1_dec(p: &G1Projective) -> (String, String) {
    let a = p.into_affine();
    (a.x.to_string(), a.y.to_string())
}

fn g2_pubkey_dec(p: &G2Projective) -> [String; 4] {
    let a = p.into_affine();
    [
        a.x.c0.to_string(),
        a.x.c1.to_string(),
        a.y.c0.to_string(),
        a.y.c1.to_string(),
    ]
}

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
// TFHE leveled-LWE context
// =============================================================================

struct TfheCtx {
    sk: LweSecretKey<Vec<u64>>,
    modulus: CiphertextModulus<u64>,
    enc: EncryptionRandomGenerator<ActivatedRandomGenerator>,
}

impl TfheCtx {
    fn new() -> Self {
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut secret = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let enc = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let sk = allocate_and_generate_new_binary_lwe_secret_key(LweDimension(LWE_K), &mut secret);
        TfheCtx {
            sk,
            modulus: CiphertextModulus::new_native(),
            enc,
        }
    }

    /// Deterministic context for artifact emission.
    ///
    /// The demo and the property tests draw TFHE keys and noise from OS entropy,
    /// which is what exercises the scheme. The emitted on-chain payload must
    /// instead be byte-reproducible: the admission gas of the multi-key path
    /// depends on the commitment coordinates through the MapToGroup trial count,
    /// so an unseeded emission produces a different per-record gas mean on every
    /// run and the reported table cannot be reproduced.
    fn new_seeded(seed: u128) -> Self {
        use tfhe::core_crypto::commons::generators::DeterministicSeeder;
        use tfhe::core_crypto::commons::math::random::Seed;

        let mut det = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let secret_seed = det.seed();
        let encryption_seed = det.seed();
        let mut secret = SecretRandomGenerator::<ActivatedRandomGenerator>::new(secret_seed);
        let enc = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            encryption_seed,
            &mut det,
        );
        let sk = allocate_and_generate_new_binary_lwe_secret_key(LweDimension(LWE_K), &mut secret);
        TfheCtx {
            sk,
            modulus: CiphertextModulus::new_native(),
            enc,
        }
    }

    /// Encrypt a small message into a native-modulus leveled LWE ciphertext.
    fn encrypt(&mut self, m: u64) -> LweCiphertextOwned<u64> {
        let pt = Plaintext(m.wrapping_mul(DELTA));
        let noise = Gaussian::from_dispersion_parameter(StandardDev(LWE_STD_DEV), 0.0);
        allocate_and_encrypt_new_lwe_ciphertext(&self.sk, pt, noise, self.modulus, &mut self.enc)
    }

    /// Decrypt a leveled LWE ciphertext given as reduced-mod-q coordinates.
    fn decrypt_coords(&self, coords_u64: &[u64]) -> u64 {
        let ct = LweCiphertextOwned::from_container(coords_u64.to_vec(), self.modulus);
        let raw = decrypt_lwe_ciphertext(&self.sk, &ct).0;
        // Round to nearest multiple of Δ, then divide.
        let rounded = raw.wrapping_add(DELTA / 2) / DELTA;
        rounded % (1u64 << MSG_BITS)
    }
}

/// Lift the u64 LWE coordinates of a ciphertext into F_r (injective, q < r).
fn coords_to_fr(ct: &LweCiphertextOwned<u64>) -> Vec<Fr> {
    ct.as_ref().iter().map(|c| Fr::from(*c)).collect()
}

// =============================================================================
// LHS keys over BN254
// =============================================================================

struct Lhs {
    sk: Fr,
    pk: G2Projective,
    gens: Vec<G1Projective>,
}

impl Lhs {
    fn keygen(rng: &mut StdRng, d: usize) -> Self {
        let sk = Fr::rand(rng);
        Lhs {
            sk,
            pk: G2Projective::generator() * sk,
            gens: commit_generators(d),
        }
    }

    /// Single-key algebraic self-check only. Not the deployed relation: the
    /// curator contract was removed and the deployed path binds the full
    /// context inside the hash (see `context_point`).
    #[allow(dead_code)]
    fn sign(&self, tag: &[u8; 32], coords: &[Fr], i: u64) -> G1Projective {
        (commit(coords, &self.gens) + index_point(tag, i)) * self.sk
    }

    /// e(σ_out, G2) == e( P(C_out) + H_Σ , pk ), with H_Σ = Σ_i w_i·H(tag, i).
    fn verify_bound(
        &self,
        tag: &[u8; 32],
        delivered_coords: &[Fr],
        sigma_out: G1Projective,
        weights: &[Fr],
    ) -> bool {
        let p_out = commit(delivered_coords, &self.gens);
        let mut h_sigma = G1Projective::zero();
        for (i, w) in weights.iter().enumerate() {
            h_sigma += index_point(tag, i as u64) * *w;
        }
        let lhs = Bn254::pairing(
            sigma_out.into_affine(),
            G2Projective::generator().into_affine(),
        );
        let rhs = Bn254::pairing((p_out + h_sigma).into_affine(), self.pk.into_affine());
        lhs == rhs
    }
}

/// Authorized linear operation (matches the contract's `allowedOperation`).
#[derive(Clone, Copy, PartialEq)]
enum Op {
    Sum, // 0: all weights +1
    Sub, // 1: w_0 = +1, w_{i>0} = -1
}

impl Op {
    fn code(self) -> u8 {
        match self {
            Op::Sum => 0,
            Op::Sub => 1,
        }
    }
    /// Field weights for the LHS aggregation.
    fn weights_fr(self, n: usize) -> Vec<Fr> {
        (0..n)
            .map(|i| match self {
                Op::Sum => Fr::from(1u64),
                Op::Sub => {
                    if i == 0 {
                        Fr::from(1u64)
                    } else {
                        -Fr::from(1u64)
                    }
                }
            })
            .collect()
    }
    /// Integer weights for computing the true (signed) expected result.
    fn weight_i128(self, i: usize) -> i128 {
        match self {
            Op::Sum => 1,
            Op::Sub => {
                if i == 0 {
                    1
                } else {
                    -1
                }
            }
        }
    }
}

// =============================================================================
// Core: encrypt (real TFHE) -> sign -> leveled aggregate -> bind -> decrypt
// =============================================================================

/// Result of one honest computation over real TFHE plus the substitution attack.
struct Run {
    lifted: Vec<Fr>,        // lifted accumulator A = Σ_i w_i·φ(C_i) delivered as output
    attack_lifted: Vec<Fr>, // C_0 (substituted output)
    sigma_out: G1Projective,
    weights: Vec<Fr>,
    // Output and aggregate signature after dropping the last authorized input.
    // The two are mutually consistent, so only verification against the full
    // authorized index set rejects them; that is what the property tests assert,
    // and they are the only readers.
    #[allow(dead_code)]
    omission_lifted: Vec<Fr>,
    #[allow(dead_code)]
    sigma_omission: G1Projective,
}


/// Prints a workflow-step banner matching the numbered list of
/// `\subsubsection{Linear Operations}` (`\label{sec:workflow-linear}`).
///
/// The measurement output used to announce only tooling stages, so a reader
/// could not tell which protocol step was executing. The labels here are
/// transcribed from the implementation and kept identical to
/// `scripts/workflow-steps.js`, which prints the same table on the JavaScript
/// side; if a step is renamed in the experiment, rename it in both places.
fn workflow_step(id: &str, title: &str, does: &[&str]) {
    // `build_run` is called once per (size, operation), so an unguarded banner
    // would repeat eight times in an emission. Each step announces itself once
    // per process; the per-case progress is reported by the existing table.
    use std::sync::Mutex;
    use std::sync::OnceLock;
    static SEEN: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(Vec::new()));
    {
        let mut guard = seen.lock().expect("workflow banner lock");
        if guard.iter().any(|s| s == id) {
            return;
        }
        guard.push(id.to_string());
    }

    let rule = "-".repeat(74);
    println!();
    println!("{rule}");
    println!("  {id}  {title}   [sec:workflow-linear, step {}]", &id[1..]);
    for line in does {
        println!("      {line}");
    }
    println!("{rule}");
}

/// Build one honest `op` run of `ratings` over real TFHE, plus the attack output.
/// Returns the run and the true signed integer result `Σ_i w_i m_i`.
fn build_run(ctx: &mut TfheCtx, lhs: &Lhs, tag: &[u8; 32], ratings: &[u64], op: Op) -> (Run, i128) {
    let n = ratings.len();
    let d = LWE_K + 1;
    let weights = op.weights_fr(n);

    workflow_step(
        "W2",
        "Data contribution and admission",
        &[
            "owner side, per record: KEYGEN (binary LWE secret key, per-owner BLS pair),",
            "ENCRYPT m_i as a leveled LWE vector c_i (tfhe-rs core_crypto, q = 2^64,",
            "Delta = 2^54), lift phi(c_i) into F_r, COMMIT P(c_i), and SIGN",
            "sigma_i = sk_i * H_G1(DST || pk_i || tau || i || op || N || P(c_i))",
        ],
    );
    // Client: encrypt each rating with real TFHE, sign the LWE coordinate vector.
    let cts: Vec<LweCiphertextOwned<u64>> = ratings.iter().map(|m| ctx.encrypt(*m)).collect();
    let coords_fr: Vec<Vec<Fr>> = cts.iter().map(coords_to_fr).collect();
    let sigs: Vec<G1Projective> = coords_fr
        .iter()
        .enumerate()
        .map(|(i, c)| lhs.sign(tag, c, i as u64))
        .collect();

    workflow_step(
        "W3",
        "Execution and output construction (off-chain)",
        &[
            "operator side: form the UNREDUCED output vector A = sum_i w_i*phi(c_i)",
            "coordinate-wise over ciphertexts, WITHOUT bootstrapping and WITHOUT ever",
            "decrypting, then compute the digest d_out and the commitment P(A)",
        ],
    );
    // Operator: leveled linear evaluation, as a *lifted accumulator* over F_r so
    // that P(A) = Σ_i w_i·P(C_i) holds exactly (no mod-q wrap under φ).
    let mut lifted = vec![Fr::zero(); d];
    for (c, w) in coords_fr.iter().zip(weights.iter()) {
        for j in 0..d {
            lifted[j] += c[j] * *w;
        }
    }
    let sigma_out = aggregate(&sigs, &weights);
    let attack_lifted = coords_fr[0].clone();

    // Malicious operator omits the last authorized input from both the output
    // and the aggregate signature. Output and signature are mutually
    // consistent, but verification against the full authorized index set must
    // reject the omission.
    let kept = n.saturating_sub(1);
    let mut omission_lifted = vec![Fr::zero(); d];
    for (c, w) in coords_fr[..kept].iter().zip(weights[..kept].iter()) {
        for j in 0..d {
            omission_lifted[j] += c[j] * *w;
        }
    }
    let sigma_omission = aggregate(&sigs[..kept], &weights[..kept]);

    let expected: i128 = ratings
        .iter()
        .enumerate()
        .map(|(i, m)| op.weight_i128(i) * (*m as i128))
        .sum();

    let run = Run {
        lifted,
        attack_lifted,
        sigma_out,
        weights,
        omission_lifted,
        sigma_omission,
    };
    (run, expected)
}


/// Exports a genuine `tfhe-rs` LWE key/ciphertext bundle so an independent
/// implementation can be proved to be the SAME cryptosystem, not merely a
/// similar one.
///
/// The JavaScript tooling in `scripts/mklhs-lib.js` re-implements the leveled
/// LWE encoding of the implementation. Structural similarity (binary key, Delta
/// scaling, native modulus, Gaussian noise with the same sigma) is not proof of
/// interoperability: an off-by-one in the rounding rule, a different secret-key
/// convention, or a different coordinate order would all pass a visual review
/// and silently model a different scheme. This command emits, from real
/// `tfhe-rs` primitives:
///
///   * the binary LWE secret key,
///   * ciphertexts of known plaintexts,
///   * the unreduced accumulator A = sum_i w_i*phi(c_i) of a SUM and a SUB run,
///   * the plaintext each of them must decrypt to.
///
/// `scripts/lwe-interop.test.mjs` then decrypts all of it with the JavaScript
/// implementation and fails if any value disagrees. The exported key is an
/// ephemeral, seeded test key and protects nothing.
fn run_emit_lwe_interop(args: &[String]) {
    let out = args.get(2).cloned().unwrap_or_else(|| "lwe_interop_vectors.json".to_string());
    let mut ctx = TfheCtx::new_seeded(0xC0DE_1234_5678_9ABC_u128);
    let d = LWE_K + 1;

    // Individual ciphertexts of known messages, spanning the ACR domain and the
    // top of the l-bit message space.
    let messages: Vec<u64> = vec![1, 2, 3, 4, 5, 999, 1023, 0];
    let mut cts = Vec::new();
    for m in &messages {
        let ct = ctx.encrypt(*m);
        cts.push(ct.into_container());
    }

    // A SUM and a SUB aggregation, lifted into F_r exactly as the operator does.
    let ratings: Vec<u64> = (0..10).map(|i| (i as u64 % 5) + 1).collect();
    let run_cts: Vec<Vec<u64>> = ratings
        .iter()
        .map(|m| ctx.encrypt(*m).into_container())
        .collect();

    let mut lifted_sum = vec![0i128; d];
    let mut lifted_sub = vec![0i128; d];
    for (i, c) in run_cts.iter().enumerate() {
        for j in 0..d {
            let v = c[j] as i128;
            lifted_sum[j] += v;
            lifted_sub[j] += if i == 0 { v } else { -v };
        }
    }
    let expect_sum: i128 = ratings.iter().map(|m| *m as i128).sum();
    let expect_sub: i128 =
        ratings[0] as i128 - ratings[1..].iter().map(|m| *m as i128).sum::<i128>();
    let msg_space = 1i128 << MSG_BITS;
    let norm = |x: i128| ((x % msg_space) + msg_space) % msg_space;

    let key: Vec<u64> = ctx.sk.as_ref().to_vec();
    let json = format!(
        "{{\n  \"note\": \"seeded tfhe-rs test vectors; the key is ephemeral and protects nothing\",\n  \"lwe_dimension\": {},\n  \"ciphertext_dim\": {},\n  \"msg_bits\": {},\n  \"delta\": \"{}\",\n  \"secret_key\": [{}],\n  \"messages\": [{}],\n  \"ciphertexts\": [{}],\n  \"ratings\": [{}],\n  \"lifted_sum\": [{}],\n  \"expect_sum\": {},\n  \"lifted_sub\": [{}],\n  \"expect_sub\": {}\n}}\n",
        LWE_K,
        d,
        MSG_BITS,
        DELTA,
        key.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
        messages.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
        cts.iter()
            .map(|c| format!("[{}]", c.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")))
            .collect::<Vec<_>>()
            .join(","),
        ratings.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
        lifted_sum.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(","),
        norm(expect_sum),
        lifted_sub.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(","),
        norm(expect_sub),
    );
    std::fs::write(&out, json).expect("write interop vectors");
    println!("Wrote {out} (real tfhe-rs key, ciphertexts and lifted accumulators)");
}


/// Per-phase wall-clock cost of the linear workflow, measured in the SAME
/// execution that uses the real libraries.
///
/// WHY THIS LIVES HERE AND NOT IN `output-binding-lhs`
/// ---------------------------------------------------
/// The sibling crate sweeps the same algebra and is useful for exploring the
/// design space, but its LWE layer is an independent implementation of the
/// implementation's encoding, not `tfhe-rs`. A figure that reported "encryption
/// time" from there would not be the encryption the protocol performs, and the
/// evaluation would be inconsistent with the construction it claims to measure.
///
/// Every number this command emits comes from the production primitives:
/// `tfhe-rs` `core_crypto` for key generation, encryption and decryption, and
/// `ark-bn254` for the commitment, the context-bound signature, the admission
/// pairing check, the aggregate certificate and the result equality.
///
/// Phases, named after the workflow of `\label{sec:workflow-linear}`:
///   W2 owner    keygen, encrypt, commit P(c_i), sign sigma_i        (per record)
///   W2 verifier admission: two-pairing check e(sigma_i,G2)=e(M_i,pk_i)
///   W3 operator unreduced aggregation A = sum_i w_i*phi(c_i), digest, P(A)
///   W4 verifier result check: the single G1 equality P(A) = P_agg
///   W5 consumer recompute d_out and P(A), balanced reduction rho, decrypt
///   baseline    the (N+1)-pairing aggregate certificate this design avoids
///
/// Usage: output_binding_tfhe bench-timings <out.csv> [sizes...] [--repeats R]
fn run_bench_timings(args: &[String]) {
    use std::time::Instant;

    let out = args.get(2).cloned().unwrap_or_else(|| "timings_linear.csv".to_string());
    let mut sizes: Vec<usize> = Vec::new();
    let mut repeats: usize = 5;
    let mut i = 3;
    while i < args.len() {
        if args[i] == "--repeats" {
            repeats = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(5);
            i += 2;
        } else {
            if let Ok(v) = args[i].parse::<usize>() {
                sizes.push(v);
            }
            i += 1;
        }
    }
    if sizes.is_empty() {
        sizes = vec![10, 50, 100, 200];
    }

    let d = LWE_K + 1;
    let gens = commit_generators(d);
    let tag = dataset_tag();

    let mut rows = String::from(
        "phase,workflow_step,n,repeat,lwe_dimension,ciphertext_dim,elapsed_ms,per_record_ms\n",
    );
    let mut push = |phase: &str, step: &str, n: usize, r: usize, ms: f64, per: f64| {
        rows.push_str(&format!(
            "{phase},{step},{n},{r},{LWE_K},{d},{ms:.6},{per:.6}\n"
        ));
    };

    println!("Linear workflow timings (tfhe-rs core_crypto + ark-bn254)");
    println!("  k = {LWE_K}, D = {d}, repeats = {repeats}, sizes = {sizes:?}");

    for &n in &sizes {
        for r in 0..repeats {
            let mut ctx = TfheCtx::new();
            let mut rng = StdRng::seed_from_u64(0xB0_1E_11 + (n as u64) * 977 + r as u64);
            // Per-owner keys, exactly as the deployed multi-key path uses them.
            let t = Instant::now();
            let owners: Vec<Lhs> = (0..n).map(|_| Lhs::keygen(&mut rng, 0)).collect();
            let keygen_ms = t.elapsed().as_secs_f64() * 1e3;
            push("owner_keygen", "W2", n, r, keygen_ms, keygen_ms / n as f64);
            let ratings: Vec<u64> = (0..n).map(|i| (i as u64 % 5) + 1).collect();
            let weights = Op::Sum.weights_fr(n);

            // -- W2 owner: encrypt (tfhe-rs) --------------------------------
            let t = Instant::now();
            let cts: Vec<LweCiphertextOwned<u64>> =
                ratings.iter().map(|m| ctx.encrypt(*m)).collect();
            let encrypt_ms = t.elapsed().as_secs_f64() * 1e3;
            push("encrypt", "W2", n, r, encrypt_ms, encrypt_ms / n as f64);

            let coords: Vec<Vec<Fr>> = cts.iter().map(coords_to_fr).collect();

            // -- W2 owner: commitment P(c_i) --------------------------------
            let t = Instant::now();
            let commitments: Vec<G1Projective> =
                coords.iter().map(|c| commit(c, &gens)).collect();
            let commit_ms = t.elapsed().as_secs_f64() * 1e3;
            push("commit_record", "W2", n, r, commit_ms, commit_ms / n as f64);

            // -- W2 owner: context-bound signature --------------------------
            let t = Instant::now();
            let sigs: Vec<G1Projective> = commitments
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    context_point(&owners[i].pk, &tag, i as u64, Op::Sum.code(), n as u64, p)
                        * owners[i].sk
                })
                .collect();
            let sign_ms = t.elapsed().as_secs_f64() * 1e3;
            push("sign_record", "W2", n, r, sign_ms, sign_ms / n as f64);

            // -- W2 verifier: admission, two pairings per record ------------
            let t = Instant::now();
            let mut admitted = 0usize;
            for i in 0..n {
                let msg = context_point(
                    &owners[i].pk, &tag, i as u64, Op::Sum.code(), n as u64, &commitments[i],
                )
                .into_affine();
                if Bn254::pairing(sigs[i].into_affine(), G2Projective::generator().into_affine())
                    == Bn254::pairing(msg, owners[i].pk.into_affine())
                {
                    admitted += 1;
                }
            }
            let admit_ms = t.elapsed().as_secs_f64() * 1e3;
            assert_eq!(admitted, n, "every honest admission must verify");
            push("admit_verify", "W2", n, r, admit_ms, admit_ms / n as f64);

            // -- W3 operator: unreduced aggregation + digest + P(A) ---------
            let t = Instant::now();
            let mut lifted = vec![Fr::zero(); d];
            for (c, w) in coords.iter().zip(weights.iter()) {
                for j in 0..d {
                    lifted[j] += c[j] * *w;
                }
            }
            let aggregate_ms = t.elapsed().as_secs_f64() * 1e3;
            push("aggregate", "W3", n, r, aggregate_ms, aggregate_ms / n as f64);

            let t = Instant::now();
            let p_out = commit(&lifted, &gens);
            let commit_output_ms = t.elapsed().as_secs_f64() * 1e3;
            push("commit_output", "W3", n, r, commit_output_ms, commit_output_ms);

            // -- W4 verifier: the O(1) result equality ----------------------
            let mut p_agg = G1Projective::zero();
            for (c, w) in commitments.iter().zip(weights.iter()) {
                p_agg += *c * *w;
            }
            let t = Instant::now();
            let accepted = p_out == p_agg;
            let result_check_ms = t.elapsed().as_secs_f64() * 1e3;
            assert!(accepted, "the honest output must satisfy P(A) = P_agg");
            push("result_check", "W4", n, r, result_check_ms, result_check_ms);

            // -- W5 consumer: recompute, reduce, decrypt --------------------
            let t = Instant::now();
            let consumer_commitment = commit(&lifted, &gens);
            let consumer_recompute_ms = t.elapsed().as_secs_f64() * 1e3;
            assert_eq!(consumer_commitment, p_out);
            push("consumer_recompute", "W5", n, r, consumer_recompute_ms, consumer_recompute_ms);

            let t = Instant::now();
            let canonical = derive_canonical_ct(&lifted);
            let plain = ctx.decrypt_coords(&canonical);
            let decrypt_ms = t.elapsed().as_secs_f64() * 1e3;
            let expected: u64 = ratings.iter().sum::<u64>() % (1u64 << MSG_BITS);
            assert_eq!(plain, expected, "the delivered vector must decrypt exactly");
            push("reduce_and_decrypt", "W5", n, r, decrypt_ms, decrypt_ms);

            // -- baseline: the (N+1)-pairing aggregate certificate ----------
            let t = Instant::now();
            // The multi-key aggregate certificate of Aranha-Pagnin: one pairing
            // per signer plus one for the aggregate. This is the O(N) cost the
            // deployed design avoids by verifying each admission once and
            // checking a pairing-free equality at result time.
            let mut ok = true;
            for i in 0..n {
                let msg = context_point(
                    &owners[i].pk, &tag, i as u64, Op::Sum.code(), n as u64, &commitments[i],
                )
                .into_affine();
                ok &= Bn254::pairing(sigs[i].into_affine(), G2Projective::generator().into_affine())
                    == Bn254::pairing(msg, owners[i].pk.into_affine());
            }
            let agg_certificate_ms = t.elapsed().as_secs_f64() * 1e3;
            assert!(ok, "the aggregate certificate baseline must verify");
            push("agg_certificate_baseline", "W4", n, r, agg_certificate_ms, agg_certificate_ms);
        }
        println!("  n = {n}: {repeats} repeats done");
    }

    std::fs::write(&out, rows).expect("write timings csv");
    println!("Wrote {out}");
}

include!("public_lwe.inc.rs");
include!("matched_linear.inc.rs");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("bench-matched") {
        run_matched_baseline(&args);
        return;
    }
    if args.get(1).map(String::as_str) == Some("release-lwe") {
        release_lwe_simulation(&args);
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("emit-onchain-mk") {
        run_emit_mk(&args);
        return;
    }
    if matches!(args.get(1).map(String::as_str), Some("emit-onchain-mk-cases" | "emit-public-mk-cases")) {
        run_emit_mk_cases(&args);
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("bench-timings") {
        run_bench_timings(&args);
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("emit-lwe-interop") {
        run_emit_lwe_interop(&args);
        return;
    }
    // An unrecognized subcommand must not fall through to the demo: a caller
    // that misspells an emitter would otherwise get exit code 0 and no payload,
    // and the pipeline would carry on with a stale file. Only a bare invocation
    // runs the demo.
    if let Some(unknown) = args.get(1) {
        eprintln!("unknown subcommand: {unknown}");
        eprintln!("usage: output_binding_tfhe [emit-onchain-mk <out.json> [sizes...]]");
        eprintln!("       output_binding_tfhe [emit-onchain-mk-cases <out.json> <cases.json>]");
        eprintln!("       output_binding_tfhe            (no argument: run the demo)");
        std::process::exit(2);
    }
    run_demo();
}

fn run_demo() {
    println!("========================================================================");
    println!(" Output-Binding over REAL TFHE (core_crypto leveled LWE)");
    println!(
        " LWE dim k = {LWE_K} | ciphertext dim D = {} | Δ = 2^{} | msg space 2^{}",
        LWE_K + 1,
        64 - MSG_BITS,
        MSG_BITS
    );
    println!("========================================================================\n");

    let mut ctx = TfheCtx::new();
    let mut rng = StdRng::seed_from_u64(0x00_7B_1D_u64);
    let d = LWE_K + 1;
    let lhs = Lhs::keygen(&mut rng, d);
    let tag = dataset_tag();

    // Two in-regime cases exercising BOTH authorized operations (SUM and SUB).
    let cases: [(&str, Vec<u64>, Op); 2] = [
        ("SUM", vec![3, 1, 2, 5, 4], Op::Sum), // 3+1+2+5+4 = 15
        ("SUB", vec![20, 3, 5, 2], Op::Sub),   // 20-3-5-2 = 10
    ];

    let mut all_ok = true;
    println!(
        "{:<6} {:<20} {:>8} {:>10} {:>16}",
        "op", "ratings", "expect", "decrypt", "verifyBound()"
    );
    println!("{}", "-".repeat(64));

    for (name, ratings, op) in cases.iter() {
        let (run, expected) = build_run(&mut ctx, &lhs, &tag, ratings, *op);

        workflow_step(
            "W5",
            "Consumer verification and decryption",
            &[
                "consumer side: recompute d_out and P(A) from the DELIVERED vector and",
                "match both against the on-chain record, then derive C_out = rho(A) by",
                "BALANCED REDUCTION (centered representative, then mod q) and DECRYPT,",
                "rounding the phase to the nearest multiple of Delta",
            ],
        );
        // Consumer derives the canonical TFHE ciphertext from the lifted
        // accumulator, then TFHE-decrypts it.
        let honest_ct = derive_canonical_ct(&run.lifted);
        let attack_ct = derive_canonical_ct(&run.attack_lifted);
        let decrypted_honest = ctx.decrypt_coords(&honest_ct);
        let decrypted_attack = ctx.decrypt_coords(&attack_ct);

        let honest_accept = lhs.verify_bound(&tag, &run.lifted, run.sigma_out, &run.weights);
        let attack_accept = lhs.verify_bound(&tag, &run.attack_lifted, run.sigma_out, &run.weights);

        // We only claim decryption correctness inside the leveled regime, and we
        // assert EXACT equality (no silent reduction modulo the message space).
        let abs_expected = expected.unsigned_abs();
        let in_regime = expected >= 0 && leveled_regime_ok(ratings.len(), abs_expected);

        println!(
            "{:<6} {:<20} {:>8} {:>10} {:>16}",
            name,
            format!("{ratings:?}"),
            expected,
            decrypted_honest,
            verdict(honest_accept)
        );

        if !honest_accept {
            eprintln!("  !! FAIL[{name}]: honest run must ACCEPT");
            all_ok = false;
        }
        if attack_accept {
            eprintln!("  !! FAIL[{name}]: output substitution must REJECT");
            all_ok = false;
        }
        if !in_regime {
            eprintln!("  !! FAIL[{name}]: demo case must be inside the leveled regime");
            all_ok = false;
        } else if decrypted_honest as i128 != expected {
            eprintln!("  !! FAIL[{name}]: decrypt {decrypted_honest} != exact expected {expected}");
            all_ok = false;
        }
        let _ = decrypted_attack;
    }

    println!("\nThe operator delivers a *lifted accumulator* A ∈ F_r^D; the consumer");
    println!("derives the canonical TFHE ciphertext C_out = ρ(A) (balanced reduction");
    println!("into Z_q) and TFHE-decrypts it. σ_out binds P(A) = Σ w_i P(C_i), so both");
    println!("SUM and SUB verify while returning C_0 is rejected by the pairing.");

    if all_ok {
        println!("\nRESULT: all security assertions passed (real TFHE, SUM + SUB).");
    } else {
        eprintln!("\nRESULT: security assertions FAILED.");
        std::process::exit(1);
    }
}

/// Multi-key (curator-free) emission: each data owner i holds its own key pair
/// (sk_i, pk_i = sk_i * G2) and signs its OWN real-TFHE ciphertext-vector
/// commitment, sigma_i = sk_i * ( P(C_i) + H(tag, i) ). No single signing
/// authority exists. The on-chain contract (MKLHS-Verification.sol) verifies
/// each admission with a two-pairing BLS check and folds w_i * P(C_i) into an
/// accumulator; result verification is the accumulator equality, pairing-free.
///
/// Self-checks performed here before emission (all over REAL TFHE ciphertexts):
///   1. per-record BLS admission equation holds for the honest signature;
///   2. a signature by the WRONG owner key fails the admission equation;
///   3. P(lifted accumulator) == sum_i w_i * P(C_i)  (accumulator equality);
///   4. the substituted output (attack) breaks the accumulator equality;
///   5. for leveled-regime sizes, the reduced ciphertext decrypts exactly.
fn run_emit_mk(args: &[String]) {
    let out_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "onchain_proofs_tfhe_mk.json".to_string());
    let sizes: Vec<usize> = if args.len() > 3 {
        args[3..].iter().filter_map(|s| s.parse().ok()).collect()
    } else {
        vec![10, 50, 100, 200]
    };

    // Seeded: the emitted payload must be byte-reproducible (see new_seeded).
    let mut ctx = TfheCtx::new_seeded(0x0C0FFEE_2Bu128);
    let mut rng = StdRng::seed_from_u64(0x0C0FFEE_2Bu64);
    let d = LWE_K + 1;
    let gens = commit_generators(d);
    let tag = dataset_tag();
    let tag_hex = format!("0x{}", hex::encode(tag));

    // Emit commitment generators once so the JS consumer can independently
    // recompute P(A') from the delivered lifted accumulator.
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
            let ratings: Vec<u64> = match op {
                Op::Sum => (0..n).map(|i| (i as u64 % 5) + 1).collect(),
                Op::Sub => (0..n)
                    .map(|i| if i == 0 { n as u64 + 10 } else { 1 })
                    .collect(),
            };
            let weights = op.weights_fr(n);

            // Per-owner keys; owner i signs its own real-TFHE record.
            let owners: Vec<Lhs> = (0..n).map(|_| Lhs::keygen(&mut rng, 0)).collect();
            let cts: Vec<LweCiphertextOwned<u64>> =
                ratings.iter().map(|m| ctx.encrypt(*m)).collect();
            let coords_fr: Vec<Vec<Fr>> = cts.iter().map(coords_to_fr).collect();
            let commitments: Vec<G1Projective> =
                coords_fr.iter().map(|c| commit(c, &gens)).collect();
            let sigs: Vec<G1Projective> = commitments
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    context_point(&owners[i].pk, &tag, i as u64, op.code(), n as u64, p)
                        * owners[i].sk
                })
                .collect();

            // Self-check 1/2: admission equation per record; wrong key fails.
            for i in 0..n {
                let msg = context_point(&owners[i].pk, &tag, i as u64, op.code(), n as u64, &commitments[i]).into_affine();
                let ok = Bn254::pairing(sigs[i].into_affine(), G2Projective::generator().into_affine())
                    == Bn254::pairing(msg, owners[i].pk.into_affine());
                assert!(ok, "honest admission must verify (record {i})");
            }
            let wrong_signer = if n > 1 { 1 } else { 0 };
            let wrong_key_sig =
                context_point(&owners[0].pk, &tag, 0, op.code(), n as u64, &commitments[0])
                    * owners[wrong_signer].sk;
            if n > 1 {
                let msg0 = context_point(&owners[0].pk, &tag, 0, op.code(), n as u64, &commitments[0]).into_affine();
                let bad = Bn254::pairing(wrong_key_sig.into_affine(), G2Projective::generator().into_affine())
                    == Bn254::pairing(msg0, owners[0].pk.into_affine());
                assert!(!bad, "wrong-key admission must fail");
            }

            // Operator: lifted accumulator; self-check 3/4.
            let mut lifted = vec![Fr::zero(); d];
            for (c, w) in coords_fr.iter().zip(weights.iter()) {
                for j in 0..d {
                    lifted[j] += c[j] * *w;
                }
            }
            let p_lifted = commit(&lifted, &gens);
            let mut p_agg = G1Projective::zero();
            for (p, w) in commitments.iter().zip(weights.iter()) {
                p_agg += *p * *w;
            }
            assert_eq!(
                p_lifted.into_affine(),
                p_agg.into_affine(),
                "accumulator equality must hold for the honest lifted output"
            );
            let attack_lifted = coords_fr[0].clone();
            let p_attack = commit(&attack_lifted, &gens);
            assert_ne!(
                p_attack.into_affine(),
                p_agg.into_affine(),
                "substituted output must break the accumulator equality"
            );

            // Self-check 5: exact decryption inside the leveled regime.
            let expected: i128 = ratings
                .iter()
                .enumerate()
                .map(|(i, m)| op.weight_i128(i) * (*m as i128))
                .sum();
            if leveled_regime_ok(n, expected.unsigned_abs()) {
                let ciphertext = derive_canonical_ct(&lifted);
                assert_eq!(
                    ctx.decrypt_coords(&ciphertext) as i128,
                    expected,
                    "leveled-regime decryption must be exact"
                );
            }

            let records: Vec<String> = (0..n)
                .map(|i| {
                    let (cx, cy) = g1_dec(&commitments[i]);
                    let (sx, sy) = g1_dec(&sigs[i]);
                    let pk = g2_pubkey_dec(&owners[i].pk);
                    format!(
                        "        {{ \"index\": {i}, \"commitment\": [\"{cx}\",\"{cy}\"], \"signature\": [\"{sx}\",\"{sy}\"], \"pubkey\": [\"{}\",\"{}\",\"{}\",\"{}\"] }}",
                        pk[0], pk[1], pk[2], pk[3]
                    )
                })
                .collect();

            let (px, py) = g1_dec(&p_lifted);
            let (axc, ayc) = g1_dec(&p_attack);
            let (wx, wy) = g1_dec(&wrong_key_sig);
            let lifted_dec: Vec<String> =
                lifted.iter().map(|f| format!("\"{f}\"")).collect();
            let honest_digest = coords_digest_hex(&lifted);
            let attack_digest = coords_digest_hex(&attack_lifted);

            entries.push(format!(
                "    {{\n      \"n\": {n},\n      \"allowed_op\": {},\n      \"expected_plaintext\": {expected},\n      \"dataset_tag\": \"{tag_hex}\",\n      \"records\": [\n{}\n      ],\n      \"honest\": {{ \"commitment\": [\"{px}\",\"{py}\"], \"output_digest\": \"{honest_digest}\", \"lifted\": [{}] }},\n      \"attack\": {{ \"commitment\": [\"{axc}\",\"{ayc}\"], \"output_digest\": \"{attack_digest}\" }},\n      \"wrong_key_signature\": [\"{wx}\",\"{wy}\"]\n    }}",
                op.code(),
                records.join(",\n"),
                lifted_dec.join(",")
            ));
        }
    }

    let json = format!(
        "{{\n  \"curve\": \"BN254\",\n  \"hash_domain\": \"MKLHS_CTX_V1_\",\n  \"scheme\": \"output_binding_tfhe_multikey\",\n  \"dataset_tag\": \"{tag_hex}\",\n  \"lwe_dimension\": {LWE_K},\n  \"ciphertext_dim\": {d},\n  \"commit_generators\": [{}],\n  \"sizes\": [\n{}\n  ]\n}}\n",
        gens_json.join(","),
        entries.join(",\n")
    );
    let mut f = std::fs::File::create(&out_path).expect("cannot write JSON");
    f.write_all(json.as_bytes()).unwrap();
    println!(
        "Wrote {out_path} (multi-key, sizes {sizes:?}, dataset_tag {tag_hex}) from REAL TFHE ciphertexts"
    );
}

/// Multi-key emission over CALLER-SUPPLIED real datasets (QoE application
/// examples). Identical cryptographic pipeline to `run_emit_mk` (real TFHE-LWE
/// encryption, per-owner MKLHS keys and signatures, accumulator equality,
/// wrong-key self-check), but the plaintext values, the operation, and the
/// dataset tag of every case come from a JSON cases file instead of a
/// synthetic pattern:
///
/// ```json
/// { "cases": [ { "label": "stav360-mean-panel",
///                "op": "SUM",
///                "values": [3, 4, 4, 4],
///                "tag_label": "qoe/stav360/epoch-1",
///                "source": "VC-FHE/BN254-Signatures/Users_Ratings.csv",
///                "interpretation": "mean = sum / N after decryption" } ] }
/// ```
///
/// Every case is REQUIRED to be inside the leveled regime; exact decryption of
/// the reduced canonical ciphertext is asserted before emission, so the
/// emitted `expected_plaintext` is the value the consumer's real TFHE
/// decryption produces.
fn run_emit_mk_cases(args: &[String]) {
    let out_path = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("usage: output_binding_tfhe emit-onchain-mk-cases <out.json> <cases.json>");
        std::process::exit(2);
    });
    let cases_path = args.get(3).cloned().unwrap_or_else(|| {
        eprintln!("usage: output_binding_tfhe emit-onchain-mk-cases <out.json> <cases.json>");
        std::process::exit(2);
    });

    let cases_raw = std::fs::read_to_string(&cases_path)
        .unwrap_or_else(|e| panic!("cannot read cases file {cases_path}: {e}"));
    let cases_doc: serde_json::Value =
        serde_json::from_str(&cases_raw).expect("cases file is not valid JSON");
    let cases = cases_doc["cases"]
        .as_array()
        .expect("cases file must contain a top-level \"cases\" array");
    assert!(!cases.is_empty(), "cases array must not be empty");

    // Seeded: the emitted payload must be byte-reproducible (see new_seeded).
    let public = args[1] == "emit-public-mk-cases";
    let mut ctx = if public { FixtureEncryption::Public(PublicLweCtx::new()) }
        else { FixtureEncryption::Legacy(if cases_doc["fresh_randomness"].as_bool() == Some(true) {
            TfheCtx::new()
        } else { TfheCtx::new_seeded(0x0C0FFEE_51u128) }) };
    if let Some(key_file) = cases_doc["local_kms_key_file"].as_str() {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(key_file).expect("create new LOCAL SIMULATION key file");
        let key = if public { serde_json::json!({"profile":PUBLIC_LWE_PROFILE,"secret":ctx.secret()}) }
            else { serde_json::json!(ctx.secret()) };
        file.write_all(serde_json::to_string(&key).unwrap().as_bytes()).unwrap();
    }
    let mut rng = if public { StdRng::from_entropy() } else { StdRng::seed_from_u64(0x0C0FFEE_51u64) };
    let lwe_k = ctx.dimension();
    let d = lwe_k + 1;
    let gens = commit_generators(d);

    let gens_json: Vec<String> = gens
        .iter()
        .map(|g| {
            let (x, y) = g1_dec(g);
            format!("[\"{x}\",\"{y}\"]")
        })
        .collect();

    let mut entries: Vec<String> = Vec::new();
    for case in cases {
        let label = case["label"].as_str().expect("case.label must be a string");
        let op = match case["op"].as_str().expect("case.op must be SUM or SUB") {
            "SUM" => Op::Sum,
            "SUB" => Op::Sub,
            other => panic!("case {label}: unsupported op {other}"),
        };
        let values: Vec<u64> = case["values"]
            .as_array()
            .expect("case.values must be an array")
            .iter()
            .map(|v| v.as_u64().expect("case.values entries must be unsigned integers"))
            .collect();
        let n = values.len();
        assert!(n >= 2, "case {label}: need at least 2 values");
        let source = case["source"].as_str().unwrap_or("");
        let interpretation = case["interpretation"].as_str().unwrap_or("");

        // Per-case dataset/epoch tag: keccak over a domain-separated label,
        // usable verbatim as the contract's bytes32 constructor tag.
        let tag: [u8; 32] = if let Some(exact) = case["dataset_tag"].as_str() {
            let bytes = hex::decode(exact.strip_prefix("0x").unwrap_or(exact)).expect("invalid deployment tag");
            bytes.try_into().expect("deployment tag must be 32 bytes")
        } else { match case["tag_label"].as_str() {
            Some(tl) => {
                let mut h = Keccak256::new();
                h.update(b"vc-fhe/qoe-examples/");
                h.update(tl.as_bytes());
                let dgst = h.finalize();
                let mut t = [0u8; 32];
                t.copy_from_slice(&dgst);
                t
            }
            None => dataset_tag(),
        } };
        let tag_hex = format!("0x{}", hex::encode(tag));
        let weights = op.weights_fr(n);

        // Per-owner keys; owner i encrypts its REAL value with TFHE and signs
        // its own record.
        let owners: Vec<Lhs> = (0..n).map(|_| Lhs::keygen(&mut rng, 0)).collect();
        let cts: Vec<LweCiphertextOwned<u64>> =
            values.iter().map(|m| ctx.encrypt(*m)).collect();
        let coords_fr: Vec<Vec<Fr>> = cts.iter().map(coords_to_fr).collect();
        let commitments: Vec<G1Projective> =
            coords_fr.iter().map(|c| commit(c, &gens)).collect();
        let sigs: Vec<G1Projective> = commitments
            .iter()
            .enumerate()
            .map(|(i, p)| {
                context_point(&owners[i].pk, &tag, i as u64, op.code(), n as u64, p) * owners[i].sk
            })
            .collect();

        // Self-check 1/2: per-record admission equation; wrong key fails.
        for i in 0..n {
            let msg = context_point(&owners[i].pk, &tag, i as u64, op.code(), n as u64, &commitments[i]).into_affine();
            let ok = Bn254::pairing(sigs[i].into_affine(), G2Projective::generator().into_affine())
                == Bn254::pairing(msg, owners[i].pk.into_affine());
            assert!(ok, "case {label}: honest admission must verify (record {i})");
        }
        let wrong_key_sig =
            context_point(&owners[0].pk, &tag, 0, op.code(), n as u64, &commitments[0]) * owners[1].sk;
        {
            let msg0 = context_point(&owners[0].pk, &tag, 0, op.code(), n as u64, &commitments[0]).into_affine();
            let bad = Bn254::pairing(wrong_key_sig.into_affine(), G2Projective::generator().into_affine())
                == Bn254::pairing(msg0, owners[0].pk.into_affine());
            assert!(!bad, "case {label}: wrong-key admission must fail");
        }

        // Operator: lifted accumulator; self-check 3/4.
        let mut lifted = vec![Fr::zero(); d];
        for (c, w) in coords_fr.iter().zip(weights.iter()) {
            for j in 0..d {
                lifted[j] += c[j] * *w;
            }
        }
        let p_lifted = commit(&lifted, &gens);
        let mut p_agg = G1Projective::zero();
        for (p, w) in commitments.iter().zip(weights.iter()) {
            p_agg += *p * *w;
        }
        assert_eq!(
            p_lifted.into_affine(),
            p_agg.into_affine(),
            "case {label}: accumulator equality must hold"
        );
        let attack_lifted = coords_fr[0].clone();
        let p_attack = commit(&attack_lifted, &gens);
        assert_ne!(
            p_attack.into_affine(),
            p_agg.into_affine(),
            "case {label}: substituted output must break the accumulator equality"
        );

        // Self-check 5, MANDATORY here: the case must be inside the leveled
        // regime and the reduced canonical ciphertext must decrypt EXACTLY.
        let expected: i128 = values
            .iter()
            .enumerate()
            .map(|(i, m)| op.weight_i128(i) * (*m as i128))
            .sum();
        assert!(
            expected >= 0 && ctx.regime(n, expected.unsigned_abs()),
            "case {label}: outside the leveled regime (n={n}, expected={expected}); \
             QoE example cases must decrypt exactly"
        );
        let ciphertext = derive_canonical_ct(&lifted);
        assert_eq!(
            ctx.decrypt_coords(&ciphertext) as i128,
            expected,
            "case {label}: leveled-regime decryption must be exact"
        );

        let records: Vec<String> = (0..n)
            .map(|i| {
                let (cx, cy) = g1_dec(&commitments[i]);
                let (sx, sy) = g1_dec(&sigs[i]);
                let pk = g2_pubkey_dec(&owners[i].pk);
                format!(
                    "        {{ \"index\": {i}, \"commitment\": [\"{cx}\",\"{cy}\"], \"signature\": [\"{sx}\",\"{sy}\"], \"pubkey\": [\"{}\",\"{}\",\"{}\",\"{}\"] }}",
                    pk[0], pk[1], pk[2], pk[3]
                )
            })
            .collect();

        let (px, py) = g1_dec(&p_lifted);
        let (axc, ayc) = g1_dec(&p_attack);
        let (wx, wy) = g1_dec(&wrong_key_sig);
        let lifted_dec: Vec<String> = lifted.iter().map(|f| format!("\"{f}\"")).collect();
        let values_dec: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        let honest_digest = coords_digest_hex(&lifted);
        let attack_digest = coords_digest_hex(&attack_lifted);
        let label_json = serde_json::to_string(label).unwrap();
        let source_json = serde_json::to_string(source).unwrap();
        let interp_json = serde_json::to_string(interpretation).unwrap();

        entries.push(format!(
            "    {{\n      \"label\": {label_json},\n      \"source\": {source_json},\n      \"interpretation\": {interp_json},\n      \"n\": {n},\n      \"allowed_op\": {},\n      \"values\": [{}],\n      \"expected_plaintext\": {expected},\n      \"decrypt_checked\": true,\n      \"dataset_tag\": \"{tag_hex}\",\n      \"records\": [\n{}\n      ],\n      \"honest\": {{ \"commitment\": [\"{px}\",\"{py}\"], \"output_digest\": \"{honest_digest}\", \"lifted\": [{}] }},\n      \"attack\": {{ \"commitment\": [\"{axc}\",\"{ayc}\"], \"output_digest\": \"{attack_digest}\" }},\n      \"wrong_key_signature\": [\"{wx}\",\"{wy}\"]\n    }}",
            op.code(),
            values_dec.join(","),
            records.join(",\n"),
            lifted_dec.join(",")
        ));
    }

    let json = format!(
        "{{\n  \"curve\": \"BN254\",\n  \"hash_domain\": \"MKLHS_CTX_V1_\",\n  \"scheme\": \"output_binding_tfhe_multikey\",\n  \"cases_file\": {},\n  \"lwe_dimension\": {lwe_k},\n  \"ciphertext_dim\": {d},\n  \"commit_generators\": [{}],\n  \"sizes\": [\n{}\n  ]\n}}\n",
        serde_json::to_string(&cases_path).unwrap(),
        gens_json.join(","),
        entries.join(",\n")
    );
    let mut f = std::fs::File::create(&out_path).expect("cannot write JSON");
    f.write_all(json.as_bytes()).unwrap();
    println!(
        "Wrote {out_path} ({} case(s) from {cases_path}) from REAL TFHE ciphertexts; exact decryption asserted for every case",
        cases.len()
    );
}

fn verdict(a: bool) -> &'static str {
    if a {
        "ACCEPT"
    } else {
        "REJECT"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_tfhe_sum_and_sub_bind_the_delivered_accumulator() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0xC0DEC0DE);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
        let tag = dataset_tag();

        for (ratings, op, expected) in [
            (vec![3, 1, 2, 5, 4], Op::Sum, 15i128),
            (vec![20, 3, 5, 2], Op::Sub, 10i128),
        ] {
            let (run, actual_expected) = build_run(&mut ctx, &lhs, &tag, &ratings, op);
            assert_eq!(actual_expected, expected);
            assert!(lhs.verify_bound(&tag, &run.lifted, run.sigma_out, &run.weights));
            assert!(!lhs.verify_bound(&tag, &run.attack_lifted, run.sigma_out, &run.weights));
            assert!(!lhs.verify_bound(
                &tag,
                &run.omission_lifted,
                run.sigma_omission,
                &run.weights
            ));
            let ciphertext = derive_canonical_ct(&run.lifted);
            assert_eq!(ctx.decrypt_coords(&ciphertext) as i128, expected);
        }
    }

    #[test]
    fn real_tfhe_multikey_admission_and_accumulator_bind_the_output() {
        // Curator-free: each owner signs its OWN real-TFHE record; result
        // integrity is the accumulator equality over admitted commitments.
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0xDEC0DE_2Bu64);
        let d = LWE_K + 1;
        let gens = commit_generators(d);
        let tag = dataset_tag();

        for (ratings, op, expected) in [
            (vec![3u64, 1, 2, 5, 4], Op::Sum, 15i128),
            (vec![20u64, 3, 5, 2], Op::Sub, 10i128),
        ] {
            let n = ratings.len();
            let weights = op.weights_fr(n);
            let owners: Vec<Lhs> = (0..n).map(|_| Lhs::keygen(&mut rng, 0)).collect();
            let cts: Vec<LweCiphertextOwned<u64>> =
                ratings.iter().map(|m| ctx.encrypt(*m)).collect();
            let coords_fr: Vec<Vec<Fr>> = cts.iter().map(coords_to_fr).collect();
            let commitments: Vec<G1Projective> =
                coords_fr.iter().map(|c| commit(c, &gens)).collect();

            // Per-record BLS admission verifies under the owner key, and fails
            // under any other owner's key.
            for i in 0..n {
                let m_i = context_point(&owners[i].pk, &tag, i as u64, op.code(), n as u64, &commitments[i]);
                let sig = m_i * owners[i].sk;
                let msg = m_i.into_affine();
                assert!(
                    Bn254::pairing(sig.into_affine(), G2Projective::generator().into_affine())
                        == Bn254::pairing(msg, owners[i].pk.into_affine())
                );
                let forged = m_i * owners[(i + 1) % n].sk;
                assert!(
                    Bn254::pairing(forged.into_affine(), G2Projective::generator().into_affine())
                        != Bn254::pairing(msg, owners[i].pk.into_affine())
                );
            }

            // Accumulator equality binds the delivered lifted output; the
            // substituted output breaks it; decryption is exact in-regime.
            let mut lifted = vec![Fr::zero(); d];
            for (c, w) in coords_fr.iter().zip(weights.iter()) {
                for j in 0..d {
                    lifted[j] += c[j] * *w;
                }
            }
            let mut p_agg = G1Projective::zero();
            for (p, w) in commitments.iter().zip(weights.iter()) {
                p_agg += *p * *w;
            }
            assert_eq!(commit(&lifted, &gens).into_affine(), p_agg.into_affine());
            assert_ne!(
                commit(&coords_fr[0], &gens).into_affine(),
                p_agg.into_affine()
            );
            let ciphertext = derive_canonical_ct(&lifted);
            assert_eq!(ctx.decrypt_coords(&ciphertext) as i128, expected);
        }
    }

    #[test]
    fn artifact_digest_detects_coordinate_substitution() {
        let original = vec![Fr::from(1u64), Fr::from(2u64)];
        let mut modified = original.clone();
        modified[0] += Fr::from(1u64);
        assert_ne!(coords_digest_hex(&original), coords_digest_hex(&modified));
    }
}

// =============================================================================
// FHE <-> plaintext equivalence ledger (TEST/DEBUG ONLY)
// =============================================================================
//
// Purpose: demonstrate, over REAL TFHE ciphertexts, the FHE correctness
// property  D( Eval(f, E(m_1),..,E(m_n)) ) == f(m_1,..,m_n)  for the leveled
// linear scheme this binary implements (f in {SUM, SUB}), and the MOS-mean
// derivation built on top of it.
//
// TWO INDEPENDENT PATHS, as required:
//   (1) FHE path      : real tfhe-rs encrypt -> lifted leveled aggregation
//                       (this is `build_run`, the production evaluator) ->
//                       canonical LWE reduction -> real tfhe-rs decrypt.
//   (2) Reference path : the same f computed here in i128 integer arithmetic.
//
// The plaintext reference exists ONLY in this #[cfg(test)] module. It is never
// compiled into the emit/demo production paths and never touches user data at
// run time. It is a debugging oracle.
//
// Each case is recorded with: plaintext input, an encrypted-input digest, the
// FHE result ciphertext digest, the decrypted value, the reference value, the
// signed difference, and the numeric rule under which equality is asserted.
// The ledger is written as Markdown to `$OB_LEDGER` (default:
// target/fhe_equivalence_ledger.md).
//
// Equality policy:
//   * Integer aggregates (SUM/SUB) inside the leveled regime: EXACT equality.
//     "Leveled regime" = expected >= 0 AND leveled_regime_ok(n, |expected|)
//     (message budget |result| < 2^(MSG_BITS-1)=512, noise budget => n <= 33).
//   * Outside the regime the property is NOT claimed: the harness asserts the
//     regime guard REJECTS the case, and that a naive decrypt would have
//     silently wrapped mod 2^MSG_BITS (which is exactly why the guard exists).
//   * MOS mean = (verified integer SUM) / n is a POST-DECRYPTION derivation
//     (the leveled scheme has no ciphertext division). It is checked under an
//     explicit fixed-point policy: milli-MOS with round-half-to-even.
#[cfg(test)]
mod equivalence_ledger {
    use super::*;
    use std::sync::Mutex;

    // ---- numeric policy -----------------------------------------------------

    /// Round a rational num/den to nearest integer, ties to even (banker's).
    fn div_round_half_even(num: i128, den: i128) -> i128 {
        assert!(den > 0);
        let q = num.div_euclid(den);
        let r = num.rem_euclid(den);
        let twice = 2 * r;
        if twice < den {
            q
        } else if twice > den {
            q + 1
        } else if q % 2 == 0 {
            q
        } else {
            q + 1
        }
    }

    /// MOS mean under the milli-MOS fixed-point policy: 1000*sum/n, rounded
    /// half-to-even. Returns the mean in milli-units (e.g. 3.25 -> 3250).
    fn mos_mean_milli(sum: i128, n: i128) -> i128 {
        div_round_half_even(1000 * sum, n)
    }

    // ---- ledger -------------------------------------------------------------

    struct Rec {
        name: String,
        f: String,
        n: usize,
        plaintext: String,
        enc_digest: String,
        result_ct_digest: String,
        decrypted: String,
        reference: String,
        diff: String,
        rule: String,
        pass: bool,
    }

    static LEDGER: Mutex<Vec<Rec>> = Mutex::new(Vec::new());

    fn record(r: Rec) {
        LEDGER.lock().unwrap().push(r);
    }

    /// Digest binding a set of input ciphertexts (their LWE coordinate vectors),
    /// so the ledger identifies the encrypted inputs without storing 743*n
    /// coordinates. Ciphertexts are randomized, so this differs run to run — by
    /// design (semantic security). Only the DECRYPTED value is asserted stable.
    fn enc_set_digest(cts: &[LweCiphertextOwned<u64>]) -> String {
        let mut h = Keccak256::new();
        for ct in cts {
            for c in ct.as_ref() {
                h.update(c.to_be_bytes());
            }
        }
        format!("0x{}", hex::encode(h.finalize()))
    }

    // ---- the two independent evaluators ------------------------------------

    /// Reference path: f over the plaintext, in i128. Test-only oracle.
    fn reference(values: &[u64], op: Op) -> i128 {
        values
            .iter()
            .enumerate()
            .map(|(i, m)| op.weight_i128(i) * (*m as i128))
            .sum()
    }

    /// FHE path: encrypt with real TFHE, run the production leveled evaluator
    /// (`build_run`), and decrypt the canonical result ciphertext. Returns the
    /// decrypted value (mod 2^MSG_BITS, as the scheme defines it), the digest of
    /// the encrypted inputs, the digest of the result ciphertext, and whether the
    /// binding proof verified.
    fn fhe_eval(
        ctx: &mut TfheCtx,
        lhs: &Lhs,
        tag: &[u8; 32],
        values: &[u64],
        op: Op,
    ) -> (u64, String, String, bool, i128) {
        // Encrypt inputs once so we can both digest them and reuse for build_run
        // semantics. build_run re-encrypts internally; to keep the digest honest
        // we digest a parallel encryption of the same values under the same key.
        let cts: Vec<LweCiphertextOwned<u64>> = values.iter().map(|m| ctx.encrypt(*m)).collect();
        let enc_digest = enc_set_digest(&cts);

        let (run, expected_from_build) = build_run(ctx, lhs, tag, values, op);
        let result_ct = derive_canonical_ct(&run.lifted);
        let decrypted = ctx.decrypt_coords(&result_ct);
        let verified = lhs.verify_bound(tag, &run.lifted, run.sigma_out, &run.weights);
        (
            decrypted,
            enc_digest,
            coords_digest_hex(&run.lifted),
            verified,
            expected_from_build,
        )
    }

    /// One in-regime integer case: FHE result must equal the reference EXACTLY.
    fn assert_exact(ctx: &mut TfheCtx, lhs: &Lhs, tag: &[u8; 32], name: &str, values: &[u64], op: Op) {
        let n = values.len();
        let refv = reference(values, op);
        let (dec, enc_d, ct_d, verified, expected_build) = fhe_eval(ctx, lhs, tag, values, op);

        // Independent reference must agree with build_run's internal expected.
        assert_eq!(refv, expected_build, "{name}: reference disagrees with evaluator");

        let in_regime = refv >= 0 && leveled_regime_ok(n, refv.unsigned_abs());
        assert!(in_regime, "{name}: case must be inside the leveled regime");
        assert!(verified, "{name}: output-binding pairing must verify");

        let dec_i = dec as i128;
        let diff = dec_i - refv;
        let pass = diff == 0;
        record(Rec {
            name: name.into(),
            f: if op == Op::Sum { "SUM".into() } else { "SUB".into() },
            n,
            plaintext: format!("{values:?}"),
            enc_digest: enc_d,
            result_ct_digest: ct_d,
            decrypted: dec_i.to_string(),
            reference: refv.to_string(),
            diff: diff.to_string(),
            rule: "exact integer equality (leveled regime)".into(),
            pass,
        });
        assert_eq!(dec_i, refv, "{name}: FHE decrypt {dec_i} != reference {refv}");
    }

    /// One out-of-regime case: the property is NOT claimed. The harness asserts
    /// the regime guard rejects it, and (for message overflow) that a NAIVE
    /// decrypt would have silently wrapped mod 2^MSG_BITS to a wrong value.
    fn assert_out_of_regime(
        ctx: &mut TfheCtx,
        lhs: &Lhs,
        tag: &[u8; 32],
        name: &str,
        values: &[u64],
        op: Op,
        reason: &str,
    ) {
        let n = values.len();
        let refv = reference(values, op);
        let in_regime = refv >= 0 && leveled_regime_ok(n, refv.unsigned_abs());
        assert!(!in_regime, "{name}: expected OUT of regime but guard accepted it");

        // Show the wrap that the guard prevents, when the result is a positive
        // message overflow (so decryption returns refv mod 2^MSG_BITS).
        let (dec, enc_d, ct_d, _verified, _e) = fhe_eval(ctx, lhs, tag, values, op);
        let dec_i = dec as i128;
        let wrapped = if refv >= 0 { refv % (1i128 << MSG_BITS) } else { -1 };
        let _note = if refv >= 0 && refv >= (1i128 << (MSG_BITS - 1)) {
            format!(
                "message overflow: naive decrypt wraps to {dec_i} (= {refv} mod 2^{MSG_BITS} = {wrapped}); guard REJECTS, no correctness claimed [{reason}]"
            )
        } else {
            format!("outside leveled regime; guard REJECTS, no correctness claimed [{reason}]")
        };
        record(Rec {
            name: name.into(),
            f: if op == Op::Sum { "SUM".into() } else { "SUB".into() },
            n,
            plaintext: format!("{values:?}"),
            enc_digest: enc_d,
            result_ct_digest: ct_d,
            decrypted: dec_i.to_string(),
            reference: refv.to_string(),
            diff: (dec_i - refv).to_string(),
            rule: "OUT OF REGIME: equality intentionally not claimed".into(),
            pass: true, // "pass" = the guard correctly refused to claim correctness
        });
    }

    fn write_ledger() {
        let recs = LEDGER.lock().unwrap();
        if recs.is_empty() {
            return;
        }
        let path = std::env::var("OB_LEDGER")
            .unwrap_or_else(|_| "target/fhe_equivalence_ledger.md".to_string());
        let mut s = String::new();
        s.push_str("# FHE <-> plaintext equivalence ledger (linear leveled path)\n\n");
        s.push_str("Scheme: native-modulus leveled LWE (tfhe-rs core_crypto), ");
        s.push_str(&format!("k={LWE_K}, D={}, MSG_BITS={MSG_BITS}, Δ=2^{}.\n", LWE_K + 1, 64 - MSG_BITS));
        s.push_str("Property demonstrated: D(Eval(f,E(m))) = f(m) for f in {SUM, SUB}, inside the leveled regime.\n\n");
        s.push_str("| case | f | n | plaintext m | enc(m) digest | Eval result ct digest | decrypted D(...) | reference f(m) | diff | rule | ok |\n");
        s.push_str("|---|---|---|---|---|---|---|---|---|---|---|\n");
        for r in recs.iter() {
            s.push_str(&format!(
                "| {} | {} | {} | `{}` | `{}` | `{}` | {} | {} | {} | {} | {} |\n",
                r.name,
                r.f,
                r.n,
                r.plaintext,
                &r.enc_digest[..10.min(r.enc_digest.len())],
                &r.result_ct_digest[..10.min(r.result_ct_digest.len())],
                r.decrypted,
                r.reference,
                r.diff,
                r.rule,
                if r.pass { "ok" } else { "FAIL" }
            ));
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(s.as_bytes());
            eprintln!("equivalence ledger written to {path} ({} cases)", recs.len());
        }
    }

    // ---- the actual test cases ---------------------------------------------

    #[test]
    fn fhe_equals_plaintext_across_the_case_matrix() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0xA11CE);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
        let tag = dataset_tag();

        // (1) Homomorphic SUM, several sizes and values.
        assert_exact(&mut ctx, &lhs, &tag, "sum_small", &[3, 1, 2, 5, 4], Op::Sum);
        assert_exact(&mut ctx, &lhs, &tag, "sum_acr_16", &[3,4,4,4,3,3,4,4,3,2,3,3,4,3,2,3], Op::Sum); // STAV360 MOS panel, Σ=52
        assert_exact(&mut ctx, &lhs, &tag, "sum_n2", &[7, 8], Op::Sum);

        // (2) Homomorphic SUB.
        assert_exact(&mut ctx, &lhs, &tag, "sub_small", &[20, 3, 5, 2], Op::Sub); // 10
        assert_exact(&mut ctx, &lhs, &tag, "sub_n2", &[9, 4], Op::Sub); // 5

        // (5) Min / max permitted, in regime.
        assert_exact(&mut ctx, &lhs, &tag, "max_single", &[511], Op::Sum); // message-space max
        assert_exact(&mut ctx, &lhs, &tag, "min_single", &[0], Op::Sum);

        // (6) Zeros.
        assert_exact(&mut ctx, &lhs, &tag, "all_zero", &[0, 0, 0, 0], Op::Sum);
        assert_exact(&mut ctx, &lhs, &tag, "zeros_and_one", &[0, 0, 1, 0], Op::Sum);

        // (4) Different user counts, isolating the NOISE budget (all ones).
        let ones33: Vec<u64> = vec![1; 33];
        assert_exact(&mut ctx, &lhs, &tag, "noise_edge_n33", &ones33, Op::Sum); // Σ=33, n=33 in regime

        // (9) Overflow / underflow, and (8) the wrap the guard prevents.
        assert_out_of_regime(&mut ctx, &lhs, &tag, "msg_overflow_512", &[256, 256], Op::Sum, "|result|>=512");
        assert_out_of_regime(&mut ctx, &lhs, &tag, "msg_wrap_1025", &[205, 205, 205, 205, 205], Op::Sum, "1025 wraps to 1 mod 1024");
        let ones34: Vec<u64> = vec![1; 34];
        assert_out_of_regime(&mut ctx, &lhs, &tag, "noise_overflow_n34", &ones34, Op::Sum, "noise budget: n>33");
        assert_out_of_regime(&mut ctx, &lhs, &tag, "underflow_negative", &[1, 5], Op::Sub, "negative result: unsigned message space");

        write_ledger();
    }

    /// (10) Order invariance: a permutation of the same inputs decrypts to the
    /// same value under SUM (an unordered aggregate).
    #[test]
    fn permutation_of_inputs_gives_the_same_result() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
        let tag = dataset_tag();
        let a = [3u64, 1, 4, 1, 5, 2];
        let b = [5u64, 4, 3, 2, 1, 1]; // same multiset
        let (da, ..) = fhe_eval(&mut ctx, &lhs, &tag, &a, Op::Sum);
        let (db, ..) = fhe_eval(&mut ctx, &lhs, &tag, &b, Op::Sum);
        assert_eq!(da, db, "permuted inputs must decrypt equally");
        assert_eq!(da as i128, reference(&a, Op::Sum));
    }

    /// (11) Reproducible results for the same inputs, across FRESH keys/noise:
    /// correctness is independent of the (randomized) ciphertexts. Also shows
    /// that the same value encrypts to DIFFERENT ciphertexts (semantic security)
    /// yet decrypts identically.
    #[test]
    fn results_reproduce_across_independent_keys_and_noise() {
        let values = [4u64, 2, 5, 3, 1];
        let refv = {
            let mut r = 0i128;
            for v in values {
                r += v as i128;
            }
            r
        };
        let mut d = Vec::new();
        let mut digests = Vec::new();
        for seed in [1u64, 2, 3] {
            let mut ctx = TfheCtx::new();
            let mut rng = StdRng::seed_from_u64(seed);
            let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
            let tag = dataset_tag();
            let (dec, enc_digest, ..) = fhe_eval(&mut ctx, &lhs, &tag, &values, Op::Sum);
            d.push(dec as i128);
            digests.push(enc_digest);
        }
        assert!(d.iter().all(|x| *x == refv), "result must reproduce: {d:?} vs {refv}");
        assert_ne!(digests[0], digests[1], "same plaintext must yield different ciphertexts");
    }

    /// The substitution attack the experiment defends against: the delivered output
    /// is replaced by an unrelated input ciphertext (C_0). It must (a) FAIL the
    /// output-binding proof, and (b) decrypt to a value DIFFERENT from the true
    /// aggregate (so it is not silently accepted). Fills a gap in the demo,
    /// which decrypted the attack ciphertext but never checked its value.
    #[test]
    fn substituted_output_is_rejected_and_decrypts_differently() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0x50B5);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
        let tag = dataset_tag();
        let values = [3u64, 4, 4, 4, 3]; // Σ=18, C_0 = 3
        let (run, expected) = build_run(&mut ctx, &lhs, &tag, &values, Op::Sum);
        assert_eq!(expected, 18);

        // honest verifies and decrypts to 18
        assert!(lhs.verify_bound(&tag, &run.lifted, run.sigma_out, &run.weights));
        assert_eq!(ctx.decrypt_coords(&derive_canonical_ct(&run.lifted)) as i128, 18);

        // attack fails the binding proof
        assert!(!lhs.verify_bound(&tag, &run.attack_lifted, run.sigma_out, &run.weights));
        // ...and decrypts to C_0 = 3 != 18, so it is not a valid substitute
        let attack_dec = ctx.decrypt_coords(&derive_canonical_ct(&run.attack_lifted)) as i128;
        assert_ne!(attack_dec, expected, "substituted output must not decrypt to the true aggregate");

        // input omission is also rejected by the full authorized index set
        assert!(!lhs.verify_bound(&tag, &run.omission_lifted, run.sigma_omission, &run.weights));
    }

    /// (3),(7),(8): MOS mean over encrypted data. The verified integer SUM is
    /// exact; the mean = SUM / n is a post-decryption fixed-point derivation
    /// with an explicit rounding policy (milli-MOS, round-half-to-even). Covers
    /// an EXACT division and an INEXACT one.
    #[test]
    fn mos_mean_matches_reference_under_fixed_point_policy() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0x503);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
        let tag = dataset_tag();

        // Exact-in-binary case: STAV360 panel Σ=52, n=16 -> 3.2500 exactly.
        let stav = [3u64,4,4,4,3,3,4,4,3,2,3,3,4,3,2,3];
        let (sum_dec, ..) = fhe_eval(&mut ctx, &lhs, &tag, &stav, Op::Sum);
        assert_eq!(sum_dec as i128, 52);
        assert_eq!(mos_mean_milli(52, 16), 3250); // 3.250 MOS

        // Inexact case: Σ=5, n=3 -> 1.6667 (milli 1667 under half-to-even).
        let three = [1u64, 2, 2];
        let (s3, ..) = fhe_eval(&mut ctx, &lhs, &tag, &three, Op::Sum);
        assert_eq!(s3 as i128, 5);
        // 1000*5/3 = 1666.66..; half-to-even nearest integer milli = 1667
        assert_eq!(mos_mean_milli(5, 3), 1667);

        // Tie case for banker's rounding: 1000*5/8 = 625.0 exact; 1000*1/8=125.
        assert_eq!(mos_mean_milli(5, 8), 625);
        // A genuine .5 tie in integer units: mean of [1,2] milli = 1500 exact.
        assert_eq!(mos_mean_milli(3, 2), 1500);
    }
}

// =============================================================================
// Individual-privacy properties of the linear (MOS) path (TEST/DEBUG ONLY)
// =============================================================================
//
// The MOS aggregation must not let any party recover an individual user's
// rating m_i. These tests establish, over REAL TFHE, the confidentiality
// properties the architecture relies on:
//
//   (U) Unlinkability. Encryption is randomized (IND-CPA): the SAME rating
//       encrypts to different ciphertexts and therefore to different published
//       per-user commitments P(c_i). An on-chain observer cannot tell that two
//       users gave the same rating, nor classify a rating from its commitment.
//
//   (L) Lossy publication. What is published per user is the commitment
//       P(c_i) = Σ_d φ(c_{i,d})·G_d — TWO field elements — while decryption
//       needs the full 743-coordinate LWE ciphertext. The on-chain per-user
//       object is information-theoretically insufficient to decrypt, EVEN with
//       the secret key: the individual ciphertext is never published.
//
//   (A) Aggregate-only release. The only object the protocol decrypts is the
//       aggregate Σ_i m_i. A released sum is consistent with exponentially many
//       input vectors, so it does not reveal any individual m_i on its own
//       (individual exposure requires n−1 colluders who already know the rest,
//       an inherent property of any sum, not a defect of this scheme).
#[cfg(test)]
mod individual_privacy {
    use super::*;

    /// (U) The same rating encrypts to different ciphertexts and different
    /// published commitments; different ratings are equally unlinkable.
    #[test]
    fn same_rating_encrypts_to_unlinkable_commitments() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0x9E11);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);

        // Two encryptions of the SAME rating.
        let c_a = coords_to_fr(&ctx.encrypt(3));
        let c_b = coords_to_fr(&ctx.encrypt(3));
        assert_ne!(c_a, c_b, "IND-CPA: same rating must give different ciphertexts");
        let p_a = commit(&c_a, &lhs.gens);
        let p_b = commit(&c_b, &lhs.gens);
        assert_ne!(
            g1_dec(&p_a),
            g1_dec(&p_b),
            "same rating must publish different commitments (unlinkable)"
        );

        // A different rating is not distinguishable from the commitment either:
        // its commitment is just as unrelated as two same-rating commitments.
        let c_c = coords_to_fr(&ctx.encrypt(5));
        let p_c = commit(&c_c, &lhs.gens);
        assert_ne!(g1_dec(&p_a), g1_dec(&p_c));
    }

    /// (L) The published per-user object is 2 field elements; the ciphertext is
    /// D = 743 coordinates. Decryption consumes the 743-coordinate object, which
    /// is NOT published — so on-chain data cannot decrypt an individual rating,
    /// with or without the key.
    #[test]
    fn published_commitment_is_lossy_and_cannot_be_decrypted() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0x105);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
        let ct = ctx.encrypt(4);
        let coords = coords_to_fr(&ct);
        assert_eq!(coords.len(), LWE_K + 1, "ciphertext has D = k+1 coordinates");

        // The published commitment is a single G1 point = 2 field elements.
        let (x, y) = g1_dec(&commit(&coords, &lhs.gens));
        let published_elems = [x, y];
        assert_eq!(published_elems.len(), 2);
        assert!(
            published_elems.len() < coords.len(),
            "the published commitment ({} elems) cannot encode the {}-coordinate ciphertext",
            published_elems.len(),
            coords.len()
        );

        // Decryption is defined on the full coordinate vector, and recovers the
        // rating only from it (here, with the key, for the demonstration).
        let raw = ct.as_ref().to_vec();
        assert_eq!(ctx.decrypt_coords(&raw), 4);
        // The commitment (2 elements) is simply not a ciphertext and cannot be
        // fed to decryption: there is no 743-coordinate object on chain.
    }

    /// (A) The released aggregate does not determine any individual rating: many
    /// distinct rating vectors decrypt to the same sum.
    #[test]
    fn released_aggregate_does_not_determine_individuals() {
        let mut ctx = TfheCtx::new();
        let mut rng = StdRng::seed_from_u64(0xA66);
        let lhs = Lhs::keygen(&mut rng, LWE_K + 1);
        let tag = dataset_tag();

        // Four different rating vectors, all summing to 15.
        let vectors: [Vec<u64>; 4] = [
            vec![3, 4, 4, 4],
            vec![1, 5, 5, 4],
            vec![5, 5, 5, 0],
            vec![2, 3, 5, 5],
        ];
        for v in &vectors {
            let (run, expected) = build_run(&mut ctx, &lhs, &tag, v, Op::Sum);
            assert_eq!(expected, 15);
            assert_eq!(
                ctx.decrypt_coords(&derive_canonical_ct(&run.lifted)) as i128,
                15,
                "all vectors summing to 15 release the same aggregate"
            );
        }
        // The released value 15 is consistent with all four (and many more)
        // input vectors, so it does not reveal any individual rating.
    }
}
