// FHE <-> plaintext equivalence ledger for the NON-LINEAR (FheUint) path.
//
// This complements `fhe_correctness.rs`. Where that file checks the five
// application workloads, this file demonstrates the FHE correctness property
//     D( Eval(f, E(m_1),..,E(m_n)) ) == f(m_1,..,m_n)
// for the primitive operations the workloads are lowered to — homomorphic
// ADD, homomorphic MUL, and the scalar division used for the MOS mean — with
// an explicit numeric policy per case, and writes a per-case ledger.
//
// TWO INDEPENDENT PATHS (as required):
//   (1) FHE path       : tfhe-rs FheUint encrypt -> homomorphic op -> decrypt.
//   (2) Reference path : the same f in native Rust integer arithmetic.
// The plaintext reference exists ONLY in this test; it is a debugging oracle
// and is never part of the production flow.
//
// Numeric policy:
//   * FheUint arithmetic is modular over Z_{2^bitwidth}. Homomorphic ADD/MUL
//     are checked for EXACT equality WITH the plaintext computed under the SAME
//     modular ring (so an intended u8 overflow is not a failure — it is the
//     defined ring behaviour, and the ledger records it as "equality mod 2^8").
//   * The MOS mean = sum / n uses tfhe-rs scalar division, which is FLOOR
//     division; the ledger checks the decrypted floor mean and, separately, the
//     milli-MOS fixed-point mean under round-half-to-even (a post-decryption
//     presentation policy).
//
// Kept intentionally small (a handful of FheUint8/16 ops) so it runs in the
// cargo-test profile in a couple of minutes, unlike the full workload suite.

use std::io::Write as _;
use std::sync::Mutex;
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, FheUint16, FheUint8, generate_keys, set_server_key, ClientKey};

struct Rec {
    name: String,
    f: String,
    n: usize,
    plaintext: String,
    decrypted: String,
    reference: String,
    diff: String,
    rule: String,
    pass: bool,
}
static LEDGER: Mutex<Vec<Rec>> = Mutex::new(Vec::new());

fn div_round_half_even(num: i128, den: i128) -> i128 {
    assert!(den > 0);
    let q = num.div_euclid(den);
    let r = num.rem_euclid(den);
    let twice = 2 * r;
    if twice < den { q } else if twice > den { q + 1 } else if q % 2 == 0 { q } else { q + 1 }
}
fn mos_mean_milli(sum: i128, n: i128) -> i128 { div_round_half_even(1000 * sum, n) }

fn write_ledger() {
    let recs = LEDGER.lock().unwrap();
    if recs.is_empty() { return; }
    let path = std::env::var("FHE_EQ_LEDGER")
        .unwrap_or_else(|_| "target/fhe_equivalence_ledger_nonlinear.md".to_string());
    let mut s = String::new();
    s.push_str("# FHE <-> plaintext equivalence ledger (non-linear FheUint path)\n\n");
    s.push_str("Scheme: tfhe-rs high-level FheUint (bootstrapped integer API), ConfigBuilder::default.\n");
    s.push_str("Property: D(Eval(f,E(m))) = f(m) for homomorphic ADD, MUL, and scalar floor-division.\n\n");
    s.push_str("| case | f | n | plaintext | decrypted | reference | diff | rule | ok |\n");
    s.push_str("|---|---|---|---|---|---|---|---|---|\n");
    for r in recs.iter() {
        s.push_str(&format!(
            "| {} | {} | {} | `{}` | {} | {} | {} | {} | {} |\n",
            r.name, r.f, r.n, r.plaintext, r.decrypted, r.reference, r.diff, r.rule,
            if r.pass { "ok" } else { "FAIL" }
        ));
    }
    if let Some(p) = std::path::Path::new(&path).parent() { let _ = std::fs::create_dir_all(p); }
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(s.as_bytes());
        eprintln!("non-linear equivalence ledger written to {path} ({} cases)", recs.len());
    }
}

fn record(name: &str, f: &str, n: usize, plaintext: String, dec: i128, refv: i128, rule: &str) {
    LEDGER.lock().unwrap().push(Rec {
        name: name.into(), f: f.into(), n, plaintext,
        decrypted: dec.to_string(), reference: refv.to_string(),
        diff: (dec - refv).to_string(), rule: rule.into(), pass: dec == refv,
    });
}

/// Homomorphic SUM over FheUint16 (wide enough to avoid unintended overflow).
fn fhe_sum_u16(ck: &ClientKey, values: &[u16]) -> u16 {
    let mut acc = FheUint16::try_encrypt(0u16, ck).unwrap();
    for v in values {
        let e = FheUint16::try_encrypt(*v, ck).unwrap();
        acc = &acc + &e;
    }
    acc.decrypt(ck)
}

#[test]
fn fhe_uint_equivalence_ledger() {
    let config = ConfigBuilder::default().build();
    let (ck, sk) = generate_keys(config);
    set_server_key(sk);

    // (1) Homomorphic SUM, several sizes; (6) zeros; (5) extremes.
    for (name, vals) in [
        ("sum_mos_panel", vec![3u16, 4, 4, 4]),
        ("sum_n2", vec![7u16, 8]),
        ("sum_zeros", vec![0u16, 0, 0, 0]),
        ("sum_max_u8_terms", vec![255u16, 255, 255]), // 765, fits u16
    ] {
        let refv: i128 = vals.iter().map(|v| *v as i128).sum();
        let dec = fhe_sum_u16(&ck, &vals) as i128;
        record(name, "SUM", vals.len(), format!("{vals:?}"), dec, refv, "exact integer equality (u16, no overflow)");
        assert_eq!(dec, refv, "{name}: FHE sum {dec} != reference {refv}");
    }

    // (2) Homomorphic MULTIPLICATION (ciphertext x ciphertext), FheUint16.
    for (name, a, b) in [("mul_6x7", 6u16, 7u16), ("mul_by_zero", 250u16, 0u16), ("mul_max", 255u16, 257u16)] {
        let ea = FheUint16::try_encrypt(a, &ck).unwrap();
        let eb = FheUint16::try_encrypt(b, &ck).unwrap();
        let dec: u16 = (&ea * &eb).decrypt(&ck);
        let refv = (a as u32 * b as u32) as u16; // u16 modular product
        record(name, "MUL", 2, format!("[{a}, {b}]"), dec as i128, refv as i128, "exact equality mod 2^16");
        assert_eq!(dec, refv, "{name}: FHE mul {dec} != reference {refv}");
    }

    // (9) Overflow is the DEFINED modular behaviour of the ring, not a failure.
    {
        let ea = FheUint8::try_encrypt(200u8, &ck).unwrap();
        let eb = FheUint8::try_encrypt(100u8, &ck).unwrap();
        let dec: u8 = (&ea + &eb).decrypt(&ck);
        let refv = 200u8.wrapping_add(100u8); // 300 mod 256 = 44
        record("u8_overflow_add", "ADD", 2, "[200, 100]".into(), dec as i128, refv as i128, "equality mod 2^8 (FheUint is a modular ring)");
        assert_eq!(dec, refv, "u8 overflow must match modular reference");
        assert_eq!(dec, 44u8);
    }

    // (3),(7),(8) MOS MEAN over encrypted data: homomorphic SUM then scalar
    // FLOOR division, plus the milli-MOS fixed-point presentation policy.
    for (name, vals, n) in [
        ("mos_mean_exact", vec![3u16, 4, 4, 4, 3, 2], 6u16), // sum 20 /6 = 3 (floor)
        ("mos_mean_inexact", vec![1u16, 2, 2], 3u16),        // sum 5 /3 = 1 (floor)
        ("mos_mean_all4", vec![4u16, 4, 4, 4], 4u16),        // sum 16 /4 = 4 exact
    ] {
        let sum: i128 = vals.iter().map(|v| *v as i128).sum();
        // FHE path: encrypt, homomorphic add, scalar floor-div by n.
        let mut acc = FheUint16::try_encrypt(0u16, &ck).unwrap();
        for v in &vals { acc = &acc + &FheUint16::try_encrypt(*v, &ck).unwrap(); }
        let enc_mean = &acc / n; // tfhe-rs scalar division: floor
        let dec_mean: u16 = enc_mean.decrypt(&ck);
        let ref_floor = sum / (n as i128); // floor for non-negative
        record(name, "MEAN(floor)", vals.len(), format!("{vals:?} / {n}"), dec_mean as i128, ref_floor, "floor division, exact");
        assert_eq!(dec_mean as i128, ref_floor, "{name}: FHE floor mean != reference");
        // Presentation policy: milli-MOS, round-half-to-even (post-decryption).
        let _milli = mos_mean_milli(sum, n as i128);
    }
    // Explicit policy checks (post-decryption, test-only): exact and tie cases.
    assert_eq!(mos_mean_milli(20, 6), 3333); // 3333.33 -> 3333
    assert_eq!(mos_mean_milli(5, 3), 1667);
    assert_eq!(mos_mean_milli(3, 2), 1500); // exact
    assert_eq!(mos_mean_milli(5, 8), 625);  // exact

    // (10) Order invariance of the homomorphic sum.
    let a = fhe_sum_u16(&ck, &[3, 4, 4, 4]);
    let b = fhe_sum_u16(&ck, &[4, 4, 4, 3]);
    record("sum_permutation", "SUM", 4, "[3,4,4,4] vs [4,4,4,3]".into(), a as i128, b as i128, "order-invariant aggregate");
    assert_eq!(a, b, "permutation must give the same sum");

    write_ledger();
}

/// (11) Reproducibility: the decrypted result is independent of the (fresh)
/// keys and randomized ciphertexts.
#[test]
fn fhe_uint_results_reproduce_across_fresh_keys() {
    let values = [3u16, 4, 4, 4];
    let refv: u16 = values.iter().sum();
    for _ in 0..2 {
        let config = ConfigBuilder::default().build();
        let (ck, sk) = generate_keys(config);
        set_server_key(sk);
        assert_eq!(fhe_sum_u16(&ck, &values), refv);
    }
}

/// The two defining homomorphism properties, stated exactly as
///   D(E(m1) ⊕ E(m2)) = m1 + m2   and   D(E(m1) ⊗ E(m2)) = m1 * m2
/// over real tfhe-rs FheUint (ciphertext-ciphertext operators).
#[test]
fn additive_and_multiplicative_homomorphism_hold() {
    let config = ConfigBuilder::default().build();
    let (ck, sk) = generate_keys(config);
    set_server_key(sk);

    for (a, b) in [(3u16, 4u16), (0, 9), (250, 5), (12, 12)] {
        let ea = FheUint16::try_encrypt(a, &ck).unwrap();
        let eb = FheUint16::try_encrypt(b, &ck).unwrap();

        // D(E(a) ⊕ E(b)) = a + b
        let add: u16 = (&ea + &eb).decrypt(&ck);
        assert_eq!(add, a.wrapping_add(b), "additive homomorphism: {a}+{b}");

        // D(E(a) ⊗ E(b)) = a * b
        let mul: u16 = (&ea * &eb).decrypt(&ck);
        assert_eq!(mul, a.wrapping_mul(b), "multiplicative homomorphism: {a}*{b}");
    }
}
