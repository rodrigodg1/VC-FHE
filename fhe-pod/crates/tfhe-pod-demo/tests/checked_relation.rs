use serde::Deserialize;
use std::process::Command;
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, FheUint64, generate_keys, set_server_key};
use tfhe_pod_demo::micro_isa::{evaluate, rhs_is_public_scalar};

#[derive(Deserialize)]
struct Case {
    opcode: String,
    lhs: String,
    rhs: String,
    valid: bool,
    value: Option<String>,
}

#[test]
fn encrypted_relation_agrees_with_independent_integer_reference() {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/checked-relation-vectors.mjs"
    );
    let output = Command::new("node")
        .arg(script)
        .output()
        .expect("node integer reference");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Case> = serde_json::from_slice(&output.stdout).unwrap();
    let (ck, sk) = generate_keys(ConfigBuilder::default());
    set_server_key(sk);
    for case in &cases {
        let a = case.lhs.parse::<u64>().unwrap();
        let b = case.rhs.parse::<u64>().unwrap();
        let lhs = FheUint64::encrypt(a, &ck);
        let rhs = FheUint64::encrypt(b, &ck);
        let rhs_ref = (!rhs_is_public_scalar(&case.opcode)).then_some(&rhs);
        let result = evaluate(&case.opcode, &lhs, rhs_ref, b).unwrap();
        let valid: bool = result.valid.decrypt(&ck);
        assert_eq!(valid, case.valid, "guard {}({a},{b})", case.opcode);
        let actual: u64 = result.value.decrypt(&ck);
        if let Some(value) = &case.value {
            assert_eq!(
                actual,
                value.parse::<u64>().unwrap(),
                "value {}",
                case.opcode
            );
        }
        // Even a correct modular result is rejected when the range guard fails.
        // Fresh encryption also tests acceptance independent of result bytes.
        let claim = FheUint64::encrypt(actual, &ck);
        let accepted: bool = result.accepts(&claim).decrypt(&ck);
        assert_eq!(accepted, case.valid, "decision {}({a},{b})", case.opcode);
        let wrong = FheUint64::encrypt(actual.wrapping_add(1), &ck);
        let accepted: bool = result.accepts(&wrong).decrypt(&ck);
        assert!(!accepted, "wrong claim {}({a},{b})", case.opcode);
        println!("PASS {} lhs={a} rhs={b} valid={valid}", case.opcode);
    }
    let lhs = FheUint64::encrypt(1u64, &ck);
    assert!(evaluate("ADD", &lhs, None, 0).is_err());
    assert!(evaluate("SHL", &lhs, Some(&lhs), 1).is_err());
    println!(
        "checked {} cases across all 15 opcodes; missing/unsupported input rejected",
        cases.len()
    );
}
