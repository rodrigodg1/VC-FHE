// Public-only TFHE operations for the explicitly versioned KMS compatibility profile.
// Compiled against the pinned upstream workspace; never accepts an FHE client key.
use anyhow::{ensure, Result};
use alloy_primitives::{keccak256, U256};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tfhe::integer::{IntegerCiphertext, RadixCiphertext};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};
use tfhe::{CompactPublicKey, FheUint16, FheUint64, ServerKey};

pub const PROFILE: &str = "kms-grouped-radix-v1";
pub const GROUPS: usize = 9;
pub const BLOCKS: usize = 8;
const LIMIT: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub profile: String,
    pub op: String,
    pub bounds: Vec<[u16; 2]>,
}
impl Plan {
    pub fn validate(&self) -> Result<Vec<(usize, i8)>> {
        ensure!(self.profile == PROFILE, "wrong profile");
        ensure!(self.op == "SUM" || self.op == "SUB", "unsupported operation");
        ensure!(!self.bounds.is_empty() && self.bounds.len() <= 33, "unsupported input count");
        let (mut lo, mut hi) = (0i64, 0i64);
        let (mut positive, mut negative) = (0usize, 0usize);
        let n_positive = if self.op == "SUM" { self.bounds.len() } else { 1 };
        let negative_start = n_positive.div_ceil(4);
        let mut layout = Vec::new();
        for (i, &[min, max]) in self.bounds.iter().enumerate() {
            ensure!(min <= max && max <= 511, "input bound outside profile");
            let sign = if self.op == "SUM" || i == 0 { 1 } else { -1 };
            let group = if sign == 1 {
                lo += min as i64; hi += max as i64;
                let g = positive / 4; positive += 1; g
            } else {
                lo -= max as i64; hi -= min as i64;
                let g = negative_start + negative / 4; negative += 1; g
            };
            ensure!(group < GROUPS, "group layout overflow");
            layout.push((group, sign));
        }
        ensure!(lo >= 0 && hi <= 511, "aggregate interval outside [0,511]");
        Ok(layout)
    }
}

pub fn write_cipher<T: serde::Serialize + tfhe::Versionize + tfhe::named::Named>(p: &Path, ct: &T) -> Result<()> {
    let mut bytes = Vec::new();
    safe_serialize(ct, &mut bytes, LIMIT)?;
    std::fs::write(p, bytes)?;
    Ok(())
}
pub fn load_server(p: &Path) -> Result<ServerKey> {
    Ok(safe_deserialize(std::io::Cursor::new(std::fs::read(p)?), LIMIT).map_err(|e| anyhow::anyhow!(e))?)
}
pub fn load_public(p: &Path) -> Result<CompactPublicKey> {
    Ok(safe_deserialize(std::io::Cursor::new(std::fs::read(p)?), LIMIT).map_err(|e| anyhow::anyhow!(e))?)
}
pub fn load_u16(p: &Path) -> Result<FheUint16> {
    Ok(safe_deserialize(std::io::Cursor::new(std::fs::read(p)?), LIMIT).map_err(|e| anyhow::anyhow!(e))?)
}
pub fn load_u64(p: &Path) -> Result<FheUint64> {
    Ok(safe_deserialize(std::io::Cursor::new(std::fs::read(p)?), LIMIT).map_err(|e| anyhow::anyhow!(e))?)
}

pub fn prepare(pk: &CompactPublicKey, sk: &ServerKey, value: u16) -> Result<FheUint16> {
    ensure!(value <= 511, "owner value outside profile");
    tfhe::set_server_key(sk.clone());
    let ct: FheUint16 = threshold_execution::tfhe_internals::utils::expanded_encrypt(pk, value, 16)?;
    let (mut raw, id, tag, metadata) = ct.into_raw_parts();
    let int_key = sk.clone().into_raw_parts().0;
    // Make the preparation postcondition explicit BEFORE owner commitment.
    int_key.full_propagate(&mut raw);
    check_prepared(&raw, &int_key)?;
    Ok(FheUint16::from_raw_parts(raw, id, tag, metadata))
}

fn check_prepared(raw: &RadixCiphertext, sk: &tfhe::integer::ServerKey) -> Result<()> {
    ensure!(raw.blocks().len() == BLOCKS, "wrong block count");
    let template: RadixCiphertext = sk.create_trivial_radix(0u64, BLOCKS);
    for (ct, expected) in raw.blocks().iter().zip(template.blocks()) {
        ensure!(ct.message_modulus.0 == 4 && ct.carry_modulus.0 == 4, "wrong radix parameters");
        ensure!(ct.degree.get() <= 3 && ct.noise_level() <= NoiseLevel::NOMINAL, "preparation capacity postcondition");
        ensure!(ct.ct.lwe_size() == expected.ct.lwe_size() && ct.ct.ciphertext_modulus() == expected.ct.ciphertext_modulus(), "wrong LWE domain");
    }
    Ok(())
}
pub fn coordinates(ct: &FheUint16) -> Vec<String> {
    ct.clone().into_raw_parts().0.blocks().iter()
        .flat_map(|b| b.ct.as_ref().iter().map(u64::to_string)).collect()
}

// Accept canonical Fr coordinates, not a caller's pre-reduced LWE ciphertext.
// The caller must also check the BLS/commitment/finality bindings before invoking conversion.
pub fn normalize(plan: &Plan, sk: &ServerKey, aggregate: &[u8], digest: &str) -> Result<FheUint16> {
    let layout = plan.validate()?;
    ensure!(format!("0x{}", hex::encode(keccak256(aggregate))) == digest, "aggregate digest mismatch");
    tfhe::set_server_key(sk.clone());
    let int_key = sk.clone().into_raw_parts().0;
    let zero: RadixCiphertext = int_key.create_trivial_radix(0u64, BLOCKS);
    let width = zero.blocks()[0].ct.as_ref().len();
    ensure!(aggregate.len() == GROUPS * BLOCKS * width * 32, "wrong aggregate dimension");
    let r = U256::from_str_radix("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)?;
    let bound = U256::from(layout.len()) * U256::from(u64::MAX);
    ensure!(bound < r / U256::from(2), "ambiguous lift domain");
    let mut words = Vec::new();
    for chunk in aggregate.chunks_exact(32) {
        let x = U256::from_be_slice(chunk);
        ensure!(x < r, "noncanonical field coordinate");
        let negative = x > r / U256::from(2);
        let magnitude = if negative { r - x } else { x };
        ensure!(magnitude <= bound, "lift outside aggregate bound");
        let low = magnitude.as_limbs()[0];
        words.push(if negative { low.wrapping_neg() } else { low });
    }
    let (mut positive, mut negative) = (zero.clone(), zero.clone());
    for g in 0..GROUPS {
        let members: Vec<_> = layout.iter().filter(|(group, _)| *group == g).collect();
        let group_words = &words[g * BLOCKS * width..(g + 1) * BLOCKS * width];
        if members.is_empty() {
            ensure!(group_words.iter().all(|&x| x == 0), "nonzero unused group");
            continue;
        }
        ensure!(members.len() <= 4, "group capacity exceeded");
        let sign = members[0].1;
        ensure!(members.iter().all(|(_, s)| *s == sign), "mixed-sign group");
        let mut sum = zero.clone();
        for (block, slice) in sum.blocks_mut().iter_mut().zip(group_words.chunks_exact(width)) {
            for (dst, &src) in block.ct.as_mut().iter_mut().zip(slice) {
                *dst = if sign == 1 { src } else { src.wrapping_neg() };
            }
            block.degree = Degree::new(3 * members.len() as u64);
            block.set_noise_level(NoiseLevel::NOMINAL * members.len() as u64, tfhe::shortint::MaxNoiseLevel::new(5));
        }
        // The checker includes the incoming carry budget; no unchecked overflow.
        int_key.is_add_possible(&sum, &zero)?;
        int_key.full_propagate(&mut sum);
        check_prepared(&sum, &int_key)?;
        if sign == 1 { positive = int_key.add_parallelized(&positive, &sum); }
        else { negative = int_key.add_parallelized(&negative, &sum); }
    }
    let result = int_key.sub_parallelized(&positive, &negative);
    check_prepared(&result, &int_key)?;
    let (_, id, tag, metadata) = FheUint16::try_encrypt_trivial(0u16)?.into_raw_parts();
    Ok(FheUint16::from_raw_parts(result, id, tag, metadata))
}

// Compile the evaluation's actual micro-ISA source against the new pinned dependency.
// Its source hash is included by the runner; do not maintain a second operation table.
pub fn evaluate(op: &str, a: &FheUint64, b: &FheUint64, public: u64) -> Result<FheUint64> {
    ensure!(!matches!(op, "DIV" | "MOD") || public != 0, "zero public divisor");
    ensure!(op != "SHR" || public < 64, "invalid public shift");
    ensure!(op != "ADD_CHAIN" || (1..=8).contains(&public), "invalid public chain");
    Ok(super::tops_micro_isa::evaluate(op, a, Some(b), public)?.value)
}

// This entry point runs in a separate process with public files only.
pub fn worker(job_path: &Path) -> Result<()> {
    let job: serde_json::Value = serde_json::from_slice(&std::fs::read(job_path)?)?;
    let root = job_path.parent().unwrap();
    let sk = load_server(Path::new(job["evaluationKey"].as_str().unwrap()))?;
    tfhe::set_server_key(sk.clone());
    match job["action"].as_str() {
        Some("prepare") => {
            let pk = load_public(Path::new(job["publicKey"].as_str().unwrap()))?;
            let plan: Plan = serde_json::from_value(job["plan"].clone())?;
            plan.validate()?;
            let values: Vec<u16> = serde_json::from_value(job["values"].clone())?;
            ensure!(values.len() == plan.bounds.len(), "owner input count mismatch");
            let mut all = Vec::new();
            for (i, (&value, &[min, max])) in values.iter().zip(&plan.bounds).enumerate() {
                ensure!(min <= value && value <= max, "owner input outside declared interval");
                let ct = prepare(&pk, &sk, value)?;
                write_cipher(&root.join(format!("input-{i}.bin")), &ct)?;
                all.push(coordinates(&ct));
            }
            std::fs::write(root.join("coordinates.json"), serde_json::to_vec(&all)?)?;
        }
        Some("normalize") => {
            let plan: Plan = serde_json::from_value(job["plan"].clone())?;
            let bytes = std::fs::read(Path::new(job["aggregate"].as_str().unwrap()))?;
            let result = normalize(&plan, &sk, &bytes, job["aggregateDigest"].as_str().unwrap())?;
            write_cipher(Path::new(job["output"].as_str().unwrap()), &result)?;
        }
        Some("nonlinear") => {
            let a = load_u64(Path::new(job["left"].as_str().unwrap()))?;
            let b = load_u64(Path::new(job["right"].as_str().unwrap()))?;
            let result = evaluate(job["opcode"].as_str().unwrap(), &a, &b, job["public"].as_u64().unwrap_or(0))?;
            write_cipher(Path::new(job["output"].as_str().unwrap()), &result)?;
        }
        _ => anyhow::bail!("unknown public worker action"),
    }
    Ok(())
}
