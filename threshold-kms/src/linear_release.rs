// Per-core verification of the public linear release witness.
//
// This verifier establishes that the released ciphertext is the deterministic
// grouped-radix conversion of the ordered ciphertext-coordinate vectors in a
// content-addressed witness. It deliberately does not prove ciphertext origin
// or honest owner-side preparation. Those remain explicit protocol assumptions
// and must be enforced before the vector digests are approved on chain.
use alloy_primitives::{keccak256, U256};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Take},
    path::Path,
};
use tfhe::integer::{IntegerCiphertext, RadixCiphertext};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};
use tfhe::{FheUint16, ServerKey};

pub const LINEAR_WITNESS_SCHEMA: &str = "vcfhe-linear-release-witness-v1";
pub const INPUT_PREPARATION_ASSUMPTION: &str = "honest-owner-preparation-required";
const PROFILE: &str = "kms-grouped-radix-v1";
const PINNED_TFHE: &str = "1.6.1";
const PINNED_UPSTREAM_COMMIT: &str = "986537258d8c0348f497b1860ccf63252bc238f3";
const GROUPS: usize = 9;
const BLOCKS: usize = 8;
const MAX_INPUTS: usize = 33;
const MAX_WITNESS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_READY_BYTES: u64 = 64 * 1024;
const TFHE_SERIALIZATION_LIMIT: u64 = 256 * 1024 * 1024;
const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const BN254_FR_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Values already authenticated by the on-chain reservation and the request
/// parser. `witness_digest` is the content address of `witness_path`.
pub struct LinearReleaseExpected<'a> {
    pub witness_digest: [u8; 32],
    pub program_digest: [u8; 32],
    pub input_bindings_digest: [u8; 32],
    pub aggregate_digest: [u8; 32],
    pub keyset_digest: [u8; 32],
    pub final_ciphertext: &'a [u8],
}

/// Public files mounted read-only into each KMS core.
pub struct LinearReleaseFiles<'a> {
    pub witness_path: &'a Path,
    pub ready_path: &'a Path,
    pub evaluation_key_path: &'a Path,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLinearRelease {
    pub input_count: usize,
    pub coordinate_width: usize,
    pub aggregate_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    profile: String,
    op: String,
    bounds: Vec<[u16; 2]>,
}

impl Plan {
    // This is intentionally identical to compatible_fhe.rs. The group layout
    // determines both the signed BN254 aggregate and its TFHE normalization.
    fn validate(&self) -> Result<Vec<(usize, i8)>> {
        ensure!(self.profile == PROFILE, "wrong linear profile");
        ensure!(
            self.op == "SUM" || self.op == "SUB",
            "unsupported linear operation"
        );
        ensure!(
            !self.bounds.is_empty() && self.bounds.len() <= MAX_INPUTS,
            "unsupported linear input count"
        );
        let (mut lo, mut hi) = (0_i64, 0_i64);
        let (mut positive, mut negative) = (0_usize, 0_usize);
        let positive_count = if self.op == "SUM" {
            self.bounds.len()
        } else {
            1
        };
        let negative_start = positive_count.div_ceil(4);
        let mut layout = Vec::with_capacity(self.bounds.len());
        for (index, &[min, max]) in self.bounds.iter().enumerate() {
            ensure!(
                min <= max && max <= 511,
                "input bound outside linear profile"
            );
            let sign = if self.op == "SUM" || index == 0 {
                1
            } else {
                -1
            };
            let group = if sign == 1 {
                lo += i64::from(min);
                hi += i64::from(max);
                let group = positive / 4;
                positive += 1;
                group
            } else {
                lo -= i64::from(max);
                hi -= i64::from(min);
                let group = negative_start + negative / 4;
                negative += 1;
                group
            };
            ensure!(group < GROUPS, "linear group layout overflow");
            layout.push((group, sign));
        }
        ensure!(lo >= 0 && hi <= 511, "aggregate interval outside [0,511]");
        Ok(layout)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Witness {
    schema: String,
    input_preparation_assumption: String,
    plan: Plan,
    vectors: Vec<WitnessVector>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WitnessVector {
    coords_digest: String,
    coordinates: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReadyFile {
    status: String,
    upstream_commit: String,
    parameters: String,
    parties: u8,
    corruption_threshold: u8,
    preloaded_fhe_key: bool,
    full_preprocessing: bool,
    key_id: String,
    key_epoch: String,
    mpc_context: String,
    keyset_digest: String,
    key_descriptor: KeyDescriptor,
    preprocessing_seconds: f64,
    dkg_seconds: f64,
    public_key_preparation_seconds: f64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KeyDescriptor {
    encryption_key_digest: String,
    evaluation_key_digest: String,
    tfhe: String,
    parameters: String,
}

fn hash_bytes(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    let digest = keccak256(bytes);
    let mut result = [0_u8; 32];
    result.copy_from_slice(digest.as_slice());
    result
}

fn decode_hex32(value: &str, label: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 66
            && value.starts_with("0x")
            && value.as_bytes()[2..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "invalid {label}"
    );
    let bytes = hex::decode(&value[2..]).with_context(|| format!("invalid {label}"))?;
    let mut result = [0_u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn read_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("missing {label}"))?;
    ensure!(file.metadata()?.is_file(), "{label} is not a regular file");
    ensure!(
        file.metadata()?.len() <= limit,
        "{label} exceeds size limit"
    );
    let mut bytes = Vec::new();
    let mut bounded: Take<File> = file.take(limit + 1);
    bounded
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {label}"))?;
    ensure!(bytes.len() as u64 <= limit, "{label} exceeds size limit");
    Ok(bytes)
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::String(value) => output.push_str(&serde_json::to_string(value)?),
        Value::Number(value) => {
            let integer = value
                .as_u64()
                .filter(|value| *value <= JS_MAX_SAFE_INTEGER)
                .context("noncanonical JSON number")?;
            output.push_str(&integer.to_string());
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                write_canonical_json(&values[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn policy_hash(plan: &Plan) -> Result<[u8; 32]> {
    let mut canonical = String::new();
    write_canonical_json(&serde_json::to_value(plan)?, &mut canonical)?;
    Ok(hash_bytes(canonical.as_bytes()))
}

fn abi_bytes32_array_digest(values: &[[u8; 32]]) -> [u8; 32] {
    // abi.encode(bytes32[]) = dynamic offset || length || ordered elements.
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    let mut offset = [0_u8; 32];
    offset[31] = 32;
    encoded.extend_from_slice(&offset);
    let mut length = [0_u8; 32];
    length[24..].copy_from_slice(&(values.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&length);
    for value in values {
        encoded.extend_from_slice(value);
    }
    hash_bytes(encoded)
}

fn parse_coordinate(value: &str) -> Result<u64> {
    ensure!(
        value == "0"
            || (!value.is_empty()
                && !value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit())),
        "noncanonical ciphertext coordinate"
    );
    value
        .parse::<u64>()
        .context("ciphertext coordinate outside u64")
}

fn be32_u64(value: u64) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    encoded[24..].copy_from_slice(&value.to_be_bytes());
    encoded
}

fn coords_digest(coordinates: &[u64]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(coordinates.len() * 32);
    for coordinate in coordinates {
        encoded.extend_from_slice(&be32_u64(*coordinate));
    }
    hash_bytes(encoded)
}

fn encode_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn reconstruct_aggregate(plan: &Plan, vectors: &[Vec<u64>]) -> Result<Vec<u8>> {
    let layout = plan.validate()?;
    ensure!(vectors.len() == layout.len(), "plan/vector count mismatch");
    let width = vectors.first().context("missing ciphertext vectors")?.len();
    ensure!(
        width > 0 && width % BLOCKS == 0,
        "invalid ciphertext coordinate width"
    );
    ensure!(
        vectors.iter().all(|vector| vector.len() == width),
        "inconsistent ciphertext coordinate width"
    );

    // A group contains at most four u64 coordinates. u128 therefore covers
    // its unreduced magnitude, while U256 performs the final BN254 reduction.
    let mut magnitudes = vec![0_u128; GROUPS * width];
    let mut signs = [0_i8; GROUPS];
    for (vector, &(group, sign)) in vectors.iter().zip(&layout) {
        ensure!(
            signs[group] == 0 || signs[group] == sign,
            "mixed-sign linear group"
        );
        signs[group] = sign;
        for (column, coordinate) in vector.iter().enumerate() {
            magnitudes[group * width + column] += u128::from(*coordinate);
        }
    }

    let modulus = U256::from_str_radix(BN254_FR_DECIMAL, 10)?;
    let mut aggregate = Vec::with_capacity(GROUPS * width * 32);
    for group in 0..GROUPS {
        for column in 0..width {
            let magnitude = U256::from(magnitudes[group * width + column]);
            ensure!(
                magnitude < modulus,
                "linear aggregate magnitude exceeds BN254 Fr"
            );
            let value = if signs[group] < 0 && magnitude != U256::ZERO {
                modulus - magnitude
            } else {
                magnitude
            };
            aggregate.extend_from_slice(&encode_u256(value));
        }
    }
    Ok(aggregate)
}

fn check_prepared(raw: &RadixCiphertext, server_key: &tfhe::integer::ServerKey) -> Result<()> {
    ensure!(raw.blocks().len() == BLOCKS, "wrong TFHE block count");
    let template: RadixCiphertext = server_key.create_trivial_radix(0_u64, BLOCKS);
    for (ciphertext, expected) in raw.blocks().iter().zip(template.blocks()) {
        ensure!(
            ciphertext.message_modulus.0 == 4 && ciphertext.carry_modulus.0 == 4,
            "wrong TFHE radix parameters"
        );
        ensure!(
            ciphertext.degree.get() <= 3 && ciphertext.noise_level() <= NoiseLevel::NOMINAL,
            "TFHE preparation capacity postcondition failed"
        );
        ensure!(
            ciphertext.ct.lwe_size() == expected.ct.lwe_size()
                && ciphertext.ct.ciphertext_modulus() == expected.ct.ciphertext_modulus(),
            "wrong TFHE LWE domain"
        );
    }
    Ok(())
}

// Kept byte-for-byte equivalent in operation order to compatible_fhe::normalize.
fn normalize(plan: &Plan, server_key: &ServerKey, aggregate: &[u8]) -> Result<FheUint16> {
    let layout = plan.validate()?;
    tfhe::set_server_key(server_key.clone());
    let integer_key = server_key.clone().into_raw_parts().0;
    let zero: RadixCiphertext = integer_key.create_trivial_radix(0_u64, BLOCKS);
    let width = zero.blocks()[0].ct.as_ref().len();
    ensure!(
        aggregate.len() == GROUPS * BLOCKS * width * 32,
        "aggregate has wrong TFHE dimension"
    );
    let modulus = U256::from_str_radix(BN254_FR_DECIMAL, 10)?;
    let bound = U256::from(layout.len()) * U256::from(u64::MAX);
    ensure!(
        bound < modulus / U256::from(2),
        "ambiguous BN254 lift domain"
    );
    let mut words = Vec::with_capacity(aggregate.len() / 32);
    for chunk in aggregate.chunks_exact(32) {
        let coordinate = U256::from_be_slice(chunk);
        ensure!(coordinate < modulus, "noncanonical aggregate coordinate");
        let negative = coordinate > modulus / U256::from(2);
        let magnitude = if negative {
            modulus - coordinate
        } else {
            coordinate
        };
        ensure!(magnitude <= bound, "aggregate lift outside bound");
        let low = magnitude.as_limbs()[0];
        words.push(if negative { low.wrapping_neg() } else { low });
    }

    let (mut positive, mut negative) = (zero.clone(), zero.clone());
    for group in 0..GROUPS {
        let members: Vec<_> = layout
            .iter()
            .filter(|(member_group, _)| *member_group == group)
            .collect();
        let group_words = &words[group * BLOCKS * width..(group + 1) * BLOCKS * width];
        if members.is_empty() {
            ensure!(
                group_words.iter().all(|&word| word == 0),
                "nonzero unused linear group"
            );
            continue;
        }
        ensure!(members.len() <= 4, "linear group capacity exceeded");
        let sign = members[0].1;
        ensure!(
            members.iter().all(|(_, other)| *other == sign),
            "mixed-sign linear group"
        );
        let mut sum = zero.clone();
        for (block, slice) in sum
            .blocks_mut()
            .iter_mut()
            .zip(group_words.chunks_exact(width))
        {
            for (destination, &source) in block.ct.as_mut().iter_mut().zip(slice) {
                *destination = if sign == 1 {
                    source
                } else {
                    source.wrapping_neg()
                };
            }
            block.degree = Degree::new(3 * members.len() as u64);
            block.set_noise_level(
                NoiseLevel::NOMINAL * members.len() as u64,
                tfhe::shortint::MaxNoiseLevel::new(5),
            );
        }
        integer_key.is_add_possible(&sum, &zero)?;
        integer_key.full_propagate(&mut sum);
        check_prepared(&sum, &integer_key)?;
        if sign == 1 {
            positive = integer_key.add_parallelized(&positive, &sum);
        } else {
            negative = integer_key.add_parallelized(&negative, &sum);
        }
    }
    let result = integer_key.sub_parallelized(&positive, &negative);
    check_prepared(&result, &integer_key)?;
    let (_, id, tag, metadata) = FheUint16::try_encrypt_trivial(0_u16)?.into_raw_parts();
    Ok(FheUint16::from_raw_parts(result, id, tag, metadata))
}

fn validate_ready(ready_bytes: &[u8], evaluation_key: &[u8], expected: [u8; 32]) -> Result<()> {
    let ready: ReadyFile =
        serde_json::from_slice(ready_bytes).context("invalid keyset ready.json")?;
    ensure!(ready.status == "passed", "keyset is not ready");
    ensure!(
        ready.upstream_commit == PINNED_UPSTREAM_COMMIT,
        "wrong KMS source pin"
    );
    ensure!(
        ready.parties == 4 && ready.corruption_threshold == 1,
        "wrong KMS threshold profile"
    );
    ensure!(
        !ready.preloaded_fhe_key && ready.full_preprocessing,
        "unapproved KMS key generation mode"
    );
    ensure!(
        matches!(ready.parameters.as_str(), "Default" | "Test"),
        "unsupported FHE parameters"
    );
    ensure!(
        ready.key_descriptor.parameters == ready.parameters,
        "keyset parameter mismatch"
    );
    ensure!(
        ready.key_descriptor.tfhe == PINNED_TFHE,
        "wrong TFHE version"
    );
    ensure!(
        [
            ready.preprocessing_seconds,
            ready.dkg_seconds,
            ready.public_key_preparation_seconds,
        ]
        .iter()
        .all(|value| value.is_finite() && *value >= 0.0),
        "invalid keyset timing metadata"
    );
    // These identifiers are not recomputed here, but strict decoding prevents
    // a malformed ready record from being accepted as the mounted keyset.
    decode_hex32(&ready.key_id, "keyId")?;
    decode_hex32(&ready.key_epoch, "keyEpoch")?;
    decode_hex32(&ready.mpc_context, "mpcContext")?;
    decode_hex32(
        &ready.key_descriptor.encryption_key_digest,
        "encryptionKeyDigest",
    )?;
    let evaluation_digest = decode_hex32(
        &ready.key_descriptor.evaluation_key_digest,
        "evaluationKeyDigest",
    )?;
    ensure!(
        hash_bytes(evaluation_key) == evaluation_digest,
        "evaluation-key digest mismatch"
    );

    // Key generation computes this digest over the descriptor JSON Value.
    // serde_json 1.0.145 stores object keys in sorted order in the pinned build.
    let descriptor = serde_json::json!({
        "encryptionKeyDigest": ready.key_descriptor.encryption_key_digest,
        "evaluationKeyDigest": ready.key_descriptor.evaluation_key_digest,
        "tfhe": ready.key_descriptor.tfhe,
        "parameters": ready.key_descriptor.parameters,
    });
    let computed = hash_bytes(serde_json::to_vec(&descriptor)?);
    ensure!(computed == expected, "computed keyset digest mismatch");
    ensure!(
        decode_hex32(&ready.keyset_digest, "keysetDigest")? == expected,
        "ready keyset digest mismatch"
    );
    Ok(())
}

fn verify_witness(
    witness_bytes: &[u8],
    expected: &LinearReleaseExpected<'_>,
) -> Result<(Plan, Vec<Vec<u64>>, Vec<u8>)> {
    ensure!(
        hash_bytes(witness_bytes) == expected.witness_digest,
        "linear witness content address mismatch"
    );
    let witness: Witness =
        serde_json::from_slice(witness_bytes).context("invalid linear witness")?;
    ensure!(
        witness.schema == LINEAR_WITNESS_SCHEMA,
        "wrong linear witness schema"
    );
    ensure!(
        witness.input_preparation_assumption == INPUT_PREPARATION_ASSUMPTION,
        "missing honest-input-preparation assumption"
    );
    ensure!(
        policy_hash(&witness.plan)? == expected.program_digest,
        "linear program digest mismatch"
    );
    let layout = witness.plan.validate()?;
    ensure!(
        witness.vectors.len() == layout.len(),
        "linear witness input count mismatch"
    );

    let mut vectors = Vec::with_capacity(witness.vectors.len());
    let mut bindings = Vec::with_capacity(witness.vectors.len());
    for vector in witness.vectors {
        let coordinates = vector
            .coordinates
            .iter()
            .map(|coordinate| parse_coordinate(coordinate))
            .collect::<Result<Vec<_>>>()?;
        let digest = coords_digest(&coordinates);
        ensure!(
            decode_hex32(&vector.coords_digest, "coordsDigest")? == digest,
            "ciphertext-coordinate digest mismatch"
        );
        bindings.push(digest);
        vectors.push(coordinates);
    }
    ensure!(
        abi_bytes32_array_digest(&bindings) == expected.input_bindings_digest,
        "input-bindings digest mismatch"
    );
    let aggregate = reconstruct_aggregate(&witness.plan, &vectors)?;
    ensure!(
        hash_bytes(&aggregate) == expected.aggregate_digest,
        "linear aggregate digest mismatch"
    );
    Ok((witness.plan, vectors, aggregate))
}

/// Verify all public linear evidence before the caller writes its durable
/// request-consumption marker or starts threshold decryption.
pub fn verify_linear_release(
    files: LinearReleaseFiles<'_>,
    expected: LinearReleaseExpected<'_>,
) -> Result<VerifiedLinearRelease> {
    ensure!(
        !expected.final_ciphertext.is_empty()
            && expected.final_ciphertext.len() as u64 <= TFHE_SERIALIZATION_LIMIT,
        "invalid final ciphertext size"
    );
    let witness_bytes = read_bounded(files.witness_path, MAX_WITNESS_BYTES, "linear witness")?;
    let (plan, vectors, aggregate) = verify_witness(&witness_bytes, &expected)?;
    let ready_bytes = read_bounded(files.ready_path, MAX_READY_BYTES, "keyset ready.json")?;
    let evaluation_key = read_bounded(
        files.evaluation_key_path,
        TFHE_SERIALIZATION_LIMIT,
        "evaluation key",
    )?;
    validate_ready(&ready_bytes, &evaluation_key, expected.keyset_digest)?;
    let server_key: ServerKey = safe_deserialize(
        std::io::Cursor::new(&evaluation_key),
        TFHE_SERIALIZATION_LIMIT,
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    let normalized = normalize(&plan, &server_key, &aggregate)?;
    let mut normalized_bytes = Vec::new();
    safe_serialize(&normalized, &mut normalized_bytes, TFHE_SERIALIZATION_LIMIT)?;
    ensure!(
        normalized_bytes.as_slice() == expected.final_ciphertext,
        "final ciphertext differs from deterministic linear normalization"
    );
    Ok(VerifiedLinearRelease {
        input_count: vectors.len(),
        coordinate_width: vectors[0].len(),
        aggregate_bytes: aggregate.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temporary_file(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vcfhe-linear-release-{label}-{}-{nonce}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn word(value: &str) -> [u8; 32] {
        decode_hex32(value, "test word").unwrap()
    }

    fn sample_plan() -> Plan {
        Plan {
            profile: PROFILE.to_owned(),
            op: "SUB".to_owned(),
            bounds: vec![[5, 10], [1, 2]],
        }
    }

    #[test]
    fn policy_hash_matches_javascript_canonical_json() {
        assert_eq!(
            policy_hash(&sample_plan()).unwrap(),
            word("0x13ed1deb78b2a1a2a213b594a9c00b89fb0dcf24d9ad4f89d9029ca69999609c")
        );
    }

    #[test]
    fn coordinate_and_solidity_array_digests_match_javascript() {
        assert_eq!(
            coords_digest(&[1, 2]),
            word("0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0")
        );
        assert_eq!(
            abi_bytes32_array_digest(&[[0x11; 32], [0x22; 32]]),
            word("0x2f685994ab703309ca4d0393ec2524b0368f819050ff85e7e3fb719cc5b48de3")
        );
    }

    #[test]
    fn signed_sub_aggregate_uses_group_layout_and_bn254_reduction() {
        let vectors = vec![
            (1_u64..=8).collect::<Vec<_>>(),
            (9_u64..=16).collect::<Vec<_>>(),
        ];
        let aggregate = reconstruct_aggregate(&sample_plan(), &vectors).unwrap();
        assert_eq!(aggregate.len(), GROUPS * 8 * 32);
        assert_eq!(
            hash_bytes(aggregate),
            word("0xdf0bed0e9d05c312f606f12692409c7d296563b09bac8f91c2cac4f73bb7a3b1")
        );
    }

    #[test]
    fn strict_witness_rejects_missing_unknown_and_mutated_fields() {
        let valid = serde_json::json!({
            "schema": LINEAR_WITNESS_SCHEMA,
            "inputPreparationAssumption": INPUT_PREPARATION_ASSUMPTION,
            "plan": {"profile": PROFILE, "op": "SUM", "bounds": [[0, 1]]},
            "vectors": [{
                "coordsDigest": format!("0x{}", hex::encode(coords_digest(&[0; BLOCKS]))),
                "coordinates": vec!["0"; BLOCKS]
            }]
        });
        let bytes = serde_json::to_vec(&valid).unwrap();
        assert!(serde_json::from_slice::<Witness>(&bytes).is_ok());

        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("plan");
        assert!(serde_json::from_value::<Witness>(missing).is_err());

        let mut unknown = valid.clone();
        unknown["untrusted"] = Value::Bool(true);
        assert!(serde_json::from_value::<Witness>(unknown).is_err());

        let mut changed = valid;
        changed["vectors"][0]["coordinates"][0] = Value::String("1".to_owned());
        let changed: Witness = serde_json::from_value(changed).unwrap();
        let coordinates = changed.vectors[0]
            .coordinates
            .iter()
            .map(|value| parse_coordinate(value))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_ne!(
            coords_digest(&coordinates),
            decode_hex32(&changed.vectors[0].coords_digest, "coordsDigest").unwrap()
        );
    }

    #[test]
    fn bounded_reader_rejects_missing_and_oversize_files() {
        let missing = temporary_file("missing");
        assert!(read_bounded(&missing, 8, "test witness").is_err());

        let oversized = temporary_file("oversize");
        fs::write(&oversized, [0_u8; 9]).unwrap();
        assert!(read_bounded(&oversized, 8, "test witness").is_err());
        fs::remove_file(oversized).unwrap();
    }

    #[test]
    fn coordinates_require_canonical_decimal_u64() {
        assert_eq!(parse_coordinate("0").unwrap(), 0);
        assert_eq!(parse_coordinate("18446744073709551615").unwrap(), u64::MAX);
        for invalid in ["", "00", "01", "+1", "-1", "1.0", "18446744073709551616"] {
            assert!(parse_coordinate(invalid).is_err(), "accepted {invalid}");
        }
    }
}
