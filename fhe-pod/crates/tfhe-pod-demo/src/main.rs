use anyhow::{Context, Result};
use chrono::Utc;
use pod_core::{
    StepProof, TraceRecorder, keccak256_hex, merkle_proof_from_serializables,
    merkle_root_hex_from_serializables, sha256_hex,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tfhe::Versionize;
use tfhe::named::Named;
use tfhe::prelude::*;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{ConfigBuilder, FheUint8, FheUint32, generate_keys, set_server_key};
use tracing::info;
use tracing_subscriber::EnvFilter;

const SERIALIZATION_LIMIT_BYTES: u64 = 1 << 20;

#[derive(Debug, Serialize)]
struct RunSummary {
    session_id: String,
    output_dir: String,
    merkle_root: String,
    micro_trace_root: String,
    steps: usize,
    micro_steps: usize,
    final_clear_result: u8,
    trace_hash_algorithm: String,
    ciphertext_hash_algorithm: String,
    note: String,
}

#[derive(Debug, Serialize)]
struct EvmAttestationPayload {
    version: String,
    domain_name: String,
    domain_version: String,
    primary_type: String,
    chain_family: String,
    proof_type: String,
    proof_type_hash_keccak256: String,
    session_id: String,
    job_id_keccak256: String,
    trace_root_keccak256: String,
    micro_trace_root_keccak256: String,
    result_hash_sha256: String,
    metadata_hash_keccak256: String,
    content_uri_hint: String,
    content_uri_hash_keccak256: String,
    objective_verifier_hint: String,
}

#[derive(Debug, Clone, Serialize)]
struct MicroStepWitness {
    leaf_index: usize,
    opcode: u8,
    opcode_name: String,
    lhs: u64,
    rhs: u64,
    claimed: u64,
}

#[derive(Debug, Serialize)]
struct MicroTraceBundle {
    session_id: String,
    micro_trace_root: String,
    leaf_count: usize,
    witnesses: Vec<MicroStepWitness>,
    note: String,
}

fn main() -> Result<()> {
    init_tracing();

    let process_started = Instant::now();
    let session_id = format!("session-{}", Utc::now().format("%Y%m%dT%H%M%SZ"));
    let output_dir = workspace_root()?
        .join("artifacts")
        .join("runs")
        .join(&session_id);
    fs::create_dir_all(&output_dir).context("failed to create output directory")?;

    info!(
        session_id = %session_id,
        output_dir = %output_dir.display(),
        "session started"
    );

    let mut recorder = TraceRecorder::new(session_id.clone());

    info!("building TFHE configuration");
    let config = ConfigBuilder::default().build();

    info!("generating TFHE client/server keys");
    let keygen_started = Instant::now();
    let (client_key, server_keys) = generate_keys(config);
    info!(
        elapsed_ms = keygen_started.elapsed().as_millis(),
        "TFHE keys ready"
    );

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u8;

    info!(
        step = 0,
        operation = "client.encrypt",
        output = "ct_a",
        "step started"
    );
    let step_started = Instant::now();
    let encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    info!(
        step = 0,
        operation = "client.encrypt",
        output = "ct_a",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        0,
        "client.encrypt",
        vec!["clear_a".to_string()],
        "ct_a",
        &encrypted_a,
        metadata(&[
            ("phase", "client"),
            ("type", "FheUint32"),
            ("semantic_role", "input-a"),
        ]),
    )?;

    info!(
        step = 1,
        operation = "client.encrypt",
        output = "ct_b",
        "step started"
    );
    let step_started = Instant::now();
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;
    info!(
        step = 1,
        operation = "client.encrypt",
        output = "ct_b",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        1,
        "client.encrypt",
        vec!["clear_b".to_string()],
        "ct_b",
        &encrypted_b,
        metadata(&[
            ("phase", "client"),
            ("type", "FheUint32"),
            ("semantic_role", "input-b"),
        ]),
    )?;

    info!(
        step = 2,
        operation = "client.encrypt",
        output = "ct_c",
        "step started"
    );
    let step_started = Instant::now();
    let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;
    info!(
        step = 2,
        operation = "client.encrypt",
        output = "ct_c",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        2,
        "client.encrypt",
        vec!["clear_c".to_string()],
        "ct_c",
        &encrypted_c,
        metadata(&[
            ("phase", "client"),
            ("type", "FheUint8"),
            ("semantic_role", "input-c"),
        ]),
    )?;

    info!("installing TFHE server key");
    set_server_key(server_keys);

    info!(
        step = 3,
        operation = "server.mul",
        output = "ct_mul",
        "step started"
    );
    let step_started = Instant::now();
    let encrypted_res_mul = &encrypted_a * &encrypted_b;
    info!(
        step = 3,
        operation = "server.mul",
        output = "ct_mul",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        3,
        "server.mul",
        vec!["ct_a".to_string(), "ct_b".to_string()],
        "ct_mul",
        &encrypted_res_mul,
        metadata(&[
            ("phase", "server"),
            ("type", "FheUint32"),
            ("clear_equivalent", "a * b"),
        ]),
    )?;

    info!(
        step = 4,
        operation = "server.shr",
        output = "ct_shift",
        "step started"
    );
    let step_started = Instant::now();
    let encrypted_shift = &encrypted_res_mul >> &encrypted_b;
    info!(
        step = 4,
        operation = "server.shr",
        output = "ct_shift",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        4,
        "server.shr",
        vec!["ct_mul".to_string(), "ct_b".to_string()],
        "ct_shift",
        &encrypted_shift,
        metadata(&[
            ("phase", "server"),
            ("type", "FheUint32"),
            ("clear_equivalent", "(a * b) >> b"),
        ]),
    )?;

    info!(
        step = 5,
        operation = "server.cast_into",
        output = "ct_cast_u8",
        "step started"
    );
    let step_started = Instant::now();
    let casted_a: FheUint8 = encrypted_shift.cast_into();
    info!(
        step = 5,
        operation = "server.cast_into",
        output = "ct_cast_u8",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        5,
        "server.cast_into",
        vec!["ct_shift".to_string()],
        "ct_cast_u8",
        &casted_a,
        metadata(&[
            ("phase", "server"),
            ("type", "FheUint8"),
            ("clear_equivalent", "((a * b) >> b) as u8"),
        ]),
    )?;

    info!(
        step = 6,
        operation = "server.min",
        output = "ct_min",
        "step started"
    );
    let step_started = Instant::now();
    let encrypted_res_min = casted_a.min(&encrypted_c);
    info!(
        step = 6,
        operation = "server.min",
        output = "ct_min",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        6,
        "server.min",
        vec!["ct_cast_u8".to_string(), "ct_c".to_string()],
        "ct_min",
        &encrypted_res_min,
        metadata(&[
            ("phase", "server"),
            ("type", "FheUint8"),
            ("clear_equivalent", "min(casted_a, c)"),
        ]),
    )?;

    info!(
        step = 7,
        operation = "server.bitand_scalar",
        output = "ct_final",
        "step started"
    );
    let step_started = Instant::now();
    let encrypted_res = &encrypted_res_min & 1_u8;
    info!(
        step = 7,
        operation = "server.bitand_scalar",
        output = "ct_final",
        elapsed_ms = step_started.elapsed().as_millis(),
        "FHE operation complete"
    );
    record_ciphertext(
        &mut recorder,
        7,
        "server.bitand_scalar",
        vec!["ct_min".to_string()],
        "ct_final",
        &encrypted_res,
        metadata(&[
            ("phase", "server"),
            ("type", "FheUint8"),
            ("clear_equivalent", "min(casted_a, c) & 1"),
        ]),
    )?;

    info!("decrypting final ciphertext for local validation");
    let decrypt_started = Instant::now();
    let clear_res: u8 = encrypted_res.decrypt(&client_key);
    info!(
        elapsed_ms = decrypt_started.elapsed().as_millis(),
        clear_result = clear_res,
        "final decrypt complete"
    );
    assert_eq!(clear_res, 1u8);

    let micro_steps = vec![
        MicroStepWitness {
            leaf_index: 0,
            opcode: 1,
            opcode_name: "MUL".to_string(),
            lhs: clear_a as u64,
            rhs: clear_b as u64,
            claimed: (clear_a * clear_b) as u64,
        },
        MicroStepWitness {
            leaf_index: 1,
            opcode: 2,
            opcode_name: "SHR".to_string(),
            lhs: (clear_a * clear_b) as u64,
            rhs: clear_b as u64,
            claimed: ((clear_a * clear_b) >> clear_b) as u64,
        },
        MicroStepWitness {
            leaf_index: 2,
            opcode: 3,
            opcode_name: "CAST_U8".to_string(),
            lhs: ((clear_a * clear_b) >> clear_b) as u64,
            rhs: 0,
            claimed: (((clear_a * clear_b) >> clear_b) as u8) as u64,
        },
        MicroStepWitness {
            leaf_index: 3,
            opcode: 4,
            opcode_name: "MIN".to_string(),
            lhs: (((clear_a * clear_b) >> clear_b) as u8) as u64,
            rhs: clear_c as u64,
            claimed: (((clear_a * clear_b) >> clear_b) as u8).min(clear_c) as u64,
        },
        MicroStepWitness {
            leaf_index: 4,
            opcode: 5,
            opcode_name: "BITAND".to_string(),
            lhs: (((clear_a * clear_b) >> clear_b) as u8).min(clear_c) as u64,
            rhs: 1,
            claimed: ((((clear_a * clear_b) >> clear_b) as u8).min(clear_c) & 1) as u64,
        },
        MicroStepWitness {
            leaf_index: 5,
            opcode: 1,
            opcode_name: "MUL".to_string(),
            lhs: clear_a as u64,
            rhs: clear_b as u64,
            claimed: (clear_a * clear_b) as u64,
        },
        MicroStepWitness {
            leaf_index: 6,
            opcode: 2,
            opcode_name: "SHR".to_string(),
            lhs: (clear_a * clear_b) as u64,
            rhs: clear_b as u64,
            claimed: ((clear_a * clear_b) >> clear_b) as u64,
        },
        MicroStepWitness {
            leaf_index: 7,
            opcode: 5,
            opcode_name: "BITAND".to_string(),
            lhs: ((((clear_a * clear_b) >> clear_b) as u8).min(clear_c)) as u64,
            rhs: 1,
            claimed: clear_res as u64,
        },
    ];

    write_outputs(&output_dir, &recorder, &micro_steps, clear_res)?;

    info!(
        total_elapsed_ms = process_started.elapsed().as_millis(),
        session_id = %session_id,
        "session finished"
    );

    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .compact()
        .try_init();
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .context("failed to resolve workspace root")
}

fn metadata(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn record_ciphertext<T>(
    recorder: &mut TraceRecorder,
    step_number: usize,
    operation: &str,
    inputs: Vec<String>,
    output: &str,
    value: &T,
    metadata: BTreeMap<String, String>,
) -> Result<()>
where
    T: Serialize + Versionize + Named,
{
    let digest_started = Instant::now();
    let (digest, size) = serialized_digest(value)?;
    info!(
        step = step_number,
        operation = operation,
        output = output,
        ciphertext_size_bytes = size,
        ciphertext_sha256_prefix = &digest[..16],
        digest_elapsed_ms = digest_started.elapsed().as_millis(),
        "trace event recorded"
    );
    recorder.record_event(
        operation.to_string(),
        inputs,
        output.to_string(),
        digest,
        size,
        metadata,
    );
    Ok(())
}

fn serialized_digest<T>(value: &T) -> Result<(String, usize)>
where
    T: Serialize + Versionize + Named,
{
    let mut buffer = Vec::new();
    safe_serialize(value, &mut buffer, SERIALIZATION_LIMIT_BYTES)
        .context("failed to safely serialize ciphertext")?;
    let digest = sha256_hex(&buffer);
    Ok((digest, buffer.len()))
}

fn write_outputs(
    output_dir: &Path,
    recorder: &TraceRecorder,
    micro_steps: &[MicroStepWitness],
    clear_res: u8,
) -> Result<()> {
    info!("building trace bundle");
    let bundle = recorder.bundle()?;
    let micro_trace_root = merkle_root_hex_from_serializables(micro_steps)?;

    info!(
        events = recorder.len(),
        "generating Merkle inclusion proofs"
    );
    let proofs = (0..recorder.len())
        .map(|index| {
            let proof = recorder.proof_for_step(index)?;
            info!(
                step = index,
                proof_hash_count = proof.proof_hashes.len(),
                "Merkle proof generated"
            );
            Result::<StepProof>::Ok(proof)
        })
        .collect::<Result<Vec<_>>>()?;

    let micro_proofs = (0..micro_steps.len())
        .map(|index| merkle_proof_from_serializables(micro_steps, index))
        .collect::<Result<Vec<_>>>()?;

    for proof in &proofs {
        let verified = proof.verify()?;
        if !verified {
            anyhow::bail!(
                "generated proof for step {} did not verify",
                proof.leaf_index
            );
        }
        info!(step = proof.leaf_index, "Merkle proof verified locally");
    }

    for proof in &micro_proofs {
        let verified = proof.verify()?;
        if !verified {
            anyhow::bail!(
                "generated micro proof for leaf {} did not verify",
                proof.leaf_index
            );
        }
        info!(leaf = proof.leaf_index, "micro-step proof verified locally");
    }

    let summary = RunSummary {
        session_id: recorder.session_id().to_string(),
        output_dir: output_dir.display().to_string(),
        merkle_root: bundle.merkle_root.clone(),
        micro_trace_root: micro_trace_root.clone(),
        steps: recorder.len(),
        micro_steps: micro_steps.len(),
        final_clear_result: clear_res,
        trace_hash_algorithm: "keccak256".to_string(),
        ciphertext_hash_algorithm: "sha256".to_string(),
        note: "This bundle proves API-level trace inclusion and integrity. The micro-trace bundle is a PoC surrogate for objective on-chain dispute resolution."
            .to_string(),
    };

    let micro_bundle = MicroTraceBundle {
        session_id: recorder.session_id().to_string(),
        micro_trace_root: micro_trace_root.clone(),
        leaf_count: micro_steps.len(),
        witnesses: micro_steps.to_vec(),
        note: "In production, these leaves would be represented by encrypted handles or FHEVM-compatible micro-witnesses, not clear PoC values."
            .to_string(),
    };

    let final_event = recorder
        .events()
        .last()
        .context("trace should contain a final event")?;
    let content_uri_hint = output_dir.display().to_string();
    let attestation = EvmAttestationPayload {
        version: "pod-evm-v2".to_string(),
        domain_name: "VerifiableFHEDisputeGame".to_string(),
        domain_version: "2".to_string(),
        primary_type: "JobClaim".to_string(),
        chain_family: "evm".to_string(),
        proof_type: "PoD_DISPUTE_GAME_ONCHAIN_OBJECTIVE_VERIFIER".to_string(),
        proof_type_hash_keccak256: keccak256_hex(
            b"PoD_DISPUTE_GAME_ONCHAIN_OBJECTIVE_VERIFIER",
        ),
        session_id: recorder.session_id().to_string(),
        job_id_keccak256: keccak256_hex(recorder.session_id().as_bytes()),
        trace_root_keccak256: bundle.merkle_root.clone(),
        micro_trace_root_keccak256: micro_trace_root,
        result_hash_sha256: final_event.ciphertext_sha256.clone(),
        metadata_hash_keccak256: keccak256_hex(&serde_json::to_vec(&bundle)?),
        content_uri_hash_keccak256: keccak256_hex(content_uri_hint.as_bytes()),
        content_uri_hint,
        objective_verifier_hint: "PoC uses deterministic Solidity micro-verification; production slot targets FHEVM-compatible objective verification."
            .to_string(),
    };

    write_json(output_dir.join("trace_bundle.json"), &bundle)?;
    write_json(output_dir.join("proofs.json"), &proofs)?;
    write_json(output_dir.join("summary.json"), &summary)?;
    write_json(output_dir.join("attestation_payload.json"), &attestation)?;
    write_json(output_dir.join("micro_trace_bundle.json"), &micro_bundle)?;
    write_json(output_dir.join("micro_trace_proofs.json"), &micro_proofs)?;
    fs::write(
        output_dir.join("root.txt"),
        format!("{}\n", bundle.merkle_root),
    )
    .context("failed to write root file")?;

    info!(output_dir = %output_dir.display(), "artifacts written");
    Ok(())
}

fn write_json(path: PathBuf, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_vec_pretty(value).context("failed to serialize json output")?;
    fs::write(&path, json).with_context(|| format!("failed to write json file {}", path.display()))
}
