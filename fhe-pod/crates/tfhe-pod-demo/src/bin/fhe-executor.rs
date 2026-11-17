//! fhe-executor — replays a lowered micro-ISA trace (`artifacts/fhe/traces.json`)
//! homomorphically with tfhe-rs 1.4.0 and emits a ciphertext manifest.
//!
//! Every leaf of every workload is executed over `FheUint64` ciphertexts. Fresh
//! operands are encrypted with the client key (they are the "authenticated
//! inputs" of the dispute game); operands flagged `lhsFromPrevious`/
//! `rhsFromPrevious` reuse the *result ciphertext* of the immediately preceding
//! leaf, so the ciphertext chain mirrors the plaintext data-flow of the trace.
//!
//! Handles are `keccak256` (Ethereum keccak, i.e. `sha3::Keccak256`, NOT the
//! FIPS-202 `Sha3_256`) of the safe-serialized ciphertext bytes. A handle
//! identifies ONE EXECUTION of an operation, not the operation: re-executing
//! the same leaf on the same operands under the same key in another process can
//! return a different -- equally valid -- ciphertext, because evaluation is
//! parallel. Nothing in the protocol compares handles to decide correctness;
//! a disputed leaf is settled by `FHE.eq` over the ciphertexts.
//!
//! Each leaf's RESULT ciphertext is persisted as `result-<index>.ct` next to the
//! input ciphertexts, because that adjudication needs the operands of the
//! disputed leaf -- and an operand taken from the previous leaf is one of these
//! stored results.
//!
//! Usage:
//!   fhe-executor [--traces <path>] [--out <path>] [--ciphertext-dir <path>]
//!                [--workloads all|<id>,<id>] [--verify-determinism]
//!                [--limit-leaves <n>]

use tfhe_pod_demo::trace_sources::SourceRef;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tfhe::Versionize;
use tfhe::named::Named;
use tfhe::prelude::*;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{
    ClientKey, ConfigBuilder, FheUint64, ServerKey, generate_keys,
    set_server_key,
};

/// Safe-serialization ceiling for a single 64-bit radix ciphertext. A default
/// -parameter `FheUint64` serializes to a few hundred kB; 64 MiB is a generous
/// sanity bound.
const CIPHERTEXT_LIMIT_BYTES: u64 = 1 << 26;
/// Server keys are ~100 MB with the default parameter set.
const KEY_LIMIT_BYTES: u64 = 1 << 33;

/// Handle used for operands that are public scalars rather than ciphertexts.
const ZERO_HANDLE: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// traces.json model
// ---------------------------------------------------------------------------

/// `lhs`/`rhs`/`claimed` are decimal *strings* in traces.json; accept plain JSON
/// numbers too so the binary keeps working if the exporter ever changes.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum NumLike {
    Str(String),
    Num(u64),
}

impl NumLike {
    fn value(&self) -> Result<u64> {
        match self {
            NumLike::Str(s) => s
                .trim()
                .parse::<u64>()
                .with_context(|| format!("value {s:?} is not a u64")),
            NumLike::Num(n) => Ok(*n),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TraceLeaf {
    index: usize,
    opcode: String,
    #[allow(dead_code)]
    opcode_id: Option<u64>,
    lhs: NumLike,
    rhs: NumLike,
    claimed: NumLike,
    #[serde(default)]
    operands: Option<Vec<NumLike>>,
    #[serde(default)]
    lhs_from_previous: bool,
    #[serde(default)]
    rhs_from_previous: bool,
    #[serde(default)]
    lhs_ref: Option<SourceRef>,
    #[serde(default)]
    rhs_ref: Option<SourceRef>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TraceWorkload {
    workload_id: String,
    #[serde(default)]
    circuit_version: Option<String>,
    #[allow(dead_code)]
    title: Option<String>,
    #[allow(dead_code)]
    leaf_count: Option<usize>,
    leaves: Vec<TraceLeaf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TraceFile {
    #[allow(dead_code)]
    generator: Option<String>,
    #[allow(dead_code)]
    engine_version: Option<String>,
    workloads: Vec<TraceWorkload>,
}

// ---------------------------------------------------------------------------
// manifest model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InputRecord {
    leaf_index: usize,
    side: String,
    clear: String,
    handle: String,
    bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LeafRecord {
    index: usize,
    opcode: String,
    result_handle: String,
    decrypted: String,
    claimed: String,
    ok: bool,
    ms: u128,
    lhs_handle: String,
    rhs_handle: String,
    lhs_source: String,
    rhs_source: String,
    lhs_ref: Option<SourceRef>,
    rhs_ref: Option<SourceRef>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkloadRecord {
    workload_id: String,
    circuit_version: Option<String>,
    leaf_count: usize,
    fhe_ms: u128,
    /// Wall-clock for the whole workload (encryption + FHE + serialization +
    /// hashing + decryption + disk I/O). Not part of the minimal schema; kept so
    /// full-run extrapolation is honest.
    wall_ms: u128,
    determinism_verified: bool,
    inputs: Vec<InputRecord>,
    leaves: Vec<LeafRecord>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    generator: String,
    tfhe_version: String,
    integer_width: u32,
    key_digest: String,
    generated_at_unix: Option<i64>,
    determinism_verified: bool,
    total_leaves: usize,
    total_fhe_ms: u128,
    total_wall_ms: u128,
    keygen_ms: u128,
    workloads: Vec<WorkloadRecord>,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Args {
    traces: PathBuf,
    out: PathBuf,
    ciphertext_dir: PathBuf,
    workloads: Option<Vec<String>>,
    verify_determinism: bool,
    limit_leaves: Option<usize>,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        traces: PathBuf::from("artifacts/fhe/traces.json"),
        out: PathBuf::from("artifacts/fhe/ciphertext-manifest.json"),
        ciphertext_dir: PathBuf::from("artifacts/fhe/ciphertexts"),
        workloads: None,
        verify_determinism: false,
        limit_leaves: None,
    };

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut next = |name: &str| -> Result<String> {
            it.next()
                .ok_or_else(|| anyhow!("flag {name} requires a value"))
        };
        match flag.as_str() {
            "--traces" => args.traces = PathBuf::from(next("--traces")?),
            "--out" => args.out = PathBuf::from(next("--out")?),
            "--ciphertext-dir" => args.ciphertext_dir = PathBuf::from(next("--ciphertext-dir")?),
            "--workloads" => {
                let raw = next("--workloads")?;
                args.workloads = if raw == "all" {
                    None
                } else {
                    Some(
                        raw.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    )
                };
            }
            "--verify-determinism" => args.verify_determinism = true,
            "--limit-leaves" => {
                args.limit_leaves = Some(
                    next("--limit-leaves")?
                        .parse::<usize>()
                        .context("--limit-leaves expects a non-negative integer")?,
                )
            }
            "-h" | "--help" => {
                println!(
                    "fhe-executor [--traces <path>] [--out <path>] [--ciphertext-dir <path>]\n\
                     \x20            [--workloads all|<id>,<id>] [--verify-determinism]\n\
                     \x20            [--limit-leaves <n>]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown flag {other}"),
        }
    }
    Ok(args)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn keccak_handle(bytes: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn serialize_ct<T>(value: &T, limit: u64) -> Result<Vec<u8>>
where
    T: Serialize + Versionize + Named,
{
    let mut buffer = Vec::new();
    safe_serialize(value, &mut buffer, limit)
        .map_err(|err| anyhow!("safe_serialize failed: {err}"))?;
    Ok(buffer)
}

/// Where an operand ciphertext came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    AuthenticatedInput,
    PreviousOutput,
    PublicConstant,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::AuthenticatedInput => "AUTHENTICATED_INPUT",
            Source::PreviousOutput => "PREVIOUS_OUTPUT",
            Source::PublicConstant => "PUBLIC_CONSTANT",
        }
    }
}

/// Public control scalars of the checked micro-ISA.
fn rhs_is_public_scalar(opcode: &str) -> bool {
    tfhe_pod_demo::micro_isa::rhs_is_public_scalar(opcode)
}

/// Opcodes that ignore the right-hand operand entirely.
fn is_unary(opcode: &str) -> bool {
    matches!(opcode, "CAST_U8")
}

/// Result-only wrapper for replay diagnostics; execution checks the guard too.
fn eval_opcode(
    opcode: &str,
    lhs_ct: &FheUint64,
    rhs_ct: Option<&FheUint64>,
    rhs_clear: u64,
    extra_operands: &[FheUint64],
) -> Result<FheUint64> {
    if !extra_operands.is_empty() {
        bail!("operand-array sums are not the adjudicated ADD_CHAIN operation");
    }
    Ok(tfhe_pod_demo::micro_isa::evaluate(opcode, lhs_ct, rhs_ct, rhs_clear)?.value)
}

/// Everything needed to replay a workload deterministically: the fresh input
/// ciphertexts, keyed by `(leaf index, side)`.
type InputStore = HashMap<(usize, String), FheUint64>;

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("FAILURE: at least one leaf did not match its claimed value");
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("ERROR: {err:?}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool> {
    let args = parse_args()?;
    let started = Instant::now();

    let raw = fs::read_to_string(&args.traces)
        .with_context(|| format!("failed to read traces {}", args.traces.display()))?;
    let traces: TraceFile = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse traces {}", args.traces.display()))?;

    let selected: Vec<&TraceWorkload> = match &args.workloads {
        None => traces.workloads.iter().collect(),
        Some(ids) => {
            for id in ids {
                if !traces.workloads.iter().any(|w| &w.workload_id == id) {
                    bail!("workload {id} not present in {}", args.traces.display());
                }
            }
            traces
                .workloads
                .iter()
                .filter(|w| ids.contains(&w.workload_id))
                .collect()
        }
    };
    eprintln!(
        "[fhe-executor] {} workload(s) selected, {} leaf/leaves total (before --limit-leaves)",
        selected.len(),
        selected.iter().map(|w| w.leaves.len()).sum::<usize>()
    );

    // ---- one config / keypair for the whole run -------------------------
    eprintln!("[fhe-executor] generating TFHE keys (ConfigBuilder::default())");
    let keygen_started = Instant::now();
    let config = ConfigBuilder::default().build();
    let (client_key, server_key): (ClientKey, ServerKey) = generate_keys(config);
    let keygen_ms = keygen_started.elapsed().as_millis();
    eprintln!("[fhe-executor] keys ready in {keygen_ms} ms");

    // Serialize the keys BEFORE `set_server_key` consumes the server key.
    let keys_dir = args.ciphertext_dir.join("keys");
    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("failed to create {}", keys_dir.display()))?;
    let server_key_bytes = serialize_ct(&server_key, KEY_LIMIT_BYTES)?;
    let key_digest = keccak_handle(&server_key_bytes);
    fs::write(keys_dir.join("server-key.bin"), &server_key_bytes)?;
    let client_key_bytes = serialize_ct(&client_key, KEY_LIMIT_BYTES)?;
    fs::write(keys_dir.join("client-key.bin"), &client_key_bytes)?;
    eprintln!(
        "[fhe-executor] server key {} bytes (digest {}), client key {} bytes",
        server_key_bytes.len(),
        key_digest,
        client_key_bytes.len()
    );
    drop(server_key_bytes);
    drop(client_key_bytes);

    set_server_key(server_key);

    // ---- execute --------------------------------------------------------
    let mut workload_records = Vec::new();
    let mut all_ok = true;
    let mut determinism_all_ok = args.verify_determinism;

    for workload in selected {
        let record = execute_workload(workload, &client_key, &args)?;
        if record.leaves.iter().any(|l| !l.ok) {
            all_ok = false;
        }
        if args.verify_determinism && !record.determinism_verified {
            determinism_all_ok = false;
        }
        workload_records.push(record);
    }

    let total_leaves: usize = workload_records.iter().map(|w| w.leaf_count).sum();
    let total_fhe_ms: u128 = workload_records.iter().map(|w| w.fhe_ms).sum();
    let total_wall_ms: u128 = workload_records.iter().map(|w| w.wall_ms).sum();

    let manifest = Manifest {
        generator: "crates/tfhe-pod-demo/src/bin/fhe-executor.rs".to_string(),
        tfhe_version: "1.4.0".to_string(),
        integer_width: 64,
        key_digest,
        generated_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64),
        determinism_verified: determinism_all_ok,
        total_leaves,
        total_fhe_ms,
        total_wall_ms,
        keygen_ms,
        workloads: workload_records,
    };

    if let Some(parent) = args.out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.out, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("failed to write manifest {}", args.out.display()))?;

    // ---- summary --------------------------------------------------------
    eprintln!("\n[fhe-executor] ===== SUMMARY =====");
    for w in &manifest.workloads {
        let failed = w.leaves.iter().filter(|l| !l.ok).count();
        eprintln!(
            "  {:<32} leaves={:<4} ok={:<4} failed={:<3} fheMs={:<8} wallMs={:<8} determinism={}",
            w.workload_id,
            w.leaf_count,
            w.leaf_count - failed,
            failed,
            w.fhe_ms,
            w.wall_ms,
            if args.verify_determinism {
                if w.determinism_verified { "OK" } else { "FAILED" }
            } else {
                "not-checked"
            }
        );
    }
    eprintln!(
        "  TOTAL leaves={} fheMs={} wallMs={} processWallMs={}",
        manifest.total_leaves,
        manifest.total_fhe_ms,
        manifest.total_wall_ms,
        started.elapsed().as_millis()
    );
    eprintln!("  manifest -> {}", args.out.display());

    if !all_ok {
        for w in &manifest.workloads {
            for l in w.leaves.iter().filter(|l| !l.ok) {
                eprintln!(
                    "  MISMATCH {}#{} opcode={} decrypted={} claimed={}",
                    w.workload_id, l.index, l.opcode, l.decrypted, l.claimed
                );
            }
        }
    }
    if args.verify_determinism && !determinism_all_ok {
        eprintln!("  DETERMINISM CHECK FAILED");
        return Ok(false);
    }
    Ok(all_ok)
}

fn execute_workload(
    workload: &TraceWorkload,
    client_key: &ClientKey,
    args: &Args,
) -> Result<WorkloadRecord> {
    let leaves: &[TraceLeaf] = match args.limit_leaves {
        Some(n) => &workload.leaves[..n.min(workload.leaves.len())],
        None => &workload.leaves,
    };

    let ct_dir = args.ciphertext_dir.join(&workload.workload_id);
    fs::create_dir_all(&ct_dir)
        .with_context(|| format!("failed to create {}", ct_dir.display()))?;

    eprintln!(
        "[fhe-executor] workload {} ({} leaves)",
        workload.workload_id,
        leaves.len()
    );

    let wall_started = Instant::now();
    let mut inputs: Vec<InputRecord> = Vec::new();
    let mut leaf_records: Vec<LeafRecord> = Vec::new();
    let mut store: InputStore = HashMap::new();
    let mut previous: Option<(FheUint64, String)> = None;
    let mut fhe_ms: u128 = 0;
    let mut outputs = Vec::new();
    let mut original_inputs = HashMap::new();
    let explicit = workload.circuit_version.is_some();
    if explicit && workload.circuit_version.as_deref() != Some("compliance-explicit-dag-v1") {
        bail!("unsupported circuit version");
    }
    for leaf in leaves {
        if leaf.index != outputs.len() { bail!("non-dense instruction indices"); }
        if leaf.lhs_ref.is_some() != explicit || leaf.rhs_ref.is_some() != explicit {
            bail!("mixed legacy/explicit trace or missing circuit version");
        }
        if explicit && (leaf.lhs_from_previous || leaf.rhs_from_previous) { bail!("ambiguous legacy source flags"); }

        let claimed = leaf.claimed.value()?;
        let lhs_clear = leaf.lhs.value()?;
        let rhs_clear = leaf.rhs.value()?;

        let scalar_rhs = rhs_is_public_scalar(&leaf.opcode);
        let unary = is_unary(&leaf.opcode);
        if leaf.operands.as_ref().is_some_and(|xs| !xs.is_empty()) {
            bail!("operand-array sums are not the adjudicated ADD_CHAIN operation");
        }
        let (lhs_ct, lhs_handle, lhs_source) = if let Some(source) = &leaf.lhs_ref {
            explicit_operand(source, lhs_clear, leaf.index, "lhs", &outputs, client_key, &ct_dir,
                &mut inputs, &mut store, &mut original_inputs)?
        } else if leaf.lhs_from_previous {
            let (ct, handle) = previous
                .clone()
                .ok_or_else(|| anyhow!("leaf {} claims lhsFromPrevious with no previous leaf", leaf.index))?;
            (ct, handle, Source::PreviousOutput)
        } else {
            let (ct, handle) = encrypt_input(
                client_key,
                lhs_clear,
                leaf.index,
                "lhs",
                &ct_dir,
                &mut inputs,
                &mut store,
                args.verify_determinism,
            )?;
            (ct, handle, Source::AuthenticatedInput)
        };

        // --- resolve rhs -------------------------------------------------
        let (rhs_ct, rhs_handle, rhs_source) = if let Some(source) = &leaf.rhs_ref {
            if scalar_rhs && source.public_value()?.is_none() { bail!("control operand must be public"); }
            let (ct, handle, kind) = explicit_operand(source, rhs_clear, leaf.index, "rhs", &outputs,
                client_key, &ct_dir, &mut inputs, &mut store, &mut original_inputs)?;
            (Some(ct), handle, kind)
        } else if scalar_rhs || unary {
            // The divisor / shift amount is a public constant, never encrypted;
            // unary leaves ignore rhs; ADD_CHAIN uses rhs as a public step count.
            (None, ZERO_HANDLE.to_string(), Source::PublicConstant)
        } else if leaf.rhs_from_previous {
            let (ct, handle) = previous
                .clone()
                .ok_or_else(|| anyhow!("leaf {} claims rhsFromPrevious with no previous leaf", leaf.index))?;
            (Some(ct), handle, Source::PreviousOutput)
        } else {
            let (ct, handle) = encrypt_input(
                client_key,
                rhs_clear,
                leaf.index,
                "rhs",
                &ct_dir,
                &mut inputs,
                &mut store,
                args.verify_determinism,
            )?;
            (Some(ct), handle, Source::AuthenticatedInput)
        };

        // --- homomorphic evaluation --------------------------------------
        let op_started = Instant::now();
        let checked = tfhe_pod_demo::micro_isa::evaluate(
            &leaf.opcode,
            &lhs_ct,
            rhs_ct.as_ref(),
            rhs_clear,
        )
        .with_context(|| format!("leaf {} ({}) failed", leaf.index, leaf.opcode))?;
        let result = checked.value;
        let ms = op_started.elapsed().as_millis();
        fhe_ms += ms;

        let result_bytes = serialize_ct(&result, CIPHERTEXT_LIMIT_BYTES)?;
        let result_handle = keccak_handle(&result_bytes);

        // Persist the result ciphertext, not just its handle. A dispute over
        // this leaf is settled by evaluating FHE.eq over the CIPHERTEXTS (see
        // ct-inspect leaf-decision), which needs the operand ciphertexts of the
        // disputed leaf -- and an operand that came from the previous leaf IS a
        // stored result. Byte-comparing handles would not need this file; that
        // is exactly the comparison the protocol no longer makes, because a
        // differently scheduled evaluation of the same operation returns a
        // different -- equally valid -- ciphertext.
        let result_path = ct_dir.join(format!("result-{}.ct", leaf.index));
        fs::write(&result_path, &result_bytes)
            .with_context(|| format!("failed to write {}", result_path.display()))?;

        let decrypted: u64 = result.decrypt(client_key);
        let valid_operands: bool = checked.valid.decrypt(client_key);
        let ok = valid_operands && decrypted == claimed;

        eprintln!(
            "    leaf {:>3} {:<9} {:>6} ms  {}  decrypted={} claimed={}",
            leaf.index,
            leaf.opcode,
            ms,
            if ok { "OK " } else { "BAD" },
            decrypted,
            claimed
        );

        leaf_records.push(LeafRecord {
            index: leaf.index,
            opcode: leaf.opcode.clone(),
            result_handle: result_handle.clone(),
            decrypted: decrypted.to_string(),
            claimed: claimed.to_string(),
            ok,
            ms,
            lhs_handle,
            rhs_handle,
            lhs_source: lhs_source.as_str().to_string(),
            rhs_source: rhs_source.as_str().to_string(),
            lhs_ref: leaf.lhs_ref.clone(),
            rhs_ref: leaf.rhs_ref.clone(),
        });

        outputs.push(result.clone());
        previous = Some((result, result_handle));
    }

    // --- determinism: replay the same chain from the SAME stored input
    //     ciphertexts and require byte-identical result handles.
    //
    //     WHAT THIS DOES AND DOES NOT ESTABLISH. It is an IN-PROCESS
    //     self-consistency check: the same objects, evaluated twice in this
    //     process, serialize the same way. It does NOT establish that another
    //     process, or this one under different load, reproduces these bytes --
    //     measured here, it often does not, because tfhe-rs evaluates in
    //     parallel and the schedule is visible in the result ciphertext. No
    //     part of the protocol depends on reproducing the bytes: a disputed
    //     leaf is settled by FHE.eq over the ciphertexts, which is insensitive
    //     to scheduling (see scripts/leaf-decision.mjs and
    //     scripts/leaf-decision-stability.test.mjs).
    //     ---------------------------------------------------------------
    let determinism_verified = if args.verify_determinism {
        eprintln!(
            "[fhe-executor] re-executing {} for determinism",
            workload.workload_id
        );
        let replay_handles = replay_workload(leaves, &store)?;
        let mut same = replay_handles.len() == leaf_records.len();
        if same {
            for (rec, handle) in leaf_records.iter().zip(replay_handles.iter()) {
                if &rec.result_handle != handle {
                    eprintln!(
                        "    DETERMINISM MISMATCH leaf {}: {} != {}",
                        rec.index, rec.result_handle, handle
                    );
                    same = false;
                }
            }
        }
        eprintln!(
            "[fhe-executor] determinism for {}: {}",
            workload.workload_id,
            if same { "OK" } else { "FAILED" }
        );
        same
    } else {
        false
    };

    Ok(WorkloadRecord {
        workload_id: workload.workload_id.clone(),
        circuit_version: workload.circuit_version.clone(),
        leaf_count: leaves.len(),
        fhe_ms,
        wall_ms: wall_started.elapsed().as_millis(),
        determinism_verified,
        inputs,
        leaves: leaf_records,
    })
}

// Cache by public record identity, never by plaintext equality. Per-use files
// remain aliases of the same bytes for compatibility with the leaf tool.
#[allow(clippy::too_many_arguments)]
fn explicit_operand(source: &SourceRef, clear: u64, leaf_index: usize, side: &str,
    outputs: &[FheUint64], client_key: &ClientKey, ct_dir: &Path, inputs: &mut Vec<InputRecord>,
    store: &mut InputStore, originals: &mut HashMap<usize, (FheUint64, u64)>)
    -> Result<(FheUint64, String, Source)> {
    if source.public_value()?.is_some_and(|value| value != clear) { bail!("public constant mismatch"); }
    let ct = source.resolve(outputs, |index| {
        if let Some((ct, value)) = originals.get(&index) {
            if *value != clear { bail!("input {index} has inconsistent owner values"); }
            return Ok(ct.clone());
        }
        let ct = FheUint64::try_encrypt(clear, client_key).map_err(|e| anyhow!("encrypt: {e:?}"))?;
        originals.insert(index, (ct.clone(), clear));
        Ok(ct)
    })?;
    let bytes = serialize_ct(&ct, CIPHERTEXT_LIMIT_BYTES)?;
    let handle = if let Some(value) = source.public_value()? { format!("0x{value:064x}") }
        else { keccak_handle(&bytes) };
    let kind = match source {
        SourceRef::Input { .. } => {
            fs::write(ct_dir.join(format!("input-{leaf_index}-{side}.ct")), &bytes)?;
            inputs.push(InputRecord { leaf_index, side: side.to_string(), clear: clear.to_string(),
                handle: handle.clone(), bytes: bytes.len() });
            store.insert((leaf_index, side.to_string()), ct.clone());
            Source::AuthenticatedInput
        },
        SourceRef::Output { .. } => Source::PreviousOutput,
        SourceRef::Constant { .. } => Source::PublicConstant,
    };
    Ok((ct, handle, kind))
}

/// Encrypt a fresh authenticated input, persist it, and record it.
#[allow(clippy::too_many_arguments)]
fn encrypt_input(
    client_key: &ClientKey,
    clear: u64,
    leaf_index: usize,
    side: &str,
    ct_dir: &Path,
    inputs: &mut Vec<InputRecord>,
    store: &mut InputStore,
    keep_for_replay: bool,
) -> Result<(FheUint64, String)> {
    let ct = FheUint64::try_encrypt(clear, client_key)
        .map_err(|err| anyhow!("encryption of {clear} failed: {err:?}"))?;
    let bytes = serialize_ct(&ct, CIPHERTEXT_LIMIT_BYTES)?;
    let handle = keccak_handle(&bytes);
    let path = ct_dir.join(format!("input-{leaf_index}-{side}.ct"));
    fs::write(&path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    inputs.push(InputRecord {
        leaf_index,
        side: side.to_string(),
        clear: clear.to_string(),
        handle: handle.clone(),
        bytes: bytes.len(),
    });
    if keep_for_replay {
        store.insert((leaf_index, side.to_string()), ct.clone());
    }
    Ok((ct, handle))
}

/// Second pass: identical chain, identical *stored* input ciphertexts (nothing
/// is re-encrypted, so any difference is attributable to the server-side
/// evaluation rather than to fresh encryption randomness).
fn replay_workload(leaves: &[TraceLeaf], store: &InputStore) -> Result<Vec<String>> {
    let mut previous: Option<FheUint64> = None;
    let mut handles = Vec::with_capacity(leaves.len());
    let mut outputs = Vec::new();

    for leaf in leaves {
        let rhs_clear = leaf.rhs.value()?;
        let scalar_rhs = rhs_is_public_scalar(&leaf.opcode);
        let unary = is_unary(&leaf.opcode);
        if leaf.operands.as_ref().is_some_and(|xs| !xs.is_empty()) {
            bail!("operand-array sums are not the adjudicated ADD_CHAIN operation");
        }
        let lhs_ct = if let Some(source) = &leaf.lhs_ref {
            source.resolve(&outputs, |_| store.get(&(leaf.index, "lhs".to_string())).cloned()
                .ok_or_else(|| anyhow!("missing stored lhs")))?
        } else if leaf.lhs_from_previous {
            previous
                .clone()
                .ok_or_else(|| anyhow!("replay: leaf {} has no previous", leaf.index))?
        } else {
            store
                .get(&(leaf.index, "lhs".to_string()))
                .cloned()
                .ok_or_else(|| anyhow!("replay: missing stored lhs for leaf {}", leaf.index))?
        };

        let rhs_ct = if let Some(source) = &leaf.rhs_ref {
            Some(source.resolve(&outputs, |_| store.get(&(leaf.index, "rhs".to_string())).cloned()
                .ok_or_else(|| anyhow!("missing stored rhs")))?)
        } else if scalar_rhs || unary {
            None
        } else if leaf.rhs_from_previous {
            Some(
                previous
                    .clone()
                    .ok_or_else(|| anyhow!("replay: leaf {} has no previous", leaf.index))?,
            )
        } else {
            Some(
                store
                    .get(&(leaf.index, "rhs".to_string()))
                    .cloned()
                    .ok_or_else(|| anyhow!("replay: missing stored rhs for leaf {}", leaf.index))?,
            )
        };

        let result = eval_opcode(
            &leaf.opcode,
            &lhs_ct,
            rhs_ct.as_ref(),
            rhs_clear,
            &[],
        )?;
        let bytes = serialize_ct(&result, CIPHERTEXT_LIMIT_BYTES)?;
        handles.push(keccak_handle(&bytes));
        outputs.push(result.clone());
        previous = Some(result);
    }

    Ok(handles)
}
