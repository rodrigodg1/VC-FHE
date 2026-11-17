//! ct-inspect — independent auditor tool for the ciphertext artifacts.
//!
//! It exists so that `scripts/verify-encrypted-execution.mjs` can CHECK, rather
//! than assume, two things the JavaScript side cannot see:
//!
//!   * `inspect`  a stored `.ct` file really safe-deserializes as an
//!                `FheUint64` under tfhe-rs 1.4.0, and the client key stored
//!                next to it decrypts it to the value the manifest declares.
//!
//!   * `replay`   the leaves of a workload re-execute from the SAME stored
//!                input ciphertexts under the PUBLIC server key (the client key
//!                is loaded only with `--decrypt`, and only to report the
//!                plaintext of each result). This is the auditor's
//!                reproduction: nothing is re-encrypted, so any divergence is
//!                attributable to the homomorphic evaluation itself.
//!                With `--decide` each replayed leaf is additionally compared
//!                to the committed result ciphertext by `FHE.eq`, which is the
//!                comparison the protocol actually makes. Ciphertext BYTES are
//!                not reproducible across processes; the equality BIT is.
//!
//!   * `leaf-decision`
//!                adjudicates one isolated leaf the way the coprocessor does:
//!                recompute it homomorphically from its operand ciphertexts,
//!                evaluate `valid_operands AND FHE.eq(recomputed, claimed)` against each party's
//!                claimed result ciphertext, and decrypt ONLY the two bits.
//!
//! Two further modes exist to explain a divergence rather than guess at it:
//!
//!   * `roundtrip` asks whether a `safe_serialize`/`safe_deserialize` round trip
//!                 of the operands changes the result (measured: it does not)
//!   * `keytest`   asks whether the published server key produces different
//!                 results from the generated one (measured: it does not)
//!
//! Every mode prints a single JSON object on stdout; progress goes to stderr.
//!
//! Usage:
//!   ct-inspect inspect --client-key <path> --ct <path> [--ct <path> ...]
//!   ct-inspect replay  --server-key <path> --ct-dir <dir> --traces <path>
//!                      --workload <id> [--limit-leaves <n>]
//!                      [--decrypt --client-key <path>] [--decide]
//!   ct-inspect leaf-decision --server-key <path> --client-key <path>
//!                      --opcode <OP> --lhs <path> [--rhs <path>]
//!                      [--rhs-scalar <n>] [--operand <path> ...]
//!                      --claim <label>=<path> [--claim <label>=<path>]
//!   ct-inspect roundtrip --client-key <path> --server-key <path>
//!   ct-inspect keytest

use tfhe_pod_demo::trace_sources::SourceRef;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::json;
use sha3::{Digest, Keccak256};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{ClientKey, FheBool, FheUint64, ServerKey, set_server_key};

const CIPHERTEXT_LIMIT_BYTES: u64 = 1 << 26;
const KEY_LIMIT_BYTES: u64 = 1 << 33;

// ---------------------------------------------------------------------------
// traces.json model (same shape the executor consumes)
// ---------------------------------------------------------------------------

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
    lhs: NumLike,
    rhs: NumLike,
    #[allow(dead_code)]
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
    leaves: Vec<TraceLeaf>,
}

#[derive(Debug, Clone, Deserialize)]
struct TraceFile {
    workloads: Vec<TraceWorkload>,
}

// ---------------------------------------------------------------------------
// shared helpers (identical to fhe-executor.rs)
// ---------------------------------------------------------------------------

fn keccak_handle(bytes: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn serialize_ct(value: &FheUint64) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    safe_serialize(value, &mut buffer, CIPHERTEXT_LIMIT_BYTES)
        .map_err(|err| anyhow!("safe_serialize failed: {err}"))?;
    Ok(buffer)
}

fn serialize_bool(value: &FheBool) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    safe_serialize(value, &mut buffer, CIPHERTEXT_LIMIT_BYTES)
        .map_err(|err| anyhow!("safe_serialize of FheBool failed: {err}"))?;
    Ok(buffer)
}

/// Compute guard AND value equality homomorphically, then decrypt only the
/// combined bit. Different ciphertext serializations of the same valid value
/// are accepted. Range errors never become valid through modular wraparound.
/// Returns (bit, handle of the combined ebool, elapsed milliseconds).
fn homomorphic_eq_bit(
    expected: &tfhe_pod_demo::micro_isa::CheckedEvaluation,
    claimed: &FheUint64,
    client_key: &ClientKey,
) -> Result<(bool, String, u128)> {
    let started = Instant::now();
    let equal: FheBool = expected.accepts(claimed);
    let ms = started.elapsed().as_millis();
    let handle = keccak_handle(&serialize_bool(&equal)?);
    let bit: bool = equal.decrypt(client_key);
    Ok((bit, handle, ms))
}

fn rhs_is_public_scalar(opcode: &str) -> bool {
    tfhe_pod_demo::micro_isa::rhs_is_public_scalar(opcode)
}

fn is_unary(opcode: &str) -> bool {
    matches!(opcode, "CAST_U8")
}

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

fn load_ciphertext(path: &Path) -> Result<(FheUint64, Vec<u8>)> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read ciphertext {}", path.display()))?;
    let ct: FheUint64 = safe_deserialize(bytes.as_slice(), CIPHERTEXT_LIMIT_BYTES).map_err(|err| {
        anyhow!(
            "{} is not a safe-serialized FheUint64: {err}",
            path.display()
        )
    })?;
    Ok((ct, bytes))
}

// ---------------------------------------------------------------------------
// modes
// ---------------------------------------------------------------------------

fn mode_inspect(client_key_path: &Path, ct_paths: &[PathBuf]) -> Result<()> {
    let key_bytes = fs::read(client_key_path)
        .with_context(|| format!("failed to read client key {}", client_key_path.display()))?;
    let client_key: ClientKey = safe_deserialize(key_bytes.as_slice(), KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("client key is not a safe-serialized ClientKey: {err}"))?;
    eprintln!(
        "[ct-inspect] client key {} bytes deserialized",
        key_bytes.len()
    );

    let mut items = Vec::new();
    for path in ct_paths {
        let (ct, bytes) = load_ciphertext(path)?;
        // Round-tripping through safe_serialize proves the on-disk bytes are the
        // canonical encoding of the object we just deserialized.
        let reserialized = serialize_ct(&ct)?;
        let value: u64 = ct.decrypt(&client_key);
        items.push(json!({
            "path": path.to_string_lossy(),
            "bytes": bytes.len(),
            "deserializedAs": "FheUint64",
            "reserializedBytes": reserialized.len(),
            "reserializeIdentical": reserialized == bytes,
            "handle": keccak_handle(&bytes),
            "reserializedHandle": keccak_handle(&reserialized),
            "headerHex": hex::encode(&bytes[..bytes.len().min(24)]),
            "decrypted": value.to_string(),
        }));
        eprintln!("[ct-inspect] {} -> {}", path.display(), value);
    }

    println!(
        "{}",
        json!({
            "mode": "inspect",
            "tfheVersion": "1.4.0",
            "clientKeyPath": client_key_path.to_string_lossy(),
            "clientKeyBytes": key_bytes.len(),
            "items": items,
        })
    );
    Ok(())
}

fn mode_replay(
    server_key_path: &Path,
    client_key_path: Option<&Path>,
    ct_dir: &Path,
    traces_path: &Path,
    workload_id: &str,
    limit_leaves: Option<usize>,
    decide: bool,
) -> Result<()> {
    let raw = fs::read_to_string(traces_path)
        .with_context(|| format!("failed to read traces {}", traces_path.display()))?;
    let traces: TraceFile = serde_json::from_str(&raw)?;
    let workload = traces
        .workloads
        .iter()
        .find(|w| w.workload_id == workload_id)
        .ok_or_else(|| anyhow!("workload {workload_id} not present in {}", traces_path.display()))?;

    let key_bytes = fs::read(server_key_path)
        .with_context(|| format!("failed to read server key {}", server_key_path.display()))?;
    let server_key_digest = keccak_handle(&key_bytes);
    let started = Instant::now();
    let server_key: ServerKey = safe_deserialize(key_bytes.as_slice(), KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("server key is not a safe-serialized ServerKey: {err}"))?;
    eprintln!(
        "[ct-inspect] server key {} bytes deserialized in {} ms (digest {})",
        key_bytes.len(),
        started.elapsed().as_millis(),
        server_key_digest
    );
    set_server_key(server_key);

    // Optional: the auditor may also hold the decryption key, in which case the
    // replayed results are decrypted too. This separates "the same ciphertext
    // bytes" from "the same plaintext": a replay that produces a different
    // ciphertext may still produce the same value.
    let client_key: Option<ClientKey> = match client_key_path {
        Some(path) => {
            let bytes = fs::read(path)
                .with_context(|| format!("failed to read client key {}", path.display()))?;
            Some(
                safe_deserialize(bytes.as_slice(), KEY_LIMIT_BYTES)
                    .map_err(|err| anyhow!("client key: {err}"))?,
            )
        }
        None => None,
    };

    let dir = ct_dir.join(workload_id);
    let load_side = |leaf: usize, side: &str| -> Result<FheUint64> {
        let path = dir.join(format!("input-{leaf}-{side}.ct"));
        Ok(load_ciphertext(&path)?.0)
    };

    let mut previous: Option<FheUint64> = None;
    let mut leaves_out = Vec::new();
    let mut outputs = Vec::new();
    let mut loaded_files = Vec::new();

    let leaves: &[TraceLeaf] = match limit_leaves {
        Some(n) => &workload.leaves[..n.min(workload.leaves.len())],
        None => &workload.leaves,
    };
    for leaf in leaves {
        if leaf.index != outputs.len() { bail!("non-dense instruction indices"); }
        if leaf.lhs_ref.is_some() != leaf.rhs_ref.is_some() { bail!("mixed explicit/legacy sources"); }
        for (source, clear) in [(&leaf.lhs_ref, &leaf.lhs), (&leaf.rhs_ref, &leaf.rhs)] {
            if let Some(source) = source {
                if source.public_value()?.is_some_and(|value| clear.value().ok() != Some(value)) {
                    bail!("public constant mismatch");
                }
            }
        }
        let rhs_clear = leaf.rhs.value()?;
        let scalar_rhs = rhs_is_public_scalar(&leaf.opcode);
        let unary = is_unary(&leaf.opcode);
        if leaf.operands.as_ref().is_some_and(|xs| !xs.is_empty()) {
            bail!("operand-array sums are not the adjudicated ADD_CHAIN operation");
        }
        let (lhs_ct, lhs_source) = if let Some(source) = &leaf.lhs_ref {
            (source.resolve(&outputs, |_| load_side(leaf.index, "lhs"))?, source.name())
        } else if leaf.lhs_from_previous {
            (
                previous
                    .clone()
                    .ok_or_else(|| anyhow!("leaf {} has no previous output", leaf.index))?,
                "PREVIOUS_OUTPUT",
            )
        } else {
            loaded_files.push(format!("input-{}-lhs.ct", leaf.index));
            (load_side(leaf.index, "lhs")?, "AUTHENTICATED_INPUT")
        };
        let _ = leaf.lhs.value()?; // the clear value is never used in replay

        let (rhs_ct, rhs_source) = if let Some(source) = &leaf.rhs_ref {
            if scalar_rhs && source.public_value()?.is_none() { bail!("control operand must be public"); }
            (Some(source.resolve(&outputs, |_| load_side(leaf.index, "rhs"))?), source.name())
        } else if scalar_rhs || unary {
            (None, "PUBLIC_CONSTANT")
        } else if leaf.rhs_from_previous {
            (
                Some(
                    previous
                        .clone()
                        .ok_or_else(|| anyhow!("leaf {} has no previous output", leaf.index))?,
                ),
                "PREVIOUS_OUTPUT",
            )
        } else {
            loaded_files.push(format!("input-{}-rhs.ct", leaf.index));
            (Some(load_side(leaf.index, "rhs")?), "AUTHENTICATED_INPUT")
        };

        let op_started = Instant::now();
        let checked = tfhe_pod_demo::micro_isa::evaluate(
            &leaf.opcode,
            &lhs_ct,
            rhs_ct.as_ref(),
            rhs_clear,
        )
        .with_context(|| format!("leaf {} ({}) failed", leaf.index, leaf.opcode))?;
        let ms = op_started.elapsed().as_millis();
        let result = checked.value.clone();
        let bytes = serialize_ct(&result)?;
        let handle = keccak_handle(&bytes);
        eprintln!(
            "[ct-inspect] replay leaf {:>3} {:<9} {:>6} ms -> {}",
            leaf.index, leaf.opcode, ms, handle
        );
        let decrypted = client_key
            .as_ref()
            .map(|key| -> u64 { result.decrypt(key) })
            .map(|value| value.to_string());

        // --- the leaf DECISION, as the protocol makes it -------------------
        // Not "are the bytes the ones that were committed?" but "does this
        // re-execution agree with the committed result under FHE.eq?". The
        // committed result ciphertext is on disk next to the inputs; the answer
        // is one homomorphically derived bit.
        let (decision_bit, decision_handle, decision_ms, committed_handle) = if decide {
            let key = client_key
                .as_ref()
                .ok_or_else(|| anyhow!("--decide requires --decrypt and a client key"))?;
            let committed_path = dir.join(format!("result-{}.ct", leaf.index));
            let (committed_ct, committed_bytes) = load_ciphertext(&committed_path)?;
            let (bit, ebool_handle, eq_ms) = homomorphic_eq_bit(&checked, &committed_ct, key)?;
            eprintln!(
                "[ct-inspect]   decide leaf {:>3}: bytes {} committed, FHE.eq -> {}",
                leaf.index,
                if handle == keccak_handle(&committed_bytes) { "==" } else { "!=" },
                bit
            );
            (
                Some(bit),
                Some(ebool_handle),
                Some(eq_ms),
                Some(keccak_handle(&committed_bytes)),
            )
        } else {
            (None, None, None, None)
        };

        leaves_out.push(json!({
            "index": leaf.index,
            "opcode": leaf.opcode,
            "resultHandle": handle,
            "bytes": bytes.len(),
            "ms": ms,
            "lhsSource": lhs_source,
            "rhsSource": rhs_source,
            "decrypted": decrypted,
            "committedResultHandle": committed_handle,
            "decisionBit": decision_bit,
            "decisionEboolHandle": decision_handle,
            "decisionMs": decision_ms,
        }));
        outputs.push(result.clone());
        previous = Some(result);
    }

    println!(
        "{}",
        json!({
            "mode": "replay",
            "tfheVersion": "1.4.0",
            "workloadId": workload_id,
            "tracesPath": traces_path.to_string_lossy(),
            "ciphertextDir": dir.to_string_lossy(),
            "serverKeyPath": server_key_path.to_string_lossy(),
            "serverKeyBytes": key_bytes.len(),
            "serverKeyDigest": server_key_digest,
            "clientKeyLoaded": client_key.is_some(),
            "decide": decide,
            "inputCiphertextFiles": loaded_files,
            "leaves": leaves_out,
        })
    );
    Ok(())
}

/// `leaf-decision` — the adjudication of ONE isolated leaf, as the coprocessor
/// performs it.
///
/// Given the operand ciphertexts of the disputed leaf and the result ciphertext
/// each party claims, it
///
///   1. RECOMPUTES the leaf homomorphically from the operands (this is the
///      reference; nobody's stored result is trusted as the reference),
///   2. evaluates `FHE.eq(recomputed, claimed)` for each claim, and
///   3. decrypts ONLY the two resulting bits.
///
/// Nothing else is decrypted: not the operands, not the recomputed result, not
/// either claim. The bits are what `settleLeafViaAttestedDecision` consumes
/// after t+1 signatures over them.
///
/// It also reports `keccak256` of every ciphertext it loaded and of the one it
/// recomputed, so the caller can bind the ciphertexts to the handles that are on
/// chain -- and so that a recomputation whose BYTES differ from the committed
/// result is visible as such while still deciding correctly.
fn mode_leaf_decision(
    server_key_path: &Path,
    client_key_path: &Path,
    opcode: &str,
    lhs_path: Option<&Path>,
    lhs_scalar: Option<u64>,
    rhs_path: Option<&Path>,
    rhs_scalar: u64,
    operand_paths: &[PathBuf],
    claim_paths: &[(String, PathBuf)],
) -> Result<()> {
    let sk_bytes = fs::read(server_key_path)
        .with_context(|| format!("failed to read server key {}", server_key_path.display()))?;
    let server_key: ServerKey = safe_deserialize(sk_bytes.as_slice(), KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("server key is not a safe-serialized ServerKey: {err}"))?;
    set_server_key(server_key);

    let ck_bytes = fs::read(client_key_path)
        .with_context(|| format!("failed to read client key {}", client_key_path.display()))?;
    let client_key: ClientKey = safe_deserialize(ck_bytes.as_slice(), KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("client key is not a safe-serialized ClientKey: {err}"))?;

    let (lhs_ct, lhs_handle) = match (lhs_path, lhs_scalar) {
        (Some(path), None) => { let (ct, bytes) = load_ciphertext(path)?; (ct, keccak_handle(&bytes)) },
        (None, Some(value)) => (FheUint64::encrypt_trivial(value), format!("0x{value:064x}")),
        _ => bail!("exactly one of --lhs and --lhs-scalar is required"),
    };
    let rhs_loaded = match rhs_path {
        Some(path) => Some(load_ciphertext(path)?),
        None => Some((FheUint64::encrypt_trivial(rhs_scalar), Vec::new())),
    };
    let mut extra_operands = Vec::new();
    let mut operand_handles = Vec::new();
    for path in operand_paths {
        let (ct, bytes) = load_ciphertext(path)?;
        operand_handles.push(keccak_handle(&bytes));
        extra_operands.push(ct);
    }

    let started = Instant::now();
    if !extra_operands.is_empty() {
        bail!("operand-array sums are not the adjudicated ADD_CHAIN operation");
    }
    let checked = tfhe_pod_demo::micro_isa::evaluate(
        opcode,
        &lhs_ct,
        rhs_loaded.as_ref().map(|(ct, _)| ct),
        rhs_scalar,
    )
    .with_context(|| format!("recomputation of opcode {opcode} failed"))?;
    let recompute_ms = started.elapsed().as_millis();
    let recomputed = &checked.value;
    let recomputed_handle = keccak_handle(&serialize_ct(recomputed)?);
    eprintln!(
        "[ct-inspect] recomputed {opcode} in {recompute_ms} ms -> {recomputed_handle}"
    );

    let mut decisions = Vec::new();
    for (label, path) in claim_paths {
        let (claimed_ct, claimed_bytes) = load_ciphertext(path)?;
        let claimed_handle = keccak_handle(&claimed_bytes);
        let (bit, ebool_handle, eq_ms) = homomorphic_eq_bit(&checked, &claimed_ct, &client_key)?;
        eprintln!(
            "[ct-inspect] FHE.eq(recomputed, {label}) = {bit} in {eq_ms} ms \
             (claim handle {claimed_handle}, bytes {} the recomputation)",
            if claimed_handle == recomputed_handle { "==" } else { "!=" }
        );
        decisions.push(json!({
            "label": label,
            "claimPath": path.to_string_lossy(),
            "claimedHandle": claimed_handle,
            "claimBytesEqualRecomputed": claimed_handle == recomputed_handle,
            "eboolHandle": ebool_handle,
            "valid": bit,
            "eqMs": eq_ms,
        }));
    }

    println!(
        "{}",
        json!({
            "mode": "leaf-decision",
            "tfheVersion": "1.4.0",
            "opcode": opcode,
            "decidedBy": "checked-uint64-v1: FHE guard AND value equality; only the combined bit is decrypted",
            "lhsHandle": lhs_handle,
            "rhsHandle": rhs_path.and_then(|_| rhs_loaded.as_ref().map(|(_, bytes)| keccak_handle(bytes))),
            "rhsScalar": rhs_path.is_none().then_some(rhs_scalar),
            "operandHandles": operand_handles,
            "recomputedHandle": recomputed_handle,
            "recomputeMs": recompute_ms,
            "serverKeyDigest": keccak_handle(&sk_bytes),
            "decisions": decisions,
        })
    );
    Ok(())
}

/// Isolation experiment for handle reproducibility.
///
/// Same key, same cleartexts. Branch A operates on the ciphertext objects as
/// they come out of `try_encrypt`; branch B operates on the very same
/// ciphertexts after a `safe_serialize` -> `safe_deserialize` round trip (which
/// is what an auditor loading the published `.ct` files gets). Branch C repeats
/// branch A to separate "nondeterministic operation" from "the round trip
/// changes the operand".
fn mode_roundtrip(client_key_path: &Path, server_key_path: &Path) -> Result<()> {
    let ck_bytes = fs::read(client_key_path)?;
    let client_key: ClientKey = safe_deserialize(ck_bytes.as_slice(), KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("client key: {err}"))?;
    let sk_bytes = fs::read(server_key_path)?;
    let server_key: ServerKey = safe_deserialize(sk_bytes.as_slice(), KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("server key: {err}"))?;
    set_server_key(server_key);

    let a: FheUint64 = FheUint64::try_encrypt(1928u64, &client_key)
        .map_err(|err| anyhow!("encrypt failed: {err:?}"))?;
    let b: FheUint64 = FheUint64::try_encrypt(100u64, &client_key)
        .map_err(|err| anyhow!("encrypt failed: {err:?}"))?;

    let a_bytes = serialize_ct(&a)?;
    let b_bytes = serialize_ct(&b)?;
    let a2: FheUint64 = safe_deserialize(a_bytes.as_slice(), CIPHERTEXT_LIMIT_BYTES)
        .map_err(|err| anyhow!("round-trip a: {err}"))?;
    let b2: FheUint64 = safe_deserialize(b_bytes.as_slice(), CIPHERTEXT_LIMIT_BYTES)
        .map_err(|err| anyhow!("round-trip b: {err}"))?;

    let mut results = Vec::new();
    for (label, x, y) in [
        ("fresh-objects", &a, &b),
        ("round-tripped", &a2, &b2),
        ("fresh-objects-again", &a, &b),
        ("round-tripped-again", &a2, &b2),
    ] {
        for opcode in ["ADD", "LT", "MUL"] {
            let started = Instant::now();
            let z = eval_opcode(opcode, x, Some(y), 0, &[])?;
            let handle = keccak_handle(&serialize_ct(&z)?);
            eprintln!(
                "[ct-inspect] {label:<20} {opcode:<4} {:>6} ms -> {handle}",
                started.elapsed().as_millis()
            );
            results.push(json!({"branch": label, "opcode": opcode, "handle": handle}));
        }
    }

    println!(
        "{}",
        json!({
            "mode": "roundtrip",
            "serializedInputsIdentical": serialize_ct(&a2)? == a_bytes,
            "results": results,
        })
    );
    Ok(())
}

/// Second isolation experiment: does the PUBLISHED server key reproduce the
/// results the in-memory generated server key produced? Same fresh key pair,
/// same operand ciphertexts, three evaluations: with the generated key, with
/// that key after a `safe_serialize` -> `safe_deserialize` round trip (what an
/// auditor loads from `keys/server-key.bin`), and with the generated key again.
fn mode_keytest() -> Result<()> {
    use tfhe::{ConfigBuilder, generate_keys};

    let config = ConfigBuilder::default().build();
    let (client_key, server_key): (ClientKey, ServerKey) = generate_keys(config);
    let mut sk_bytes = Vec::new();
    safe_serialize(&server_key, &mut sk_bytes, KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("serialize server key: {err}"))?;
    let server_key_rt: ServerKey = safe_deserialize(sk_bytes.as_slice(), KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("deserialize server key: {err}"))?;
    let mut sk_bytes_rt = Vec::new();
    safe_serialize(&server_key_rt, &mut sk_bytes_rt, KEY_LIMIT_BYTES)
        .map_err(|err| anyhow!("re-serialize server key: {err}"))?;
    eprintln!(
        "[ct-inspect] server key {} bytes, re-serialized {} bytes, identical={}",
        sk_bytes.len(),
        sk_bytes_rt.len(),
        sk_bytes == sk_bytes_rt
    );

    set_server_key(server_key.clone());
    let a: FheUint64 = FheUint64::try_encrypt(1928u64, &client_key)
        .map_err(|err| anyhow!("encrypt failed: {err:?}"))?;
    let b: FheUint64 = FheUint64::try_encrypt(100u64, &client_key)
        .map_err(|err| anyhow!("encrypt failed: {err:?}"))?;

    let mut results = Vec::new();
    for (label, key) in [
        ("generated-key", &server_key),
        ("round-tripped-key", &server_key_rt),
        ("generated-key-again", &server_key),
    ] {
        set_server_key(key.clone());
        for opcode in ["ADD", "LT", "MUL"] {
            let started = Instant::now();
            let z = eval_opcode(opcode, &a, Some(&b), 0, &[])?;
            let handle = keccak_handle(&serialize_ct(&z)?);
            eprintln!(
                "[ct-inspect] {label:<20} {opcode:<4} {:>6} ms -> {handle}",
                started.elapsed().as_millis()
            );
            results.push(json!({"branch": label, "opcode": opcode, "handle": handle}));
        }
    }

    println!(
        "{}",
        json!({
            "mode": "keytest",
            "serverKeyBytes": sk_bytes.len(),
            "serverKeyReserializeIdentical": sk_bytes == sk_bytes_rt,
            "results": results,
        })
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or_else(|| anyhow!("usage: ct-inspect <inspect|replay> [flags]"))?;

    let mut client_key = PathBuf::from("artifacts/fhe/ciphertexts/keys/client-key.bin");
    let mut server_key = PathBuf::from("artifacts/fhe/ciphertexts/keys/server-key.bin");
    let mut ct_dir = PathBuf::from("artifacts/fhe/ciphertexts");
    let mut traces = PathBuf::from("artifacts/fhe/traces.json");
    let mut workload: Option<String> = None;
    let mut cts: Vec<PathBuf> = Vec::new();
    let mut limit_leaves: Option<usize> = None;
    let mut decrypt = false;
    let mut decide = false;
    let mut opcode: Option<String> = None;
    let mut lhs: Option<PathBuf> = None;
    let mut lhs_scalar: Option<u64> = None;
    let mut rhs: Option<PathBuf> = None;
    let mut rhs_scalar: u64 = 0;
    let mut operands: Vec<PathBuf> = Vec::new();
    let mut claims: Vec<(String, PathBuf)> = Vec::new();

    while let Some(flag) = args.next() {
        let mut next = |name: &str| -> Result<String> {
            args.next()
                .ok_or_else(|| anyhow!("flag {name} requires a value"))
        };
        match flag.as_str() {
            "--client-key" => client_key = PathBuf::from(next("--client-key")?),
            "--server-key" => server_key = PathBuf::from(next("--server-key")?),
            "--ct" => cts.push(PathBuf::from(next("--ct")?)),
            "--ct-dir" => ct_dir = PathBuf::from(next("--ct-dir")?),
            "--traces" => traces = PathBuf::from(next("--traces")?),
            "--workload" => workload = Some(next("--workload")?),
            "--limit-leaves" => limit_leaves = Some(next("--limit-leaves")?.parse::<usize>()?),
            "--decrypt" => decrypt = true,
            "--decide" => decide = true,
            "--opcode" => opcode = Some(next("--opcode")?),
            "--lhs" => lhs = Some(PathBuf::from(next("--lhs")?)),
            "--rhs" => rhs = Some(PathBuf::from(next("--rhs")?)),
            "--lhs-scalar" => lhs_scalar = Some(next("--lhs-scalar")?.parse::<u64>()?),
            "--rhs-scalar" => rhs_scalar = next("--rhs-scalar")?.parse::<u64>()?,
            "--operand" => operands.push(PathBuf::from(next("--operand")?)),
            "--claim" => {
                // --claim <label>=<path>
                let raw = next("--claim")?;
                let (label, path) = raw
                    .split_once('=')
                    .ok_or_else(|| anyhow!("--claim expects <label>=<path>, got {raw:?}"))?;
                claims.push((label.to_string(), PathBuf::from(path)));
            }
            other => bail!("unknown flag {other}"),
        }
    }

    match mode.as_str() {
        "inspect" => {
            if cts.is_empty() {
                bail!("inspect requires at least one --ct <path>");
            }
            mode_inspect(&client_key, &cts)
        }
        "replay" => {
            let workload = workload.ok_or_else(|| anyhow!("replay requires --workload <id>"))?;
            if decide && !decrypt {
                bail!("--decide requires --decrypt (the equality bit has to be decrypted)");
            }
            mode_replay(
                &server_key,
                if decrypt { Some(client_key.as_path()) } else { None },
                &ct_dir,
                &traces,
                &workload,
                limit_leaves,
                decide,
            )
        }
        "leaf-decision" => {
            let opcode = opcode.ok_or_else(|| anyhow!("leaf-decision requires --opcode <OP>"))?;
            if claims.is_empty() {
                bail!("leaf-decision requires at least one --claim <label>=<path>");
            }
            mode_leaf_decision(
                &server_key,
                &client_key,
                &opcode,
                lhs.as_deref(),
                lhs_scalar,
                rhs.as_deref(),
                rhs_scalar,
                &operands,
                &claims,
            )
        }
        "roundtrip" => mode_roundtrip(&client_key, &server_key),
        "keytest" => mode_keytest(),
        other => bail!(
            "unknown mode {other} (expected inspect|replay|leaf-decision|roundtrip|keytest)"
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ERROR: {err:?}");
            ExitCode::from(2)
        }
    }
}
