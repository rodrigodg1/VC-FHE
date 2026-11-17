//! Explicit-DAG execution with a separate public evaluator and owner checker.
//! Canonical mode fixes the reference evaluator; legacy execute remains separate.
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{env, fs, path::Path, time::Instant};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{ClientKey, CompressedPublicKey, ConfigBuilder, FheBool, FheUint64, ServerKey, generate_keys, set_server_key};
use tfhe_pod_demo::micro_isa::evaluate;

const LIMIT: u64 = 1 << 33;
const CT_LIMIT: u64 = 1 << 26;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Source { Input { index: usize }, Output { index: usize }, Constant { value: String } }
#[derive(Deserialize)]
struct Input { id: String, r#type: String }
#[derive(Deserialize)]
struct Instruction { index: usize, opcode: String, lhs: Source, rhs: Source }
#[derive(Deserialize)]
struct Program { version: String, inputs: Vec<Input>, instructions: Vec<Instruction>, output: Source }

fn digest(bytes: &[u8]) -> String { format!("0x{}", hex::encode(Keccak256::digest(bytes))) }
fn write_ct(path: &Path, value: &FheUint64) -> Result<String> {
    let mut bytes = Vec::new();
    safe_serialize(value, &mut bytes, CT_LIMIT).map_err(|e| anyhow!("{e}"))?;
    fs::write(path, &bytes)?; Ok(digest(&bytes))
}
fn read_ct(path: &Path) -> Result<FheUint64> {
    safe_deserialize(fs::read(path)?.as_slice(), CT_LIMIT).map_err(|e| anyhow!("{e}"))
}
fn validate(program: &Program) -> Result<()> {
    ensure!(program.version == "compliance-explicit-dag-v1", "unsupported circuit version");
    ensure!(!program.instructions.is_empty(), "empty circuit");
    let mut ids = std::collections::HashSet::new();
    for input in &program.inputs { ensure!(input.r#type == "uint64" && ids.insert(&input.id), "ambiguous input"); }
    for (i, instruction) in program.instructions.iter().enumerate() {
        ensure!(instruction.index == i, "unordered instruction");
        ensure!(matches!(instruction.opcode.as_str(), "ADD" | "SUB" | "MUL" | "DIV" | "MOD" |
            "EQ" | "LT" | "GT" | "MIN" | "BITAND" | "BITOR" | "BITXOR" | "SHR" |
            "CAST_U8" | "ADD_CHAIN"), "unsupported opcode");
        for source in [&instruction.lhs, &instruction.rhs] {
            match source {
                Source::Input { index } => ensure!(*index < program.inputs.len(), "missing input"),
                Source::Output { index } => ensure!(*index < i, "forward or cyclic reference"),
                Source::Constant { value } => { value.parse::<u64>().context("constant outside uint64")?; }
            }
        }
        if tfhe_pod_demo::micro_isa::rhs_is_public_scalar(&instruction.opcode) {
            ensure!(matches!(instruction.rhs, Source::Constant { .. }), "private control operand");
        }
    }
    ensure!(matches!(program.output, Source::Output { index } if index == program.instructions.len()-1), "output is not terminal");
    Ok(())
}
fn resolve(source: &Source, inputs: &[FheUint64], outputs: &[FheUint64]) -> Result<FheUint64> {
    match source {
        Source::Input { index } => inputs.get(*index).cloned().ok_or_else(|| anyhow!("missing input")),
        Source::Output { index } => outputs.get(*index).cloned().ok_or_else(|| anyhow!("missing output")),
        Source::Constant { value } => Ok(FheUint64::encrypt_trivial(value.parse::<u64>()?)),
    }
}
fn source_handle(source: &Source, inputs: &[String], outputs: &[String]) -> Result<String> {
    Ok(match source {
        Source::Input { index } => inputs[*index].clone(),
        Source::Output { index } => outputs[*index].clone(),
        Source::Constant { value } => format!("0x{:064x}", value.parse::<u64>()?),
    })
}

fn main() -> Result<()> {
    // Explicitly fix the thread pool, independent of the caller's environment.
    rayon::ThreadPoolBuilder::new().num_threads(1).build_global()?;
    let args: Vec<String> = env::args().collect();
    let arg = |i| args.get(i).map(String::as_str).ok_or_else(|| anyhow!("missing argument {i}"));
    match arg(1)? {
        "setup" => {
            // Laboratory orchestration: key generation is trusted; encryption
            // runs in a child receiving only the public bundle and owner data.
            let started = Instant::now();
            let raw = fs::read(arg(2)?)?;
            let program: Program = serde_json::from_slice(&raw)?; validate(&program)?;
            let values: Vec<serde_json::Value> = serde_json::from_slice(&fs::read(arg(3)?)?)?;
            ensure!(values.len() == program.inputs.len(), "input count mismatch");
            let root = Path::new(arg(4)?);
            ensure!(!root.join("public").exists() && !root.join("owner").exists(), "setup never overwrites keys");
            fs::create_dir_all(root.join("public"))?; fs::create_dir_all(root.join("owner"))?;
            fs::write(root.join("public/program.json"), &raw)?;
            let (ck, sk) = generate_keys(ConfigBuilder::default());
            let mut bytes = Vec::new();
            safe_serialize(&sk, &mut bytes, LIMIT).map_err(|e| anyhow!("{e}"))?;
            fs::write(root.join("public/server-key.bin"), &bytes)?;
            bytes.clear(); safe_serialize(&ck, &mut bytes, LIMIT).map_err(|e| anyhow!("{e}"))?;
            fs::write(root.join("owner/client-key.bin"), &bytes)?;
            let pk = CompressedPublicKey::new(&ck);
            bytes.clear(); safe_serialize(&pk, &mut bytes, LIMIT).map_err(|e| anyhow!("{e}"))?;
            fs::write(root.join("public/encryption-key.bin"), &bytes)?;
            let public_key_digest = digest(&bytes);
            drop(pk); drop(ck); drop(sk); drop(bytes);
            let encryption = std::process::Command::new(env::current_exe()?)
                .arg("encrypt-inputs").arg(root.join("public")).arg(arg(3)?).output()?;
            ensure!(encryption.status.success(), "public encryption failed: {}", String::from_utf8_lossy(&encryption.stderr));
            let encryption: serde_json::Value = serde_json::from_slice(&encryption.stdout)?;
            let report = json!({"mode":"owner-setup","inputEncryption":"tfhe-compressed-public-key-v1",
                "inputs":values.len(),"programDigest":digest(&raw),"publicKeyDigest":public_key_digest,
                "elapsedMs":started.elapsed().as_millis(),"ownerEncryption":encryption});
            fs::write(root.join("public/preparation.json"), serde_json::to_vec_pretty(&report)?)?;
            println!("{}", report);
        }
        "encrypt-inputs" => {
            // No client key or secret-key path is accepted by owner encryption.
            ensure!(args.len() == 4, "encrypt-inputs PUBLIC_BUNDLE OWNER_VALUES");
            let public = Path::new(arg(2)?);
            let program: Program = serde_json::from_slice(&fs::read(public.join("program.json"))?)?;
            validate(&program)?;
            let values: Vec<serde_json::Value> = serde_json::from_slice(&fs::read(arg(3)?)?)?;
            ensure!(values.len() == program.inputs.len(), "input count mismatch");
            let key_bytes = fs::read(public.join("encryption-key.bin"))?;
            let pk: CompressedPublicKey = safe_deserialize(key_bytes.as_slice(), LIMIT).map_err(|e| anyhow!("{e}"))?;
            let started = Instant::now();
            for (i, value) in values.iter().enumerate() {
                let clear = value.as_u64().or_else(|| value.as_str()?.parse().ok()).ok_or_else(|| anyhow!("input {i} not uint64"))?;
                let output = public.join(format!("input-{i}.ct"));
                ensure!(!output.exists(), "owner encryption never overwrites an input");
                write_ct(&output, &FheUint64::encrypt(clear, &pk))?;
            }
            println!("{}", json!({"inputEncryption":"tfhe-compressed-public-key-v1","inputs":values.len(),
                "publicKeyDigest":digest(&key_bytes),"elapsedMs":started.elapsed().as_millis(),"secretKeyReads":0}));
        }
        "execute" | "execute-canonical" | "execute-canonical-fault-fixture" => {
            // execute PUBLIC_BUNDLE OUTPUT [TAMPER_INDEX TAMPER_VALUE]... Fault
            // selection is never included in the public trace manifest.
            let public = Path::new(arg(2)?); let out = Path::new(arg(3)?);
            let canonical = arg(1)? != "execute";
            if canonical { ensure!(cfg!(feature="fixed-fft-experiment"), "canonical execution requires pinned FFT"); }
            if arg(1)? == "execute-canonical" { ensure!(args.len() == 4, "canonical evaluation accepts no fault instructions"); }
            ensure!(!out.exists(), "execution output already exists");
            ensure!(args.len() >= 4 && (args.len() - 4) % 2 == 0, "faults require index/value pairs");
            let mut tamper = std::collections::BTreeMap::new();
            for pair in args[4..].chunks(2) {
                ensure!(tamper.insert(pair[0].parse::<usize>()?, pair[1].parse::<u64>()?).is_none(), "duplicate fault index");
            }
            let raw = fs::read(public.join("program.json"))?;
            let program: Program = serde_json::from_slice(&raw)?; validate(&program)?;
            for index in tamper.keys() { ensure!(*index < program.instructions.len(), "fault outside trace"); }
            let key = fs::read(public.join("server-key.bin"))?;
            let sk: ServerKey = safe_deserialize(key.as_slice(), LIMIT).map_err(|e| anyhow!("{e}"))?;
            set_server_key(sk);
            let mut inputs = Vec::new(); let mut input_handles = Vec::new();
            for i in 0..program.inputs.len() {
                let path = public.join(format!("input-{i}.ct"));
                let bytes = fs::read(&path)?;
                input_handles.push(digest(&bytes));
                inputs.push(safe_deserialize(bytes.as_slice(), CT_LIMIT).map_err(|e| anyhow!("{e}"))?);
            }
            fs::create_dir_all(out)?;
            let mut outputs = Vec::new(); let mut handles = Vec::new(); let mut rows = Vec::new();
            let wall = Instant::now();
            for instruction in &program.instructions {
                let lhs = resolve(&instruction.lhs, &inputs, &outputs)?;
                let rhs = resolve(&instruction.rhs, &inputs, &outputs)?;
                let scalar = match &instruction.rhs { Source::Constant { value } => value.parse()?, _ => 0 };
                let started = Instant::now();
                let checked = evaluate(&instruction.opcode, &lhs, Some(&rhs), scalar)?;
                let result = match tamper.get(&instruction.index) {
                    Some(value) => FheUint64::encrypt_trivial(*value),
                    _ => checked.value,
                };
                let handle = write_ct(&out.join(format!("result-{}.ct", instruction.index)), &result)?;
                let mut guard = Vec::new();
                safe_serialize(&checked.valid, &mut guard, CT_LIMIT).map_err(|e| anyhow!("{e}"))?;
                fs::write(out.join(format!("guard-{}.ct", instruction.index)), guard)?;
                rows.push(json!({"index":instruction.index,"opcode":instruction.opcode,
                    "lhs":instruction.lhs,"rhs":instruction.rhs,
                    "lhsHandle":source_handle(&instruction.lhs,&input_handles,&handles)?,
                    "rhsHandle":source_handle(&instruction.rhs,&input_handles,&handles)?,
                    "resultHandle":handle,"ms":started.elapsed().as_millis()}));
                handles.push(handle); outputs.push(result);
            }
            let report = json!({"version":if canonical { "canonical-dag-execution-v1" } else { "explicit-dag-execution-experiment-v1" },
                "programDigest":digest(&raw),"serverKeyDigest":digest(&key),"inputs":input_handles,
                "profile":{"tfhe":"1.4.0","threads":1,"fixedFFT":cfg!(feature="fixed-fft-experiment"),
                    "arch":env::consts::ARCH,"os":env::consts::OS,"binaryDigest":digest(&fs::read(env::current_exe()?)?)},
                "leaves":rows,"terminalHandle":handles.last(),"elapsedMs":wall.elapsed().as_millis(),
                "publicDecisionsReleased":0,"boundary":"public execution transcript; certificates require independent verification"});
            fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&report)?)?;
            println!("{}",report);
        }
        "leaf" => {
            // Public one-step recomputation. No client-key path is accepted.
            // leaf PUBLIC_BUNDLE OPERATOR_TRACE INDEX OUTPUT_CT
            ensure!(args.len() == 6, "leaf expects four arguments");
            ensure!(cfg!(feature="fixed-fft-experiment"), "canonical leaf requires pinned FFT");
            let public = Path::new(arg(2)?); let trace = Path::new(arg(3)?);
            let index: usize = arg(4)?.parse()?;
            let program_bytes = fs::read(public.join("program.json"))?;
            let program: Program = serde_json::from_slice(&program_bytes)?;
            validate(&program)?;
            let instruction = program.instructions.get(index).context("leaf outside program")?;
            let key_bytes = fs::read(public.join("server-key.bin"))?;
            let sk: ServerKey = safe_deserialize(key_bytes.as_slice(), LIMIT)
                .map_err(|e| anyhow!("{e}"))?;
            set_server_key(sk);
            let resolve_one = |source: &Source| -> Result<(FheUint64, String)> {
                let bytes = match source {
                    Source::Input { index } => fs::read(public.join(format!("input-{index}.ct")))?,
                    Source::Output { index } => fs::read(trace.join(format!("result-{index}.ct")))?,
                    Source::Constant { value } => return Ok((FheUint64::encrypt_trivial(value.parse::<u64>()?), format!("0x{:064x}", value.parse::<u64>()?))),
                };
                Ok((safe_deserialize(bytes.as_slice(), CT_LIMIT).map_err(|e| anyhow!("{e}"))?, digest(&bytes)))
            };
            let (lhs, lhs_handle) = resolve_one(&instruction.lhs)?;
            let (rhs, rhs_handle) = resolve_one(&instruction.rhs)?;
            let scalar = match &instruction.rhs { Source::Constant { value } => value.parse()?, _ => 0 };
            let wall = Instant::now();
            let expected = evaluate(&instruction.opcode, &lhs, Some(&rhs), scalar)?;
            let output = Path::new(arg(5)?); ensure!(!output.exists(), "leaf output already exists");
            let handle = write_ct(output, &expected.value)?;
            println!("{}", json!({"index":index,"resultHandle":handle,"lhsHandle":lhs_handle,"rhsHandle":rhs_handle,
                "programDigest":digest(&program_bytes),"serverKeyDigest":digest(&key_bytes),
                "elapsedMs":wall.elapsed().as_millis(),"plaintextOpenings":0}));
        }
        "release-output" => {
            // Trusted local KMS simulator primitive; authorization is enforced
            // by the separate release service BEFORE invoking this mode.
            ensure!(args.len() == 5, "release-output expects key, exact ciphertext and authorized digest");
            let ck: ClientKey = safe_deserialize(fs::read(arg(2)?)?.as_slice(), LIMIT).map_err(|e| anyhow!("{e}"))?;
            let bytes = fs::read(arg(3)?)?;
            ensure!(digest(&bytes) == arg(4)?, "unauthorized ciphertext digest");
            let ct: FheUint64 = safe_deserialize(bytes.as_slice(), CT_LIMIT).map_err(|e| anyhow!("{e}"))?;
            let value: u64 = ct.decrypt(&ck);
            println!("{}", json!({"value":value.to_string(),"backend":"local-full-key-kms-simulation"}));
        }
        "owner-check" => {
            // owner-check OWNER_KEY TRACE_DIR EXPECTED_OUTPUT: laboratory check
            // only. The public evaluator never enters this branch or reads ck.
            let ck: ClientKey = safe_deserialize(fs::read(arg(2)?)?.as_slice(),LIMIT).map_err(|e| anyhow!("{e}"))?;
            let trace = Path::new(arg(3)?);
            let manifest: serde_json::Value = serde_json::from_slice(&fs::read(trace.join("manifest.json"))?)?;
            let leaves = manifest["leaves"].as_array().ok_or_else(|| anyhow!("invalid manifest"))?;
            let expected_leaves: Option<Vec<String>> = if args.len() > 5 {
                Some(serde_json::from_slice(&fs::read(arg(5)?)?)?)
            } else { None };
            if let Some(expected) = &expected_leaves { ensure!(expected.len() == leaves.len(), "reference length mismatch"); }
            for i in 0..leaves.len() {
                let valid: FheBool = safe_deserialize(fs::read(trace.join(format!("guard-{i}.ct")))?.as_slice(), CT_LIMIT).map_err(|e| anyhow!("{e}"))?;
                let bit: bool = valid.decrypt(&ck); ensure!(bit, "arithmetic guard failed at {i}");
                if let Some(expected) = &expected_leaves {
                    let actual: u64 = read_ct(&trace.join(format!("result-{i}.ct")))?.decrypt(&ck);
                    ensure!(actual == expected[i].parse::<u64>()?, "plaintext mismatch at {i}");
                }
            }
            let value: u64 = read_ct(&trace.join(format!("result-{}.ct",leaves.len()-1)))?.decrypt(&ck);
            ensure!(value == arg(4)?.parse::<u64>()?, "terminal result differs from reference");
            println!("{}",json!({"checkedGuards":leaves.len(),"terminalResultMatches":true}));
        }
        _ => bail!("expected setup, execute, leaf, release-output or owner-check"),
    }
    Ok(())
}
