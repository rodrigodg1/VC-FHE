//! seed-probe: does a deterministic tfhe-rs engine seed make the result
//! ciphertext of one leaf reproducible across processes?
//!
//! Loads the fixture keys and the two operands of leaf 0 (GT) of the
//! determinism-gate fixture, evaluates GT exactly as ct-inspect does, and
//! prints the keccak handle of the safe-serialized result. Run it N times as
//! independent processes and compare the handles.
//!
//!   PROBE_MODE=none   no seeding (baseline: what ct-inspect does today)
//!   PROBE_MODE=main   seed the calling thread's ShortintEngine only
//!   PROBE_MODE=pool   build the global rayon pool with the calling thread as a
//!                     worker and seed EVERY worker's ShortintEngine
//!   PROBE_SEED=<u128> seed value (default 42)
//!   PROBE_CT_DIR      fixture ciphertext dir (default: the canonical gate fixture)
//!   PROBE_LEAVES      how many leaves of the workload to replay in order (default 1)

use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use sha3::{Digest, Keccak256};
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::{DefaultRandomGenerator, Seed};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::engine::ShortintEngine;
use tfhe::{ClientKey, FheUint64, ServerKey, set_server_key};

const CIPHERTEXT_LIMIT_BYTES: u64 = 1 << 26;
const KEY_LIMIT_BYTES: u64 = 1 << 33;

fn seed_this_thread(seed: u128) {
    let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
    ShortintEngine::with_thread_local_mut(|engine| {
        *engine = ShortintEngine::new_from_seeder(&mut seeder);
    });
}

fn keccak(bytes: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(bytes);
    format!("0x{}", hex::encode(h.finalize()))
}

fn load_ct(path: &PathBuf) -> Result<FheUint64> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    safe_deserialize(bytes.as_slice(), CIPHERTEXT_LIMIT_BYTES)
        .map_err(|e| anyhow!("{}: {e}", path.display()))
}

fn main() -> Result<()> {
    let mode = env::var("PROBE_MODE").unwrap_or_else(|_| "none".into());
    let seed: u128 = env::var("PROBE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(42);
    let leaves: usize = env::var("PROBE_LEAVES").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let ct_dir = PathBuf::from(env::var("PROBE_CT_DIR").unwrap_or_else(|_| {
        "artifacts/fhe/stability-test-canonical/ciphertexts".into()
    }));
    let threads: usize = env::var("RAYON_NUM_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(1);

    if mode == "pool" {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .use_current_thread()
            .start_handler(move |_| seed_this_thread(seed))
            .build_global()
            .map_err(|e| anyhow!("rayon pool: {e}"))?;
        // use_current_thread registers the caller as a worker, but the start
        // handler runs only for spawned workers: seed the caller explicitly.
        seed_this_thread(seed);
    } else if mode == "main" {
        seed_this_thread(seed);
    }

    let sk_bytes = fs::read(ct_dir.join("keys/server-key.bin"))?;
    let server_key: ServerKey =
        safe_deserialize(sk_bytes.as_slice(), KEY_LIMIT_BYTES).map_err(|e| anyhow!("server key: {e}"))?;
    set_server_key(server_key);
    let ck_bytes = fs::read(ct_dir.join("keys/client-key.bin"))?;
    let client_key: ClientKey =
        safe_deserialize(ck_bytes.as_slice(), KEY_LIMIT_BYTES).map_err(|e| anyhow!("client key: {e}"))?;

    // Leaf 0 of regulatory_qoe_compliance is GT(lhs, rhs) on authenticated inputs;
    // the following leaves of that workload are also GT on fresh inputs, so a
    // multi-leaf probe replays them the same way.
    let wl = ct_dir.join("regulatory_qoe_compliance");
    for leaf in 0..leaves {
        let lhs = load_ct(&wl.join(format!("input-{leaf}-lhs.ct")))?;
        let rhs = load_ct(&wl.join(format!("input-{leaf}-rhs.ct")))?;
        let out: FheUint64 = FheUint64::cast_from(FheOrd::gt(&lhs, &rhs));
        let mut buf = Vec::new();
        safe_serialize(&out, &mut buf, CIPHERTEXT_LIMIT_BYTES).map_err(|e| anyhow!("serialize: {e}"))?;
        let value: u64 = out.decrypt(&client_key);
        let handle = keccak(&buf);
        // PROBE_DUMP=<dir>: write the serialized result as <dir>/<handle>.bin so
        // that two divergent outputs can be compared byte by byte.
        if let Ok(dir) = env::var("PROBE_DUMP") {
            fs::create_dir_all(&dir)?;
            fs::write(format!("{dir}/leaf{leaf}-{}.bin", &handle[2..14]), &buf)?;
        }
        println!("mode={mode} seed={seed} threads={threads} leaf={leaf} value={value} bytes={} handle={handle}", buf.len());
    }
    Ok(())
}
