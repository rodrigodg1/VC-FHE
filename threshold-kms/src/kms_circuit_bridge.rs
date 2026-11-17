// Public-key preparation and unchanged explicit-DAG executor under the KMS keyset.
use anyhow::{ensure, Result};
use std::path::Path;
pub fn worker(job_path: &Path) -> Result<()> {
    let job: serde_json::Value = serde_json::from_slice(&std::fs::read(job_path)?)?;
    match job["action"].as_str() {
        Some("kms-circuit") => {
            let args: Vec<String> = serde_json::from_value(job["args"].clone())?;
            super::tops_kms_circuit::run(args, Path::new(job["result"].as_str().unwrap()))?;
        }
        Some("kms-encrypt-circuit") => {
            let root = Path::new(job["publicDir"].as_str().unwrap());
            ensure!(!root.exists(), "public bundle already exists");
            let pk = super::tops_compatible_fhe::load_public(Path::new(job["publicKey"].as_str().unwrap()))?;
            let sk = super::tops_compatible_fhe::load_server(Path::new(job["evaluationKey"].as_str().unwrap()))?;
            tfhe::set_server_key(sk);
            let values: Vec<u64> = serde_json::from_value(job["values"].clone())?;
            ensure!(job["program"]["inputs"].as_array().unwrap().len()==values.len(), "input count mismatch");
            std::fs::create_dir_all(root)?;
            std::fs::write(root.join("program.json"),serde_json::to_vec(&job["program"])?)?;
            std::fs::write(root.join("kms-keyset.json"),serde_json::to_vec(&job["keyset"])?)?;
            std::fs::copy(job["publicKey"].as_str().unwrap(),root.join("encryption-key.bin"))?;
            std::fs::copy(job["evaluationKey"].as_str().unwrap(),root.join("server-key.bin"))?;
            for (i,value) in values.iter().enumerate() {
                let ct: tfhe::FheUint64 = threshold_execution::tfhe_internals::utils::expanded_encrypt(&pk,*value,64)?;
                super::tops_compatible_fhe::write_cipher(&root.join(format!("input-{i}.ct")),&ct)?;
            }
        }
        _ => anyhow::bail!("unsupported KMS circuit action"),
    }
    Ok(())
}
