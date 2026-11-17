// Appended ONLY to the isolated upstream v0.13.20 integration-test module.
// Isolated functional/resource feasibility, not evaluation evidence.
// No existing application ciphertext, release policy or contract is replaced.
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn tops_local_four_party_pilot() -> Result<()> {
    let start = std::time::Instant::now();
    let max_iter: usize = std::env::var("TOPS_KMS_PILOT_MAX_POLLS")?.parse()?;
    anyhow::ensure!(max_iter > 0, "positive polling limit required");
    let selected = std::env::var("TOPS_KMS_PILOT_PARAMS").unwrap_or_else(|_| "Test".into());
    let (parameters, label) = match selected.as_str() {
        "Test" => (FheParameter::Test, "Test-INSECURE"),
        "Default" => (FheParameter::Default, "Default"),
        _ => anyhow::bail!("unsupported pilot parameter set"),
    };
    let mut spec = kms_lib::testing::material::TestMaterialSpec::threshold_signing_only(4);
    // The builder generates signing/recipient keys after material setup. An
    // empty copy list prevents the manager's cwd/keys fallback from importing
    // fixture keys or failing when that optional directory does not exist.
    spec.required_keys.clear();
    if parameters == FheParameter::Default {
        spec.material_type = kms_lib::testing::material::MaterialType::Default;
    }
    eprintln!("TOPS_PILOT {label}: starting four native services and live PRSS");
    let environment = ThresholdTestEnv::builder()
        .with_test_name("tops-local-four-party-pilot")
        .with_party_count(4)
        .with_material_spec(spec)
        .with_material_manager(kms_lib::testing::material::TestMaterialManager::new(None))
        .force_isolated()
        .with_prss()
        .build().await?;
    let material = environment.material_dir;
    let servers = environment.servers;
    let config_path = generate_threshold_cli_config(&material, &servers, 4, parameters)?;
    assert_eq!(servers.len(), 4);
    let config: CoreClientConfig = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    assert_eq!(config.fhe_params, Some(parameters));
    // The native integration helper is stricter than client_local_threshold.toml:
    // it requests 3 matching public responses and 3 reconstruction responses.
    assert_eq!((config.num_majority, config.num_reconstruct), (3, 3));
    eprintln!("TOPS_PILOT four native parties; {label} parameters; real preprocessing/keygen requested");

    // No insecure-keygen, dummy preprocessing, imported full FHE key or
    // pre-generated FHE keyset: only signing/recipient keys are supplied by setup.
    let key_id = real_preproc_and_keygen(&config_path, material.path(), max_iter, false).await?;
    let key_time = start.elapsed().as_secs_f64();
    eprintln!("TOPS_PILOT preprocessing/keygen completed after {key_time:.2} seconds");
    let ciphertext_path = material.path().join("tops-pilot-u64.bin");
    let encrypt = CCCommand::Encrypt(cipher_params(
        "0x2A", FheType::Euint64, KeyId::from_str(&key_id)?,
        1, false, true, false, Some(ciphertext_path.clone()),
    ));
    execute_cmd(&cmd_config(&config_path, encrypt, max_iter), material.path()).await
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    assert!(ciphertext_path.is_file());
    let before = std::fs::read(&ciphertext_path)?;
    let file = CipherFile { input_path: ciphertext_path.clone(), batch_size: 1,
        num_requests: 1, parallel_requests: 1, inter_request_delay_ms: 0, extra_data: None };
    let mut stages = Vec::new();
    for (name, command) in [
        ("public-decrypt", CCCommand::PublicDecrypt(CipherArguments::FromFile(file.clone()))),
        ("recipient-decrypt", CCCommand::UserDecrypt(CipherArguments::FromFile(file))),
    ] {
        eprintln!("TOPS_PILOT starting {name}");
        let now = std::time::Instant::now();
        // The upstream client verifies response authentication and compares the
        // reconstructed plaintext to the synthetic expected value in the file.
        let result = execute_cmd(&cmd_config(&config_path, command, max_iter), material.path()).await
            .map_err(|e| anyhow::anyhow!("{name} failed: {e}"))?;
        assert_eq!(result.len(), 1);
        assert_eq!(std::fs::read(&ciphertext_path)?, before);
        stages.push(serde_json::json!({"operation":name,"seconds":now.elapsed().as_secs_f64(),
            "clientResult":format!("{result:?}")}));
    }
    let result = serde_json::json!({
        "status":"passed", "classification":"isolated-upstream-functional-pilot",
        "parties":4, "fheParameters":label, "allPartiesOnline":true,
        "serviceIsolation":"four native service instances within one upstream test process",
        "transport":"loopback RPC; upstream native helper uses no TLS",
        "publicMatchingResponses":config.num_majority,
        "recipientReconstructionResponses":config.num_reconstruct,
        "clientWaitsForAllResponses":true, "preprocessing":"PreprocKeyGen",
        "maxClientPollIterations":max_iter,
        "keyGeneration":"KeyGen", "preloadedFheKey":false,
        "keyId":key_id,
        "syntheticPlaintext":42, "ciphertextBytes":before.len(),
        "setupAndKeygenSeconds":key_time, "decryption":stages,
        "evaluationIntegration":false, "homomorphicApplicationEvaluated":false,
        "requestContext":"upstream diagnostic defaults and dummy external handle; no application authorization",
        "productionParametersEvaluated":parameters == FheParameter::Default,
        "independentAdministrativeDomains":false
    });
    let output = std::env::var("TOPS_KMS_PILOT_DETAIL")?;
    std::fs::write(std::path::Path::new(&output).with_extension("cipher.bin"), &before)?;
    std::fs::write(output, serde_json::to_vec_pretty(&result)?)?;
    eprintln!("TOPS_PILOT passed");
    Ok(())
}
