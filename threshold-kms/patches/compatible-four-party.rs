// Integration of public FHE preparation/conversion with real upstream UserDecrypt.
// Test-only topology: four native services, one process, loopback, synthetic inputs.
#[tokio::test]
async fn tops_public_fhe_worker() -> Result<()> {
    if let Ok(job) = std::env::var("TOPS_FHE_WORKER_JOB") {
        tops_compatible_fhe::worker(Path::new(&job))?;
    }
    Ok(())
}

fn tops_worker(job: &serde_json::Value, path: &Path) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(job)?)?;
    let output = Command::new(std::env::current_exe()?)
        .args(["tops_public_fhe_worker", "--exact", "--nocapture", "--test-threads=1"])
        .env("TOPS_FHE_WORKER_JOB", path).env("RAYON_NUM_THREADS", "1").output()?;
    anyhow::ensure!(output.status.success(), "public worker failed: {}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn tops_compatible_four_party() -> Result<()> {
    use alloy_primitives::keccak256;
    use kms_grpc::kms::v1::{CiphertextFormat, TypedCiphertext};
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_lib::client::client_wasm::Client;
    use kms_lib::client::user_decryption_wasm::ParsedUserDecryptionRequest;
    use kms_lib::cryptography::signatures::PrivateSigKey;
    use kms_lib::vault::storage::{file::FileStorage, StorageType};
    use kms_lib::vault::storage::crypto_material::get_core_verification_key;
    use tfhe::prelude::*;
    let selected = std::env::var("TOPS_KMS_PILOT_PARAMS")?;
    let parameters = match selected.as_str() {
        "Default" => FheParameter::Default, "Test" => FheParameter::Test,
        _ => anyhow::bail!("unsupported parameters"),
    };
    let max_iter: usize = std::env::var("TOPS_KMS_PILOT_MAX_POLLS")?.parse()?;
    let output = PathBuf::from(std::env::var("TOPS_KMS_PILOT_DETAIL")?);
    let root = output.with_extension("public");
    std::fs::create_dir(&root)?;
    let mut report = serde_json::json!({"status":"starting", "classification":"two-path-threshold-compatibility",
        "fheParameters":if parameters == FheParameter::Test {"Test-INSECURE"} else {"Default"},
        "evaluationIntegration":false,"parties":4,"corruptionThreshold":1,
        "serviceIsolation":"four native services in one process; loopback, no TLS",
        "preloadedFheKey":false,"fullFheKeyInApplication":false,"cases":[],"negativeTests":[]});
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    let mut spec = kms_lib::testing::material::TestMaterialSpec::threshold_signing_only(4);
    spec.required_keys.clear();
    if parameters == FheParameter::Default { spec.material_type = kms_lib::testing::material::MaterialType::Default; }
    eprintln!("TOPS_COMPAT starting four-party live PRSS and full preprocessing/DKG");
    let started = std::time::Instant::now();
    let env = ThresholdTestEnv::builder().with_test_name("tops-compatible-four-party")
        .with_party_count(4).with_material_spec(spec)
        .with_material_manager(kms_lib::testing::material::TestMaterialManager::new(None))
        .force_isolated().with_prss().build().await?;
    let config_path = generate_threshold_cli_config(&env.material_dir, &env.servers, 4, parameters)?;
    let config: CoreClientConfig = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    let key_id = real_preproc_and_keygen(&config_path, env.material_dir.path(), max_iter, false).await?;
    report["setupAndKeygenSeconds"] = started.elapsed().as_secs_f64().into();
    report["keyId"] = key_id.clone().into();
    report["status"] = "public-key-preparation".into();
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    let key = RequestId::from_str(&key_id)?;
    let fetched = fetch_public_elements(&key_id, &[PubDataType::CompressedXofKeySet, PubDataType::PublicKey],
        &config, env.material_dir.path(), false).await?;
    let prefix = format!("PUB-p{}", fetched[0].party_id);
    let compressed: CompressedXofKeySet = load_material_from_pub_storage(Some(env.material_dir.path()), &key,
        PubDataType::CompressedXofKeySet, Some(&prefix)).await;
    let (pk, sk) = compressed.decompress()?.into_raw_parts();
    let pk_file = root.join("encryption-key.bin");
    let sk_file = root.join("evaluation-key.bin");
    tops_compatible_fhe::write_cipher(&pk_file, &pk)?;
    tops_compatible_fhe::write_cipher(&sk_file, &sk)?;
    let key_descriptor=serde_json::json!({"encryptionKeyDigest":format!("0x{}",hex::encode(keccak256(std::fs::read(&pk_file)?))),
        "evaluationKeyDigest":format!("0x{}",hex::encode(keccak256(std::fs::read(&sk_file)?))),"tfhe":"1.6.1","parameters":selected});
    report["keysetDigest"] = format!("0x{}", hex::encode(keccak256(serde_json::to_vec(&key_descriptor)?))).into();
    report["keyDescriptor"]=key_descriptor;
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    tfhe::set_server_key(sk.clone());
    let a: tfhe::FheUint64 = threshold_execution::tfhe_internals::utils::expanded_encrypt(&pk, 13u64, 64)?;
    let b: tfhe::FheUint64 = threshold_execution::tfhe_internals::utils::expanded_encrypt(&pk, 3u64, 64)?;
    tops_compatible_fhe::write_cipher(&root.join("a.bin"), &a)?;
    tops_compatible_fhe::write_cipher(&root.join("b.bin"), &b)?;

    // Trusted recipient state. This fixed signing key is synthetic test material;
    // the ephemeral ML-KEM decryption key never enters the gateway/files/report.
    fetch_public_elements(&SIGNING_KEY_ID.to_string(), &[PubDataType::VerfKey, PubDataType::VerfAddress],
        &config, env.material_dir.path(), true).await?;
    let mut verification = HashMap::new();
    let mut endpoints = Vec::new();
    for core in &config.cores {
        let storage = FileStorage::new(Some(env.material_dir.path()), StorageType::PUB, Some(&core.object_folder))?;
        verification.insert(core.party_id as u32, get_core_verification_key(&storage).await?);
        let url = if core.address.starts_with("http") { core.address.clone() } else { format!("http://{}", core.address) };
        endpoints.push(CoreServiceEndpointClient::connect(url).await?);
    }
    let recipient_sk = PrivateSigKey::new(k256::ecdsa::SigningKey::from_slice(&[0x43; 32])?);
    let recipient_address = recipient_sk.verf_key().address();
    let params = if parameters == FheParameter::Test { kms_lib::consts::TEST_PARAM } else { kms_lib::consts::DEFAULT_PARAM };
    let mut client = Client::new(verification, recipient_address, Some(recipient_sk), params, Some(DecryptionMode::NoiseFloodSmall));
    let domain = alloy_sol_types::eip712_domain! { name: "VCFHE authorized output", version: "1", chain_id: 31337u64,
        verifying_contract: alloy_primitives::Address::from([0x56;20]), };
    let cases = vec![
        ("sum-carry-four", "SUM", vec![127u16;4], vec![[0u16,127u16];4]),
        ("sub-carry-four", "SUB", vec![511,127,127,127,127], vec![[511,511],[0,127],[0,127],[0,127],[0,127]]),
        ("sum-33", "SUM", (0..33).map(|i| i%5+1).collect(), vec![[1,5];33]),
        ("sub-33", "SUB", std::iter::once(511).chain(std::iter::repeat_n(15,32)).collect(),
            std::iter::once([511,511]).chain(std::iter::repeat_n([0,15],32)).collect()),
    ];
    let mut outputs = Vec::new();
    for (name, op, values, bounds) in cases {
        let dir = root.join(name); std::fs::create_dir(&dir)?;
        let plan = serde_json::json!({"profile":tops_compatible_fhe::PROFILE,"op":op,"bounds":bounds});
        eprintln!("TOPS_COMPAT preparing {name} with public-only worker");
        tops_worker(&serde_json::json!({"action":"prepare","evaluationKey":sk_file,"publicKey":pk_file,
            "plan":plan,"values":values}), &dir.join("prepare.json"))?;
        let bridge = PathBuf::from(std::env::var("TOPS_KMS_BINDING_SCRIPT")?);
        let bridge_config = serde_json::json!({"directory":dir,"plan":plan,"evaluationKey":sk_file,
            "keyId":key_id,"keysetDigest":report["keysetDigest"],"workerBinary":std::env::current_exe()?});
        std::fs::write(dir.join("binding-input.json"), serde_json::to_vec_pretty(&bridge_config)?)?;
        let binding = Command::new("node").arg(&bridge).arg(dir.join("binding-input.json"))
            .current_dir(std::env::var("TOPS_KMS_LINEAR_CWD")?).output()?;
        std::fs::write(dir.join("binding.log"), &binding.stdout)?;
        anyhow::ensure!(binding.status.success(), "binding failed: {}", String::from_utf8_lossy(&binding.stderr));
        let evidence: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("binding.json"))?)?;
        let expected: i64 = values.iter().enumerate().map(|(i,&m)| if op == "SUB" && i>0 {-(m as i64)} else {m as i64}).sum();
        outputs.push((name.to_string(), dir.join("output.bin"), tfhe::FheTypes::Uint16, expected as u64, evidence));
    }
    for (op, public, expected) in [
        ("ADD",0,16),("SUB",0,10),("MUL",0,39),("DIV",3,4),("MOD",3,1),
        ("EQ",0,0),("LT",0,0),("GT",0,1),("MIN",0,3),("BITAND",0,1),
        ("BITOR",0,15),("BITXOR",0,14),("SHR",2,3),("CAST_U8",0,13),("ADD_CHAIN",3,16),
    ] {
        let mut files = Vec::new();
        for run in 0..2 {
            let path = root.join(format!("{op}-{run}.bin"));
            tops_worker(&serde_json::json!({"action":"nonlinear","evaluationKey":sk_file,
                "left":root.join("a.bin"),"right":root.join("b.bin"),"opcode":op,"public":public,"output":path}),
                &root.join(format!("{op}-{run}.json")))?;
            files.push(path);
        }
        anyhow::ensure!(std::fs::read(&files[0])? == std::fs::read(&files[1])?, "independent replay differs for {op}");
        outputs.push((format!("nonlinear-{op}"), files[0].clone(), tfhe::FheTypes::Uint64, expected,
            serde_json::json!({"independentProcesses":2,"byteReplayMatches":true,"fullDisputeGame":false})));
    }
    for (index,(name,path,typ,expected,evidence)) in outputs.into_iter().enumerate() {
        eprintln!("TOPS_COMPAT recipient threshold decryption of {name}");
        let ciphertext = std::fs::read(&path)?;
        let digest = keccak256(&ciphertext);
        let request_id = derive_request_id(&format!("{key_id}:{name}:{index}"))?;
        let context = serde_json::to_vec(&serde_json::json!({"profile":"tops-kms-compatible-v1","keyId":key_id,
            "requestId":request_id.to_string(),"keyEpoch":DEFAULT_EPOCH_ID.to_string(),"mpcContext":DEFAULT_MPC_CONTEXT.to_string(),
            "case":name,"outputDigest":format!("0x{}",hex::encode(digest)),"outputType":typ as i32,
            "recipient":recipient_address.to_checksum(None),"keysetDigest":report["keysetDigest"],
            "evidenceDigest":format!("0x{}",hex::encode(keccak256(serde_json::to_vec(&evidence)?)))}))?;
        let (request, enc_pk, enc_sk) = client.user_decryption_request(&domain,
            vec![TypedCiphertext{ciphertext, fhe_type:typ as i32,external_handle:digest.to_vec(),
                ciphertext_format:CiphertextFormat::SmallExpanded as i32}], &request_id, &key,
            Some(&DEFAULT_MPC_CONTEXT), Some(&DEFAULT_EPOCH_ID), &context)?;
        let started = std::time::Instant::now();
        tops_recipient_validation::validate_request_metadata(&request)?;
        std::fs::write(root.join(format!("request-{index}.json")),serde_json::to_vec(&request)?)?;
        for endpoint in &mut endpoints { endpoint.user_decrypt(tonic::Request::new(request.clone())).await?; }
        let mut responses = Vec::new();
        for endpoint in &mut endpoints {
            let mut found = None;
            for _ in 0..max_iter {
                match endpoint.get_user_decryption_result(tonic::Request::new(request.request_id.clone().unwrap())).await {
                    Ok(response) => {found=Some(response.into_inner());break;},
                    Err(e) if e.code()==tonic::Code::Unavailable => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                    Err(e) => return Err(e.into()),
                }
            }
            responses.push(found.ok_or_else(||anyhow::anyhow!("threshold response timeout"))?);
        }
        std::fs::write(root.join(format!("responses-{index}.json")),serde_json::to_vec(&responses)?)?;
        let parsed = ParsedUserDecryptionRequest::try_from(&request)?;
        let plaintexts = tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&responses)?;
        anyhow::ensure!(plaintexts.len()==1,"unexpected plaintext count");
        let actual = match typ {tfhe::FheTypes::Uint16 => plaintexts[0].as_u16() as u64, _ => plaintexts[0].as_u64()};
        anyhow::ensure!(actual==expected,"{name}: wrong threshold result");
        // Real authenticated responses: insufficient, duplicate, misbound and corrupt data must reject.
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&responses[..1]).is_err(),"accepted one response");
        let duplicate=vec![responses[0].clone();4];
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&duplicate).is_err(),"accepted duplicate responses");
        let mut wrong=request.clone();
        let mut changed_context:serde_json::Value=serde_json::from_slice(&wrong.extra_data)?;
        changed_context["evidenceDigest"]=format!("0x{}","00".repeat(32)).into();wrong.extra_data=serde_json::to_vec(&changed_context)?;
        let native_accepts_changed_context=client.process_user_decryption_resp(&ParsedUserDecryptionRequest::try_from(&wrong)?,&domain,&enc_pk,&enc_sk,Some(1),&responses).is_ok();
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&wrong,&domain,&enc_pk,&enc_sk,1,&responses).is_err(),"accepted changed context");
        let mut no_external=responses.clone();for r in &mut no_external {r.external_signature.clear();}
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&no_external).is_err(),"fell back to internal signatures");
        let mut wrong_key=request.clone();wrong_key.key_id=Some(derive_request_id("wrong-key")?.into());
        anyhow::ensure!(tops_recipient_validation::validate_request_metadata(&wrong_key).is_err(),"accepted wrong key metadata");
        report["cases"].as_array_mut().unwrap().push(serde_json::json!({"name":name,"expected":expected,"actual":actual,
            "ciphertextFile":path,"ciphertextDigest":format!("0x{}",hex::encode(digest)),"fheType":typ as i32,
            "thresholdResponses":responses.len(),"recipientDecryptionSeconds":started.elapsed().as_secs_f64(),"evidence":evidence,
            "verification":"external EIP-712; no internal-signature fallback","nativeInternalPathAcceptsChangedContext":native_accepts_changed_context,
            "responseNegativeChecks":["one-response","duplicate-responses","changed-context","missing-external-signatures","wrong-key-metadata"]}));
        std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    }
    report["status"]="passed".into();
    report["authorizationIntegration"]="pending: diagnostic context-bound UserDecrypt; no application gateway".into();
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
