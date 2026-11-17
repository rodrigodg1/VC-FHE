// Four native KMS participants and the actual two application pipelines.
#[tokio::test]
async fn tops_public_fhe_worker() -> Result<()> {
    if let Ok(job) = std::env::var("TOPS_FHE_WORKER_JOB") {
        let v: serde_json::Value=serde_json::from_slice(&std::fs::read(&job)?)?;
        if v["action"].as_str().unwrap_or("").starts_with("kms-") {
            tops_kms_circuit_bridge::worker(Path::new(&job))?;
        } else { tops_compatible_fhe::worker(Path::new(&job))?; }
    }
    Ok(())
}
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn tops_integrated_four_party() -> Result<()> {
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
    let mut report = serde_json::json!({"status":"starting", "classification":"two-path-authorized-threshold-integration",
        "fheParameters":if parameters == FheParameter::Test {"Test-INSECURE"} else {"Default"},
        "evaluationIntegration":true,"parties":4,"corruptionThreshold":1,
        "serviceIsolation":"four native services in one process; loopback, no TLS",
        "preloadedFheKey":false,"fullFheKeyInApplication":false,"cases":[],"negativeTests":[]});
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    let mut spec = kms_lib::testing::material::TestMaterialSpec::threshold_signing_only(4);
    spec.required_keys.clear();
    if parameters == FheParameter::Default { spec.material_type = kms_lib::testing::material::MaterialType::Default; }
    eprintln!("TOPS_COMPAT starting four-party live PRSS and full preprocessing/DKG");
    let started = std::time::Instant::now();
    let env = ThresholdTestEnv::builder().with_test_name("tops-integrated-four-party")
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

    use std::io::{BufRead, Write};
    use std::process::Stdio;
    let token=std::env::var("TOPS_KMS_GATEWAY_TOKEN")?;
    anyhow::ensure!(token.len()==64,"missing private ingress token");
    let driver_config=serde_json::json!({"root":root,"publicKey":pk_file,"evaluationKey":sk_file,
        "workerBinary":std::env::current_exe()?,"keysetDigest":report["keysetDigest"],"keyDescriptor":report["keyDescriptor"],
        "keyId":format!("0x{key_id}"),"keyEpoch":format!("0x{}",DEFAULT_EPOCH_ID.to_string()),
        "mpcContext":format!("0x{}",DEFAULT_MPC_CONTEXT.to_string()),"recipient":recipient_address.to_checksum(None),
        "runtime":std::env::var("TOPS_KMS_RUNTIME")?});
    let config_file=root.join("application-config.json");
    std::fs::write(&config_file,serde_json::to_vec_pretty(&driver_config)?)?;
    let mut child=Command::new("node").arg(std::env::var("TOPS_KMS_INTEGRATED_DRIVER")?).arg(&config_file)
        .current_dir(std::env::var("TOPS_KMS_LINEAR_CWD")?).env_remove("TOPS_KMS_GATEWAY_TOKEN")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let mut writer=child.stdin.take().unwrap();
    let mut reader=std::io::BufReader::new(child.stdout.take().unwrap());
    let mut index=0usize;
    loop {
        let mut line=String::new();
        anyhow::ensure!(reader.read_line(&mut line)?>0,"application driver ended without completion");
        let message:serde_json::Value=serde_json::from_str(&line)?;
        if message["kind"]=="complete" { report["application"]=message["report"].clone();break; }
        anyhow::ensure!(message["kind"]=="request","unexpected application message");
        let ciphertext=std::fs::read(message["ciphertextFile"].as_str().unwrap())?;
        let digest=keccak256(&ciphertext);
        let typ=if message["authorization"]["outputType"]=="uint16" {tfhe::FheTypes::Uint16} else {tfhe::FheTypes::Uint64};
        let request_id=derive_request_id(&format!("{key_id}:authorized:{index}"))?;
        let context=serde_json::to_vec(&serde_json::json!({"requestId":request_id.to_string(),"keyId":key_id,
            "keyEpoch":DEFAULT_EPOCH_ID.to_string(),"mpcContext":DEFAULT_MPC_CONTEXT.to_string(),
            "outputDigest":format!("0x{}",hex::encode(digest)),"outputType":typ as i32,
            "recipient":recipient_address.to_checksum(None),"authorization":message["authorization"]}))?;
        let domain=alloy_sol_types::eip712_domain!{name:"VCFHE authorized output",version:"1",chain_id:31337u64,
            verifying_contract:alloy_primitives::Address::from_str(message["authorization"]["game"].as_str().unwrap())?,};
        let (request,enc_pk,enc_sk)=client.user_decryption_request(&domain,
            vec![TypedCiphertext{ciphertext,fhe_type:typ as i32,external_handle:digest.to_vec(),
                ciphertext_format:CiphertextFormat::SmallExpanded as i32}],&request_id,&key,
            Some(&DEFAULT_MPC_CONTEXT),Some(&DEFAULT_EPOCH_ID),&context)?;
        tops_recipient_validation::validate_request_metadata(&request)?;
        let wire=serde_json::to_vec(&request)?;
        // Only this recipient holds the ephemeral private encapsulation key.
        // Public application code receives a request plus encrypted responses.
        writeln!(writer,"{}",serde_json::json!({"kind":"wire","wire":hex::encode(&wire)}))?;writer.flush()?;
        line.clear();anyhow::ensure!(reader.read_line(&mut line)?>0,"missing authorized submission");
        let submit:serde_json::Value=serde_json::from_str(&line)?;
        anyhow::ensure!(submit["kind"]=="submit" && submit["wireDigest"]==format!("0x{}",hex::encode(keccak256(&wire))),"transport request changed");
        std::fs::write(root.join(format!("request-{index}.json")),&wire)?;
        // Real RPC bypass attempts: no direct decryption route is available.
        for endpoint in &mut endpoints {
            let error=endpoint.user_decrypt(tonic::Request::new(request.clone())).await.unwrap_err();
            anyhow::ensure!(error.code()==tonic::Code::PermissionDenied,"unguarded UserDecrypt ingress");
            let error=endpoint.public_decrypt(tonic::Request::new(kms_grpc::kms::v1::PublicDecryptionRequest::default())).await.unwrap_err();
            anyhow::ensure!(error.code()==tonic::Code::PermissionDenied,"unguarded PublicDecrypt ingress");
        }
        let authorized=|value| {let mut r=tonic::Request::new(value);r.metadata_mut().insert("x-tops-output-gateway",token.parse().unwrap());r};
        for endpoint in &mut endpoints { endpoint.user_decrypt(authorized(request.clone())).await?; }
        let mut responses=Vec::new();
        for endpoint in &mut endpoints {
            let mut found=None;
            for _ in 0..max_iter {
                let mut r=tonic::Request::new(request.request_id.clone().unwrap());
                r.metadata_mut().insert("x-tops-output-gateway",token.parse().unwrap());
                match endpoint.get_user_decryption_result(r).await {
                    Ok(response)=>{found=Some(response.into_inner());break;},
                    Err(e) if e.code()==tonic::Code::Unavailable=>tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                    Err(e)=>return Err(e.into()),
                }
            }
            responses.push(found.ok_or_else(||anyhow::anyhow!("threshold response timeout"))?);
        }
        let plaintexts=tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&responses)?;
        let actual=match typ {tfhe::FheTypes::Uint16=>plaintexts[0].as_u16() as u64,_=>plaintexts[0].as_u64()};
        anyhow::ensure!(Some(actual)==message["expected"].as_u64(),"wrong threshold result");
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&responses[..1]).is_err(),"accepted one response");
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&vec![responses[0].clone();4]).is_err(),"accepted duplicate responses");
        let mut wrong=request.clone();let mut c:serde_json::Value=serde_json::from_slice(&wrong.extra_data)?;
        c["authorization"]["slot"]="changed".into();wrong.extra_data=serde_json::to_vec(&c)?;
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&wrong,&domain,&enc_pk,&enc_sk,1,&responses).is_err(),"accepted changed consent");
        let mut unsigned=responses.clone();for r in &mut unsigned {r.external_signature.clear();}
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&unsigned).is_err(),"external signature fallback");
        let bytes=serde_json::to_vec(&responses)?;
        std::fs::write(root.join(format!("responses-{index}.json")),&bytes)?;
        writeln!(writer,"{}",serde_json::json!({"kind":"encrypted-response","bytes":hex::encode(&bytes)}))?;writer.flush()?;
        report["cases"].as_array_mut().unwrap().push(serde_json::json!({"name":message["name"],"actual":actual,"expected":message["expected"],
            "outputDigest":format!("0x{}",hex::encode(digest)),"thresholdResponses":responses.len(),
            "directUserDecryptDenied":4,"directPublicDecryptDenied":4,
            "responseNegatives":["one-response","duplicate-responses","changed-consent","missing-external-signature"]}));
        std::fs::write(&output,serde_json::to_vec_pretty(&report)?)?;index+=1;
    }
    drop(writer);anyhow::ensure!(child.wait()?.success(),"application driver failed");
    anyhow::ensure!(index>=4,"missing application outputs");
    report["status"]="passed".into();
    report["authorizationIntegration"]="owner consent, finalized chain state, exact ciphertext, durable budget, private core ingress".into();
    std::fs::write(&output,serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
