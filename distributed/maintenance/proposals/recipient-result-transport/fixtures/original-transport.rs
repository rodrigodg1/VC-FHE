// Appended to the pinned upstream integration target. Only these exact entry
// points run; no ThresholdTestEnv, pregenerated FHE key or local decrypt is used.
#[tokio::test]
async fn tops_public_fhe_worker() -> Result<()> {
    let job = PathBuf::from(std::env::var("TOPS_FHE_WORKER_JOB")?);
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&job)?)?;
    if v["action"].as_str().unwrap_or("").starts_with("kms-") {
        tops_kms_circuit_bridge::worker(&job)?;
    } else { tops_compatible_fhe::worker(&job)?; }
    Ok(())
}

#[tokio::test]
async fn tops_campaign_setup() -> Result<()> {
    use alloy_primitives::keccak256;
    let config_path = PathBuf::from("/config/client.toml");
    let config: CoreClientConfig = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    let root = Path::new("/keyset");
    anyhow::ensure!(!root.join("ready.json").exists(), "refusing to overwrite a live keyset");
    std::fs::create_dir_all(root)?;
    let polls = std::env::var("VCFHE_KMS_MAX_POLLS")?.parse::<usize>()?;
    let started = std::time::Instant::now();
    let preproc = cmd_config(&config_path, CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
        context_id: None, epoch_id: None, uncompressed: false, from_existing_shares: false,
    }), polls);
    let preproc_id = run_cmd(&preproc, root, "full preprocessing").await?;
    let preproc_seconds = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let keygen = cmd_config(&config_path, CCCommand::KeyGen(KeyGenParameters {
        preproc_id, shared_args: SharedKeyGenParameters::default(),
    }), polls);
    let key = run_cmd(&keygen, root, "distributed key generation").await?;
    let key_id = key.to_string();
    let dkg_seconds = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let fetched = fetch_public_elements(&key_id, &[PubDataType::CompressedXofKeySet, PubDataType::PublicKey],
        &config, root, false).await?;
    let prefix = format!("PUB-p{}", fetched[0].party_id);
    let compressed: CompressedXofKeySet = load_material_from_pub_storage(Some(root), &key,
        PubDataType::CompressedXofKeySet, Some(&prefix)).await;
    let (pk, sk) = compressed.decompress()?.into_raw_parts();
    tops_compatible_fhe::write_cipher(&root.join("encryption-key.bin"), &pk)?;
    tops_compatible_fhe::write_cipher(&root.join("evaluation-key.bin"), &sk)?;
    fetch_public_elements(&SIGNING_KEY_ID.to_string(), &[PubDataType::VerfKey, PubDataType::VerfAddress],
        &config, root, true).await?;
    let descriptor = serde_json::json!({
        "encryptionKeyDigest":format!("0x{}",hex::encode(keccak256(std::fs::read(root.join("encryption-key.bin"))?))),
        "evaluationKeyDigest":format!("0x{}",hex::encode(keccak256(std::fs::read(root.join("evaluation-key.bin"))?))),
        "tfhe":"1.6.1", "parameters":std::env::var("VCFHE_FHE_PARAMS")?,
    });
    let ready = serde_json::json!({"status":"passed", "upstreamCommit":"986537258d8c0348f497b1860ccf63252bc238f3",
        "parameters":std::env::var("VCFHE_FHE_PARAMS")?,"parties":4,"corruptionThreshold":1,
        "preloadedFheKey":false,"fullPreprocessing":true,"keyId":format!("0x{key_id}"),
        "keyEpoch":format!("0x{}",DEFAULT_EPOCH_ID.to_string()),"mpcContext":format!("0x{}",DEFAULT_MPC_CONTEXT.to_string()),
        "keysetDigest":format!("0x{}",hex::encode(keccak256(serde_json::to_vec(&descriptor)?))),
        "keyDescriptor":descriptor,"preprocessingSeconds":preproc_seconds,"dkgSeconds":dkg_seconds,
        "publicKeyPreparationSeconds":started.elapsed().as_secs_f64()});
    std::fs::write(root.join("ready.json"),serde_json::to_vec_pretty(&ready)?)?;
    Ok(())
}

#[tokio::test]
async fn tops_campaign_recipient() -> Result<()> {
    use alloy_primitives::keccak256;
    use kms_grpc::kms::v1::{CiphertextFormat,TypedCiphertext};
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_lib::client::client_wasm::Client;
    use kms_lib::cryptography::signatures::PrivateSigKey;
    use kms_lib::vault::storage::{file::FileStorage,StorageType};
    use kms_lib::vault::storage::crypto_material::get_core_verification_key;
    let config: CoreClientConfig=toml::from_str(&std::fs::read_to_string("/config/client.toml")?)?;
    let ready:serde_json::Value=serde_json::from_slice(&std::fs::read("/keyset/ready.json")?)?;
    let policy:serde_json::Value=serde_json::from_slice(&std::fs::read("/config/release-policy.json")?)?;
    let expected_policy_code_hash=policy["runtimeCodeHash"].as_str()
        .ok_or_else(||anyhow::anyhow!("missing pinned release-policy code hash"))?;
    let mut verification=HashMap::new();let mut endpoints=Vec::new();
    for core in &config.cores {
        let storage=FileStorage::new(Some(Path::new("/keyset")),StorageType::PUB,Some(&core.object_folder))?;
        verification.insert(core.party_id as u32,get_core_verification_key(&storage).await?);
        endpoints.push(CoreServiceEndpointClient::connect(format!("http://{}",core.address)).await?);
    }
    let secret=hex::decode(std::fs::read_to_string("/recipient-identity/signing.hex")?.trim())?;
    let recipient_sk=PrivateSigKey::new(k256::ecdsa::SigningKey::from_slice(&secret)?);
    let recipient_address=recipient_sk.verf_key().address();
    let params=if ready["parameters"]=="Default" {kms_lib::consts::DEFAULT_PARAM} else {
        anyhow::ensure!(std::env::var("VCFHE_ALLOW_INSECURE").as_deref()==Ok("1"),"insecure downgrade");
        kms_lib::consts::TEST_PARAM
    };
    let mut client=Client::new(verification,recipient_address,Some(recipient_sk),params,Some(DecryptionMode::NoiseFloodSmall));
    let polls:usize=std::env::var("VCFHE_KMS_MAX_POLLS")?.parse()?;
    let exchange=Path::new("/exchange");let mut index=0;
    loop {
        let request_path=exchange.join(format!("request-{index}.json"));
        let mut waited=0;
        while !request_path.exists() {
            if exchange.join("complete.json").exists(){return Ok(());}
            anyhow::ensure!(waited<polls,"recipient waiting for application timed out");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;waited+=1;
        }
        let message:serde_json::Value=serde_json::from_slice(&std::fs::read(request_path)?)?;
        anyhow::ensure!(message["authorization"]["policy"]==policy["address"]&&
            message["authorization"]["policyDomain"]==policy["policyDomain"]&&
            message["authorization"]["chainId"]==policy["chainId"],
            "release request changed the pinned policy domain");
        let ciphertext=hex::decode(message["ciphertextHex"].as_str().ok_or_else(||anyhow::anyhow!("missing ciphertext"))?)?;
        let digest=keccak256(&ciphertext);
        let typ=if message["authorization"]["outputType"]=="uint16" {tfhe::FheTypes::Uint16} else {tfhe::FheTypes::Uint64};
        let request_id=derive_request_id(&format!("{}:{}:{}",ready["keyId"],message["authorization"]["slot"],index))?;
        let key=RequestId::from_str(ready["keyId"].as_str().unwrap())?;
        let context=serde_json::to_vec(&serde_json::json!({"requestId":request_id.to_string(),"keyId":key.to_string(),
            "keyEpoch":DEFAULT_EPOCH_ID.to_string(),"mpcContext":DEFAULT_MPC_CONTEXT.to_string(),
            "outputDigest":format!("0x{}",hex::encode(digest)),"outputType":typ as i32,
            "recipient":recipient_address.to_checksum(None),"authorization":message["authorization"]}))?;
        let chain=message["authorization"]["chainId"].as_str().ok_or_else(||anyhow::anyhow!("missing chain"))?.parse::<u64>()?;
        let domain=alloy_sol_types::eip712_domain!{name:"VCFHE authorized output",version:"1",chain_id:chain,
            verifying_contract:alloy_primitives::Address::from_str(message["authorization"]["game"].as_str().unwrap())?,};
        let (request,enc_pk,enc_sk)=client.user_decryption_request(&domain,vec![TypedCiphertext {
            ciphertext,fhe_type:typ as i32,external_handle:digest.to_vec(),ciphertext_format:CiphertextFormat::SmallExpanded as i32,
        }],&request_id,&key,Some(&DEFAULT_MPC_CONTEXT),Some(&DEFAULT_EPOCH_ID),&context)?;
        tops_recipient_validation::validate_request_metadata(&request)?;
        let wire=serde_json::to_vec(&request)?;
        let get=serde_json::to_vec(request.request_id.as_ref().unwrap())?;
        // The recipient authorizes the exact on-chain release request. The
        // relayer can submit the transaction but cannot change any protobuf,
        // ciphertext, recipient-key or output field.
        let signing_input=Path::new("/recipient").join(format!("request-{index}.json"));
        let signing_get=Path::new("/recipient").join(format!("request-id-{index}.json"));
        std::fs::write(&signing_input,&wire)?;
        std::fs::write(&signing_get,&get)?;
        let signed=std::process::Command::new("node").arg("/app/threshold-kms/campaign/sign-request.mjs")
            .arg(&signing_input).arg(&signing_get).output()?;
        anyhow::ensure!(signed.status.success(),"recipient release signing failed: {}",String::from_utf8_lossy(&signed.stderr));
        let signed:serde_json::Value=serde_json::from_slice(&signed.stdout)?;
        campaign_write(exchange.join(format!("wire-{index}.json")),&serde_json::json!({"wire":hex::encode(&wire),"get":hex::encode(&get),
            "request":signed["request"],"releaseRequest":signed["releaseRequest"],"recipientSignature":signed["recipientSignature"]}))?;

        // The candidate exists off chain but has not been reserved. All cores
        // must reject it before any MPC side effect. This handshake prevents
        // the relayer from racing the negative check with the reservation.
        let mut direct_denied=0;
        for endpoint in &mut endpoints {
            let error=endpoint.user_decrypt(tonic::Request::new(request.clone())).await.unwrap_err();
            anyhow::ensure!(error.code()==tonic::Code::PermissionDenied,"unreserved user decrypt admitted");
            let error=endpoint.public_decrypt(tonic::Request::new(kms_grpc::kms::v1::PublicDecryptionRequest::default())).await.unwrap_err();
            anyhow::ensure!(error.code()==tonic::Code::PermissionDenied,"public decrypt enabled");direct_denied+=1;
        }
        campaign_write(exchange.join(format!("pre-reservation-{index}.json")),&serde_json::json!({"status":"all-cores-denied"}))?;

        let reservation_path=exchange.join(format!("reserved-{index}.json"));let mut waited=0;
        while !reservation_path.exists() {
            anyhow::ensure!(waited<polls,"on-chain release reservation timed out");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;waited+=1;
        }
        let reservation:serde_json::Value=serde_json::from_slice(&std::fs::read(reservation_path)?)?;
        anyhow::ensure!(reservation["submitWireDigest"]==format!("0x{}",hex::encode(keccak256(&wire))),"changed reserved wire");
        anyhow::ensure!(reservation["resultQueryDigest"]==format!("0x{}",hex::encode(keccak256(&get))),"changed reserved result query");
        anyhow::ensure!(reservation["requestId"]==signed["releaseRequest"]["requestId"]&&
            reservation["requestKey"]==signed["releaseRequest"]["requestKey"],"changed reserved request identity");
        let confirmations=reservation["validatorConfirmations"].as_array().ok_or_else(||anyhow::anyhow!("missing validator confirmations"))?;
        anyhow::ensure!((3..=4).contains(&confirmations.len()),"fewer than three validator confirmations");
        let mut previous_validator=0;
        for row in confirmations {
            let validator=row["validator"].as_u64().ok_or_else(||anyhow::anyhow!("missing validator identity"))?;
            anyhow::ensure!((1..=4).contains(&validator)&&validator>previous_validator,
                "validator confirmations are not a canonical distinct subset");
            anyhow::ensure!(row["blockHash"]==reservation["blockHash"]&&
                row["blockNumber"]==reservation["blockNumber"]&&row["chainId"]==message["authorization"]["chainId"]&&
                row["policyCodeHash"].as_str()==Some(expected_policy_code_hash),
                "validator confirmation disagrees with the reserved chain state");
            previous_validator=validator;
        }
        let mut admin_denied=0;
        let mut bound_wire_denied=0;
        for endpoint in &mut endpoints {
            // Defaults contain no usable key/context target. These calls must
            // fail at authorization, before any administrative operation runs.
            let checks = [
                endpoint.new_mpc_epoch(kms_grpc::kms::v1::NewMpcEpochRequest::default()).await.unwrap_err(),
                endpoint.key_gen(kms_grpc::kms::v1::KeyGenRequest::default()).await.unwrap_err(),
                endpoint.insecure_key_gen(kms_grpc::kms::v1::KeyGenRequest::default()).await.unwrap_err(),
                endpoint.new_mpc_context(kms_grpc::kms::v1::NewMpcContextRequest::default()).await.unwrap_err(),
                endpoint.destroy_mpc_epoch(kms_grpc::kms::v1::DestroyMpcEpochRequest::default()).await.unwrap_err(),
                endpoint.custodian_recovery_init(kms_grpc::kms::v1::CustodianRecoveryInitRequest::default()).await.unwrap_err(),
            ];
            for error in checks {
                anyhow::ensure!(error.code()==tonic::Code::PermissionDenied,"unguarded administrative API");
                admin_denied+=1;
            }
            let mut wrong_authority=tonic::Request::new(kms_grpc::kms::v1::NewMpcEpochRequest::default());
            wrong_authority.metadata_mut().insert("x-vcfhe-setup-signature","00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse()?);
            anyhow::ensure!(endpoint.new_mpc_epoch(wrong_authority).await.unwrap_err().code()==tonic::Code::PermissionDenied,"untrusted signature admitted as setup authority");
            admin_denied+=1;
            let mut altered=request.clone();altered.extra_data.push(0);
            anyhow::ensure!(endpoint.user_decrypt(tonic::Request::new(altered)).await.unwrap_err().code()==tonic::Code::PermissionDenied,"changed reserved wire admitted");
            bound_wire_denied+=1;
        }
        let started=std::time::Instant::now();
        let mut accepted_submit_cores=Vec::new();
        let mut failed_submit_cores=Vec::new();
        let submissions=endpoints.iter().cloned().enumerate().map(|(core_index,mut endpoint)|{
            let request=request.clone();
            async move {((core_index+1) as u64,tokio::time::timeout(
                std::time::Duration::from_secs(180),
                endpoint.user_decrypt(tonic::Request::new(request))).await)}
        });
        for (core,result) in futures::future::join_all(submissions).await {
            match result {
                Ok(Ok(_))=>accepted_submit_cores.push(core),
                Ok(Err(_))|Err(_)=>failed_submit_cores.push(core),
            }
        }
        validate_submit_core_partition(&accepted_submit_cores,&failed_submit_cores)?;
        let submit_seconds=started.elapsed().as_secs_f64();
        let mut responses=Vec::new();let mut seen=std::collections::HashSet::new();let mut poll_count=0;
        for _ in 0..polls {
            for (i,endpoint) in endpoints.iter_mut().enumerate() {
                if seen.contains(&i){continue;}
                poll_count+=1;
                match endpoint.get_user_decryption_result(tonic::Request::new(request.request_id.clone().unwrap())).await {
                    Ok(response)=>{responses.push(response.into_inner());seen.insert(i);},
                    Err(e) if e.code()==tonic::Code::Unavailable=>(),
                    Err(e)=>return Err(e.into()),
                }
                if responses.len()>=3 {break;}
            }
            if responses.len()>=3 {break;}
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        anyhow::ensure!(responses.len()>=3,"threshold response timeout");
        let kms_seconds=started.elapsed().as_secs_f64();let started=std::time::Instant::now();
        let plain=tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&responses)?;
        let recipient_seconds=started.elapsed().as_secs_f64();
        let actual=match typ {tfhe::FheTypes::Uint16=>plain[0].as_u16() as u64,_=>plain[0].as_u64()};
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&responses[..1]).is_err(),"one response accepted");
        let mut unsigned=responses.clone();for r in &mut unsigned {r.external_signature.clear();}
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&unsigned).is_err(),"signature fallback");
        let duplicate=vec![responses[0].clone();3];
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&request,&domain,&enc_pk,&enc_sk,1,&duplicate).is_err(),"duplicate response quorum");
        let mut substituted=request.clone();substituted.extra_data.push(0);
        anyhow::ensure!(tops_recipient_validation::decrypt_bound(&client,&substituted,&domain,&enc_pk,&enc_sk,1,&responses).is_err(),"substituted release context");
        let encrypted=serde_json::to_vec(&responses)?;
        campaign_write(Path::new("/recipient").join(format!("result-{index}.json")),&serde_json::json!({
            "index":index,"actual":actual,"name":message["name"],"outputDigest":format!("0x{}",hex::encode(digest)),
            "kmsSeconds":kms_seconds,"recipientSeconds":recipient_seconds,"responses":responses.len(),
            "submitSeconds":submit_seconds,"polls":poll_count,"negativeResponseChecks":4,
            "requestBytes":wire.len(),"responseBytes":encrypted.len(),"directUserAndPublicDenied":direct_denied,
            "directAdministrativeDenied":admin_denied,
            "changedReservedWireDenied":bound_wire_denied,
            "acceptedSubmitCores":accepted_submit_cores,"failedSubmitCores":failed_submit_cores,
            "onChainRelease":{"policy":message["authorization"]["policy"],"policyDomain":message["authorization"]["policyDomain"],
                "consentId":signed["releaseRequest"]["consentId"],"requestId":signed["releaseRequest"]["requestId"],
                "requestKey":signed["releaseRequest"]["requestKey"],"submitWireDigest":signed["releaseRequest"]["submitWireDigest"],
                "resultQueryDigest":signed["releaseRequest"]["resultQueryDigest"],
                "recipientEncryptionKeyDigest":signed["releaseRequest"]["recipientEncryptionKeyDigest"],
                "recipient":message["authorization"]["recipient"],
                "slot":message["authorization"]["slot"],"reservationTransaction":reservation["transactionHash"],
                "reservationBlock":reservation["blockNumber"],"reservationBlockHash":reservation["blockHash"],
                "validatorConfirmations":confirmations},
        }))?;
        campaign_write(exchange.join(format!("responses-{index}.json")),&serde_json::json!({"bytes":hex::encode(encrypted)}))?;
        index+=1;
    }
}

fn campaign_write(path:PathBuf,value:&serde_json::Value)->Result<()> {
    use std::io::Write;
    let tmp=path.with_extension("pending");
    let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    f.write_all(&serde_json::to_vec(value)?)?;f.sync_all()?;
    std::fs::rename(tmp,path)?;Ok(())
}

fn validate_submit_core_partition(accepted:&[u64],failed:&[u64])->Result<()> {
    let all=accepted.iter().chain(failed.iter()).copied().collect::<Vec<_>>();
    anyhow::ensure!(all.len()==4&&all.iter().all(|core|(1..=4).contains(core))&&
        all.iter().copied().collect::<std::collections::HashSet<_>>().len()==4,
        "KMS submission results do not cover four distinct cores");
    anyhow::ensure!(accepted.len()>=3,"fewer than three KMS cores accepted the reserved request");
    Ok(())
}

#[test]
fn tops_submit_core_quorum_gate() -> Result<()> {
    validate_submit_core_partition(&[1,2,3],&[4])?;
    validate_submit_core_partition(&[1,2,3,4],&[])?;
    anyhow::ensure!(validate_submit_core_partition(&[1,2],&[3,4]).is_err(),
        "two KMS submissions formed a quorum");
    anyhow::ensure!(validate_submit_core_partition(&[1,2,2],&[4]).is_err(),
        "duplicate KMS core formed a quorum");
    Ok(())
}
