// Candidate client transport helper. No authorization or MPC operation occurs here.
async fn acquire_accepted_user_results(
    endpoints: &[kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient<tonic::transport::Channel>],
    request_id: &kms_grpc::kms::v1::RequestId,
    accepted_submit_cores: &[u64],
    failed_submit_cores: &[u64],
    polls: usize,
) -> Result<(Vec<kms_grpc::kms::v1::UserDecryptionResponse>, usize)> {
    // Keep the same four-core submission partition and three successful ACKs.
    validate_submit_core_partition(accepted_submit_cores, failed_submit_cores)?;
    anyhow::ensure!(endpoints.len() == 4, "result endpoints do not cover four cores");
    anyhow::ensure!(polls > 0, "no result polls admitted");
    let mut responses = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut poll_count = 0;
    for _ in 0..polls {
        // A failed submission is not an acknowledged backend computation.
        // Never query it in place of a core that acknowledged this request.
        for core in accepted_submit_cores {
            if seen.contains(core) {
                continue;
            }
            poll_count += 1;
            let mut endpoint = endpoints[(*core - 1) as usize].clone();
            match endpoint
                .get_user_decryption_result(tonic::Request::new(request_id.clone()))
                .await
            {
                Ok(response) => {
                    responses.push(response.into_inner());
                    seen.insert(*core);
                }
                Err(error) if error.code() == tonic::Code::Unavailable => (),
                // NOT_FOUND after a successful ACK is not ordinary pending
                // work. Preserve the original fail-closed handling for it.
                Err(error) => return Err(error.into()),
            }
            if responses.len() >= 3 {
                break;
            }
        }
        if responses.len() >= 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::ensure!(responses.len() >= 3, "threshold response timeout");
    // These are untrusted responses. The unchanged decrypt_bound call must
    // authenticate their signatures, distinct parties and exact context.
    Ok((responses, poll_count))
}
