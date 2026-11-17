// Recipient-side verification for the pinned native SDK. Its normal signature
// branch does not cover application extra_data. Select the SDK's external
// EIP-712 verification path, which signs the payload AND the expected context.
// This is not a gateway, authorization check or proof that a handle names the
// ciphertext submitted through an independently exposed core ingress.
use anyhow::{ensure, Result};
use kms_grpc::kms::v1::{CiphertextFormat, TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse};
use kms_lib::client::{client_wasm::Client, user_decryption_wasm::ParsedUserDecryptionRequest};
use kms_lib::cryptography::encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey};

pub fn validate_request_metadata(request: &UserDecryptionRequest) -> Result<()> {
    ensure!(request.typed_ciphertexts.len() == 1, "only one terminal ciphertext is supported");
    let ct = &request.typed_ciphertexts[0];
    ensure!(ct.ciphertext_format == CiphertextFormat::SmallExpanded as i32, "unsupported release format");
    let digest = alloy_primitives::keccak256(&ct.ciphertext);
    ensure!(ct.external_handle == digest.to_vec(), "ciphertext/handle mismatch");
    let context: serde_json::Value = serde_json::from_slice(&request.extra_data)?;
    for (name, value) in [
        ("requestId", request.request_id.as_ref()), ("keyId", request.key_id.as_ref()),
        ("keyEpoch", request.epoch_id.as_ref()), ("mpcContext", request.context_id.as_ref()),
    ] {
        let id = value.ok_or_else(|| anyhow::anyhow!("missing {name}"))?;
        ensure!(context[name].as_str() == Some(id.request_id.as_str()), "context {name} mismatch");
    }
    ensure!(context["outputDigest"].as_str() == Some(format!("0x{}", hex::encode(digest)).as_str()), "context ciphertext mismatch");
    ensure!(context["outputType"].as_i64() == Some(ct.fhe_type as i64), "context type mismatch");
    ensure!(context["recipient"].as_str() == Some(request.client_address.as_str()), "context recipient mismatch");
    Ok(())
}

pub fn decrypt_bound(
    client: &Client,
    request: &UserDecryptionRequest,
    domain: &alloy_sol_types::Eip712Domain,
    enc_pk: &UnifiedPublicEncKey,
    enc_sk: &UnifiedPrivateEncKey,
    corruption_threshold: usize,
    responses: &[UserDecryptionResponse],
) -> Result<Vec<TypedPlaintext>> {
    validate_request_metadata(request)?;
    let ct = &request.typed_ciphertexts[0];
    let parsed = ParsedUserDecryptionRequest::try_from(request)?;
    let external_responses: Vec<_> = responses.iter().map(|response| {
        let mut external = response.clone();
        // Keep the raw response unchanged in evidence. A missing/bad external
        // signature is rejected by the existing SDK quorum validator; it must
        // never fall back to the narrower internal signature.
        external.signature.clear();
        external
    }).collect();
    let plaintexts = client.process_user_decryption_resp(
        &parsed, domain, enc_pk, enc_sk, Some(corruption_threshold), &external_responses,
    )?;
    ensure!(plaintexts.len() == 1 && plaintexts[0].fhe_type == ct.fhe_type, "response type/count mismatch");
    Ok(plaintexts)
}
