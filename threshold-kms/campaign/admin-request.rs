// Used only by the isolated setup clients, never by a core or application role.
fn vcfhe_setup_request<T: serde::Serialize>(mut request: tonic::Request<T>, operation: &str) -> tonic::Request<T> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let secret = std::fs::read_to_string("/setup-identity/signing.hex").expect("setup identity unavailable");
    let secret = hex::decode(secret.trim()).expect("invalid setup identity encoding");
    let key = k256::ecdsa::SigningKey::from_slice(&secret).expect("invalid setup identity");
    let mut payload = format!("VCFHE_SETUP_V1:{operation}:").into_bytes();
    payload.extend(serde_json::to_vec(request.get_ref()).expect("invalid setup request"));
    let signature: k256::ecdsa::Signature = key.sign_prehash(alloy_primitives::keccak256(payload).as_slice())
        .expect("setup request signature failed");
    request.metadata_mut().insert("x-vcfhe-setup-signature",hex::encode(signature.to_bytes()).parse().unwrap());
    request
}
