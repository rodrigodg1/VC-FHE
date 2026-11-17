// Per-core authorization for recipient decryption. Each KMS core parses the
// request that it will execute and compares those semantics with the reserved
// on-chain release through a quorum of configured blockchain validators.
use alloy_primitives::keccak256;
use kms_grpc::kms::v1::{CiphertextFormat, RequestId, UserDecryptionRequest};
use serde::Deserialize;
use serde_json::{json, Value};
#[cfg(unix)]
use std::fs::File;
use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tfhe::FheTypes;
use tonic::Status;

const POLICY_CONFIG_PATH: &str = "/config/release-policy.json";
const CAMPAIGN_CONFIG_PATH: &str = "/config/campaign.json";
const CONSUMED_REQUESTS_PATH: &str = "/private/release-policy-consumed";
const WORKFLOW_AUTH_SCRIPT: &str = "/app/threshold-kms/campaign/workflow-auth.mjs";
const RELEASE_EVIDENCE_PATH: &str = "/release-evidence";
const RELEASE_KEYSET_PATH: &str = "/release-keyset";
const EXPECTED_POLICY_VERSION: u64 = 3;
const EXPECTED_DOMAIN_NAME: &str = "VCFHE authorized output";
const EXPECTED_DOMAIN_VERSION: &str = "1";
const EXPECTED_AUTHORIZATION_KIND: &str = "kms-recipient-release-v3";
const VALIDATOR_COUNT: usize = 4;
const VALIDATOR_QUORUM: usize = 3;
const MAX_EXTRA_DATA_BYTES: usize = 1024 * 1024;
const SUBMIT_POLICY_METHOD: &str = "isSubmitAuthorized((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,bytes32,bytes32,bytes32,bytes32,address,uint256,bytes32,address,bytes32,uint8,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32))";
const RESULT_POLICY_METHOD: &str = "isResultAuthorized(bytes32,bytes32,bytes32)";

static POLICY_CONFIG: OnceLock<Result<PolicyConfig, ()>> = OnceLock::new();
static WORKFLOW_WINDOW_SECONDS: OnceLock<Result<u64, ()>> = OnceLock::new();

#[derive(Deserialize)]
#[serde(untagged)]
enum ConfiguredInteger {
    Number(u64),
    Text(String),
}

impl ConfiguredInteger {
    fn parse(&self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(*value),
            Self::Text(value) if value.starts_with("0x") => {
                u64::from_str_radix(&value[2..], 16).ok()
            }
            Self::Text(value) => value.parse().ok(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPolicyConfig {
    schema: String,
    chain_id: ConfiguredInteger,
    address: String,
    runtime_code_hash: String,
    policy_version: ConfiguredInteger,
    policy_domain: String,
    domain_separator: String,
    genesis_block_hash: String,
    deployment_block: ConfiguredInteger,
    deployment_block_hash: String,
    last_verified_block_number: ConfiguredInteger,
    last_verified_block_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCampaignConfig {
    window_seconds: u64,
}

struct ChainAnchors {
    genesis_block_hash: [u8; 32],
    deployment_block: u64,
    deployment_block_hash: [u8; 32],
    last_verified_block_number: u64,
    last_verified_block_hash: [u8; 32],
}

struct PolicyConfig {
    chain_id: u64,
    address: [u8; 20],
    contract: String,
    runtime_code_hash: [u8; 32],
    policy_domain: [u8; 32],
    domain_separator: [u8; 32],
    anchors: ChainAnchors,
    rpc_urls: [String; VALIDATOR_COUNT],
    client: reqwest::Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockObservation {
    number: u64,
    hash: [u8; 32],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseAuthorization {
    kind: String,
    policy_version: u64,
    policy: String,
    policy_domain: String,
    slot: String,
    consent_id: String,
    chain_id: ConfiguredInteger,
    game: String,
    workflow_kind: u8,
    task_id: String,
    context_digest: String,
    program_digest: String,
    program_root: String,
    profile_digest: String,
    keyset_digest: String,
    key_id: String,
    key_epoch: String,
    mpc_context: String,
    aggregate_digest: String,
    output_digest: String,
    output_type: String,
    recipient: String,
    input_bindings: Vec<String>,
    workflow_manifest: Value,
    linear_witness_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestContext {
    request_id: String,
    key_id: String,
    key_epoch: String,
    mpc_context: String,
    output_digest: String,
    output_type: i32,
    recipient: String,
    authorization: ReleaseAuthorization,
}

struct SubmitAuthorization {
    request_id: [u8; 32],
    request_key: [u8; 32],
    submit_wire_digest: [u8; 32],
    consent_id: [u8; 32],
    final_output_digest: [u8; 32],
    aggregate_digest: [u8; 32],
    recipient_encryption_key_digest: [u8; 32],
    recipient: [u8; 20],
    key_id: [u8; 32],
    key_epoch: [u8; 32],
    mpc_context: [u8; 32],
    output_type: [u8; 32],
    workflow: [u8; 20],
    chain_id: u64,
    policy_domain: [u8; 32],
    policy: [u8; 20],
    slot: [u8; 32],
    workflow_kind: u8,
    task_id: [u8; 32],
    context_digest: [u8; 32],
    program_digest: [u8; 32],
    program_root: [u8; 32],
    profile_digest: [u8; 32],
    keyset_digest: [u8; 32],
    input_bindings_digest: [u8; 32],
    input_bindings: Vec<[u8; 32]>,
    workflow_manifest: Value,
    linear_witness_digest: Option<[u8; 32]>,
    final_ciphertext: Vec<u8>,
}

fn local_configuration_error() -> Status {
    Status::failed_precondition("invalid release-policy configuration")
}

fn policy_unavailable() -> Status {
    Status::unavailable("release-policy state unavailable")
}

fn unauthorized() -> Status {
    Status::permission_denied("on-chain release authorization required")
}

fn replayed_request() -> Status {
    Status::permission_denied("decryption request already consumed")
}

fn replay_state_unavailable() -> Status {
    Status::failed_precondition("release replay state unavailable")
}

fn hash_bytes(value: impl AsRef<[u8]>) -> [u8; 32] {
    let digest = keccak256(value);
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

fn abi_bytes32_array_digest(values: &[[u8; 32]]) -> [u8; 32] {
    // abi.encode(bytes32[]) contains a head offset, the array length and the
    // elements. This is the exact encoding used by the release registry.
    let mut encoded = Vec::with_capacity((2 + values.len()) * 32);
    let mut offset = [0_u8; 32];
    offset[31] = 32;
    encoded.extend_from_slice(&offset);
    let mut length = [0_u8; 32];
    length[24..].copy_from_slice(&(values.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&length);
    for value in values {
        encoded.extend_from_slice(value);
    }
    hash_bytes(encoded)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn consume_request_at(
    directory: &Path,
    request_id: &[u8; 32],
    submit_wire_digest: &[u8; 32],
) -> Result<(), Status> {
    fs::create_dir_all(directory).map_err(|_| replay_state_unavailable())?;
    if let Some(parent) = directory.parent() {
        sync_directory(parent).map_err(|_| replay_state_unavailable())?;
    }
    sync_directory(directory).map_err(|_| replay_state_unavailable())?;

    let marker = directory.join(hex::encode(request_id));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(marker) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(replayed_request());
        }
        Err(_) => return Err(replay_state_unavailable()),
    };

    // Creation is the no-refund point. Any later error leaves the marker in
    // place, and a successful return means both its data and directory entry
    // have been synchronized before the endpoint can start MPC.
    let contents = format!(
        "VCFHE_KMS_RELEASE_CONSUMED_V1\nrequest_id={}\nsubmit_wire_digest={}\n",
        hex::encode(request_id),
        hex::encode(submit_wire_digest)
    );
    file.write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| replay_state_unavailable())?;
    sync_directory(directory).map_err(|_| replay_state_unavailable())?;
    Ok(())
}

fn consume_submit_authorization(authorization: &SubmitAuthorization) -> Result<(), Status> {
    consume_request_at(
        Path::new(CONSUMED_REQUESTS_PATH),
        &authorization.request_id,
        &authorization.submit_wire_digest,
    )
}

fn decode_hex_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let encoded = value.strip_prefix("0x")?;
    if encoded.len() != N * 2 {
        return None;
    }
    let mut out = [0_u8; N];
    hex::decode_to_slice(encoded, &mut out).ok()?;
    Some(out)
}

fn decode_word(value: &str) -> Result<[u8; 32], Status> {
    decode_hex_fixed(value)
        .filter(|word| *word != [0_u8; 32])
        .ok_or_else(unauthorized)
}

fn decode_context_word(value: &str) -> Result<[u8; 32], Status> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(unauthorized());
    }
    let mut out = [0_u8; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| unauthorized())?;
    if out == [0_u8; 32] {
        return Err(unauthorized());
    }
    Ok(out)
}

fn request_id_word(value: &RequestId) -> Result<[u8; 32], Status> {
    if value.request_id.starts_with("0x") {
        return Err(unauthorized());
    }
    decode_context_word(&value.request_id)
}

fn decode_address(value: &str) -> Result<[u8; 20], Status> {
    let address = decode_hex_fixed(value).ok_or_else(unauthorized)?;
    if address == [0_u8; 20] {
        return Err(unauthorized());
    }
    Ok(address)
}

fn decode_big_endian_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 32 {
        return None;
    }
    let split = bytes.len().saturating_sub(8);
    if bytes[..split].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut word = [0_u8; 8];
    word[8 - (bytes.len() - split)..].copy_from_slice(&bytes[split..]);
    Some(u64::from_be_bytes(word))
}

fn parse_policy_header(raw: &RawPolicyConfig) -> Result<(u64, ChainAnchors), ()> {
    let chain_id = raw.chain_id.parse().filter(|value| *value != 0).ok_or(())?;
    if raw.schema != "vcfhe-release-policy-config-v3"
        || raw.policy_version.parse() != Some(EXPECTED_POLICY_VERSION)
    {
        return Err(());
    }
    let genesis_block_hash = decode_hex_fixed::<32>(&raw.genesis_block_hash)
        .filter(|value| *value != [0_u8; 32])
        .ok_or(())?;
    let deployment_block = raw
        .deployment_block
        .parse()
        .filter(|value| *value != 0)
        .ok_or(())?;
    let deployment_block_hash = decode_hex_fixed::<32>(&raw.deployment_block_hash)
        .filter(|value| *value != [0_u8; 32])
        .ok_or(())?;
    let last_verified_block_number = raw
        .last_verified_block_number
        .parse()
        .filter(|value| *value >= deployment_block)
        .ok_or(())?;
    let last_verified_block_hash = decode_hex_fixed::<32>(&raw.last_verified_block_hash)
        .filter(|value| *value != [0_u8; 32])
        .ok_or(())?;
    Ok((
        chain_id,
        ChainAnchors {
            genesis_block_hash,
            deployment_block,
            deployment_block_hash,
            last_verified_block_number,
            last_verified_block_hash,
        },
    ))
}

fn parse_rpc_urls(value: &str) -> Result<[String; VALIDATOR_COUNT], ()> {
    let candidates: Vec<_> = value.split(',').map(str::trim).collect();
    if candidates.len() != VALIDATOR_COUNT || candidates.iter().any(|value| value.is_empty()) {
        return Err(());
    }

    let mut unique = HashSet::with_capacity(VALIDATOR_COUNT);
    let mut urls = Vec::with_capacity(VALIDATOR_COUNT);
    for candidate in candidates {
        let url = reqwest::Url::parse(candidate).map_err(|_| ())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(());
        }
        let canonical = url.to_string();
        if !unique.insert(canonical.clone()) {
            return Err(());
        }
        urls.push(canonical);
    }
    urls.try_into().map_err(|_| ())
}

fn load_policy_config() -> Result<PolicyConfig, ()> {
    let raw: RawPolicyConfig =
        serde_json::from_slice(&std::fs::read(POLICY_CONFIG_PATH).map_err(|_| ())?)
            .map_err(|_| ())?;
    let (chain_id, anchors) = parse_policy_header(&raw)?;
    let address = decode_hex_fixed::<20>(&raw.address)
        .filter(|value| *value != [0_u8; 20])
        .ok_or(())?;
    let runtime_code_hash = decode_hex_fixed::<32>(&raw.runtime_code_hash)
        .filter(|value| *value != [0_u8; 32])
        .ok_or(())?;
    let policy_domain = decode_hex_fixed::<32>(&raw.policy_domain)
        .filter(|value| *value != [0_u8; 32])
        .ok_or(())?;
    let domain_separator = decode_hex_fixed::<32>(&raw.domain_separator)
        .filter(|value| *value != [0_u8; 32])
        .ok_or(())?;
    let rpc_urls = parse_rpc_urls(&std::env::var("VCFHE_POLICY_RPC_URLS").map_err(|_| ())?)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| ())?;
    Ok(PolicyConfig {
        chain_id,
        address,
        contract: format!("0x{}", hex::encode(address)),
        runtime_code_hash,
        policy_domain,
        domain_separator,
        anchors,
        rpc_urls,
        client,
    })
}

fn policy_config() -> Result<&'static PolicyConfig, Status> {
    match POLICY_CONFIG.get_or_init(load_policy_config) {
        Ok(config) => Ok(config),
        Err(()) => Err(local_configuration_error()),
    }
}

fn workflow_window_seconds() -> Result<u64, Status> {
    match WORKFLOW_WINDOW_SECONDS.get_or_init(|| {
        let raw: RawCampaignConfig =
            serde_json::from_slice(&std::fs::read(CAMPAIGN_CONFIG_PATH).map_err(|_| ())?)
                .map_err(|_| ())?;
        if !(1..=86_400).contains(&raw.window_seconds) {
            return Err(());
        }
        Ok(raw.window_seconds)
    }) {
        Ok(value) => Ok(*value),
        Err(()) => Err(local_configuration_error()),
    }
}

fn expected_fhe_type(output_type: &str) -> Result<i32, Status> {
    match output_type {
        "bool" | "uint64" => Ok(FheTypes::Uint64 as i32),
        "uint16" => Ok(FheTypes::Uint16 as i32),
        _ => Err(unauthorized()),
    }
}

fn parse_request_context(bytes: &[u8]) -> Result<RequestContext, Status> {
    if bytes.is_empty() || bytes.len() > MAX_EXTRA_DATA_BYTES {
        return Err(unauthorized());
    }
    serde_json::from_slice(bytes).map_err(|_| unauthorized())
}

fn extract_submit_authorization(
    request: &UserDecryptionRequest,
    config: &PolicyConfig,
) -> Result<SubmitAuthorization, Status> {
    if request.typed_ciphertexts.len() != 1 || request.enc_key.is_empty() {
        return Err(unauthorized());
    }
    let ciphertext = &request.typed_ciphertexts[0];
    if ciphertext.ciphertext.is_empty()
        || ciphertext.ciphertext_format != CiphertextFormat::SmallExpanded as i32
    {
        return Err(unauthorized());
    }
    let final_output_digest = hash_bytes(&ciphertext.ciphertext);
    if ciphertext.external_handle.as_slice() != final_output_digest.as_slice() {
        return Err(unauthorized());
    }

    let context = parse_request_context(&request.extra_data)?;
    let authorization = &context.authorization;
    if authorization.kind != EXPECTED_AUTHORIZATION_KIND
        || authorization.policy_version != EXPECTED_POLICY_VERSION
    {
        return Err(unauthorized());
    }

    let request_id_message = request.request_id.as_ref().ok_or_else(unauthorized)?;
    let key_id_message = request.key_id.as_ref().ok_or_else(unauthorized)?;
    let key_epoch_message = request.epoch_id.as_ref().ok_or_else(unauthorized)?;
    let mpc_context_message = request.context_id.as_ref().ok_or_else(unauthorized)?;
    let request_id = request_id_word(request_id_message)?;
    let key_id = request_id_word(key_id_message)?;
    let key_epoch = request_id_word(key_epoch_message)?;
    let mpc_context = request_id_word(mpc_context_message)?;
    if decode_context_word(&context.request_id)? != request_id
        || decode_context_word(&context.key_id)? != key_id
        || decode_context_word(&context.key_epoch)? != key_epoch
        || decode_context_word(&context.mpc_context)? != mpc_context
        || decode_context_word(&authorization.key_id)? != key_id
        || decode_context_word(&authorization.key_epoch)? != key_epoch
        || decode_context_word(&authorization.mpc_context)? != mpc_context
    {
        return Err(unauthorized());
    }

    if context.output_type != ciphertext.fhe_type
        || ciphertext.fhe_type != expected_fhe_type(&authorization.output_type)?
        || decode_context_word(&context.output_digest)? != final_output_digest
        || decode_word(&authorization.output_digest)? != final_output_digest
    {
        return Err(unauthorized());
    }

    let recipient = decode_address(&request.client_address)?;
    if decode_address(&context.recipient)? != recipient
        || decode_address(&authorization.recipient)? != recipient
    {
        return Err(unauthorized());
    }

    let domain = request.domain.as_ref().ok_or_else(unauthorized)?;
    if domain.name != EXPECTED_DOMAIN_NAME
        || domain.version != EXPECTED_DOMAIN_VERSION
        || domain.salt.is_some()
    {
        return Err(unauthorized());
    }
    let chain_id = decode_big_endian_u64(&domain.chain_id).ok_or_else(unauthorized)?;
    if chain_id != config.chain_id || authorization.chain_id.parse() != Some(chain_id) {
        return Err(unauthorized());
    }
    let workflow = decode_address(&domain.verifying_contract)?;
    if workflow == recipient || decode_address(&authorization.game)? != workflow {
        return Err(unauthorized());
    }

    let policy = decode_address(&authorization.policy)?;
    let policy_domain = decode_word(&authorization.policy_domain)?;
    if policy != config.address || policy_domain != config.policy_domain {
        return Err(unauthorized());
    }
    if !(1..=2).contains(&authorization.workflow_kind) {
        return Err(unauthorized());
    }
    if authorization.input_bindings.is_empty() || authorization.input_bindings.len() > 128 {
        return Err(unauthorized());
    }
    let input_bindings = authorization
        .input_bindings
        .iter()
        .map(|value| decode_word(value))
        .collect::<Result<Vec<_>, _>>()?;
    let input_bindings_digest = abi_bytes32_array_digest(&input_bindings);
    if !authorization.workflow_manifest.is_object() {
        return Err(unauthorized());
    }
    let linear_witness_digest = match authorization.workflow_kind {
        1 => Some(decode_word(
            authorization
                .linear_witness_digest
                .as_deref()
                .ok_or_else(unauthorized)?,
        )?),
        2 if authorization.linear_witness_digest.is_none() => None,
        _ => return Err(unauthorized()),
    };

    let wire = serde_json::to_vec(request).map_err(|_| unauthorized())?;
    let request_id_wire = serde_json::to_vec(request_id_message).map_err(|_| unauthorized())?;
    let output_type =
        hash_bytes(format!("VCFHE_OUTPUT_TYPE_V1:{}", authorization.output_type).as_bytes());
    Ok(SubmitAuthorization {
        request_id,
        request_key: hash_bytes(request_id_wire),
        submit_wire_digest: hash_bytes(wire),
        consent_id: decode_word(&authorization.consent_id)?,
        final_output_digest,
        aggregate_digest: decode_word(&authorization.aggregate_digest)?,
        recipient_encryption_key_digest: hash_bytes(&request.enc_key),
        recipient,
        key_id,
        key_epoch,
        mpc_context,
        output_type,
        workflow,
        chain_id,
        policy_domain,
        policy,
        slot: decode_word(&authorization.slot)?,
        workflow_kind: authorization.workflow_kind,
        task_id: decode_word(&authorization.task_id)?,
        context_digest: decode_word(&authorization.context_digest)?,
        program_digest: decode_word(&authorization.program_digest)?,
        program_root: decode_word(&authorization.program_root)?,
        profile_digest: decode_word(&authorization.profile_digest)?,
        keyset_digest: decode_word(&authorization.keyset_digest)?,
        input_bindings_digest,
        input_bindings,
        workflow_manifest: authorization.workflow_manifest.clone(),
        linear_witness_digest,
        final_ciphertext: ciphertext.ciphertext.clone(),
    })
}

fn push_word(data: &mut Vec<u8>, value: &[u8; 32]) {
    data.extend_from_slice(value);
}

fn push_address(data: &mut Vec<u8>, value: &[u8; 20]) {
    data.extend_from_slice(&[0_u8; 12]);
    data.extend_from_slice(value);
}

fn push_u64(data: &mut Vec<u8>, value: u64) {
    data.extend_from_slice(&[0_u8; 24]);
    data.extend_from_slice(&value.to_be_bytes());
}

fn push_u8(data: &mut Vec<u8>, value: u8) {
    data.extend_from_slice(&[0_u8; 31]);
    data.push(value);
}

fn submit_authorization_calldata(authorization: &SubmitAuthorization) -> String {
    let selector = hash_bytes(SUBMIT_POLICY_METHOD);
    let mut data = Vec::with_capacity(4 + 25 * 32);
    data.extend_from_slice(&selector[..4]);
    push_word(&mut data, &authorization.request_id);
    push_word(&mut data, &authorization.request_key);
    push_word(&mut data, &authorization.submit_wire_digest);
    push_word(&mut data, &authorization.consent_id);
    push_word(&mut data, &authorization.final_output_digest);
    push_word(&mut data, &authorization.aggregate_digest);
    push_word(&mut data, &authorization.recipient_encryption_key_digest);
    push_address(&mut data, &authorization.recipient);
    push_word(&mut data, &authorization.key_id);
    push_word(&mut data, &authorization.key_epoch);
    push_word(&mut data, &authorization.mpc_context);
    push_word(&mut data, &authorization.output_type);
    push_address(&mut data, &authorization.workflow);
    push_u64(&mut data, authorization.chain_id);
    push_word(&mut data, &authorization.policy_domain);
    push_address(&mut data, &authorization.policy);
    push_word(&mut data, &authorization.slot);
    push_u8(&mut data, authorization.workflow_kind);
    push_word(&mut data, &authorization.task_id);
    push_word(&mut data, &authorization.context_digest);
    push_word(&mut data, &authorization.program_digest);
    push_word(&mut data, &authorization.program_root);
    push_word(&mut data, &authorization.profile_digest);
    push_word(&mut data, &authorization.keyset_digest);
    push_word(&mut data, &authorization.input_bindings_digest);
    format!("0x{}", hex::encode(data))
}

fn result_authorization_calldata(
    request_id: &[u8; 32],
    request_key: &[u8; 32],
    result_query_digest: &[u8; 32],
) -> String {
    let selector = hash_bytes(RESULT_POLICY_METHOD);
    let mut data = Vec::with_capacity(4 + 3 * 32);
    data.extend_from_slice(&selector[..4]);
    push_word(&mut data, request_id);
    push_word(&mut data, request_key);
    push_word(&mut data, result_query_digest);
    format!("0x{}", hex::encode(data))
}

fn decode_rpc_bytes(value: &Value) -> Result<Vec<u8>, Status> {
    let encoded = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(policy_unavailable)?;
    if encoded.len() % 2 != 0 {
        return Err(policy_unavailable());
    }
    hex::decode(encoded).map_err(|_| policy_unavailable())
}

fn decode_rpc_word(value: &Value) -> Result<[u8; 32], Status> {
    let encoded = decode_rpc_bytes(value)?;
    if encoded.len() != 32 {
        return Err(policy_unavailable());
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&encoded);
    Ok(out)
}

fn rpc_word_as_u64(word: &[u8; 32]) -> Result<u64, Status> {
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(policy_unavailable());
    }
    let mut value = [0_u8; 8];
    value.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(value))
}

fn parse_quantity(value: &Value) -> Result<u64, Status> {
    let encoded = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(policy_unavailable)?;
    if encoded.is_empty() {
        return Err(policy_unavailable());
    }
    u64::from_str_radix(encoded, 16).map_err(|_| policy_unavailable())
}

fn decode_authorized(value: &Value) -> Result<bool, Status> {
    let word = decode_rpc_word(value)?;
    if word[..31].iter().any(|byte| *byte != 0) {
        return Err(policy_unavailable());
    }
    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(policy_unavailable()),
    }
}

async fn rpc_endpoint(
    client: &reqwest::Client,
    rpc_url: &str,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value, Status> {
    let response = client
        .post(rpc_url)
        .json(&json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
        .send()
        .await
        .map_err(|_| policy_unavailable())?;
    if !response.status().is_success() {
        return Err(policy_unavailable());
    }
    let body: Value = response.json().await.map_err(|_| policy_unavailable())?;
    if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || body.get("id").and_then(Value::as_u64) != Some(id)
        || body.get("error").is_some()
    {
        return Err(policy_unavailable());
    }
    body.get("result").cloned().ok_or_else(policy_unavailable)
}

fn select_quorum<T, E>(observations: [Result<T, E>; VALIDATOR_COUNT]) -> Option<T>
where
    T: Clone + Eq,
{
    observations
        .iter()
        .filter_map(|observation| observation.as_ref().ok())
        .find_map(|candidate| {
            let matching = observations
                .iter()
                .filter_map(|observation| observation.as_ref().ok())
                .filter(|observation| *observation == candidate)
                .count();
            (matching >= VALIDATOR_QUORUM).then(|| candidate.clone())
        })
}

async fn quorum_rpc<T, F>(
    config: &PolicyConfig,
    id: u64,
    method: &str,
    params: Value,
    decode: F,
) -> Result<T, Status>
where
    T: Clone + Eq,
    F: Fn(&Value) -> Result<T, Status>,
{
    let [rpc0, rpc1, rpc2, rpc3] = &config.rpc_urls;
    let (response0, response1, response2, response3) = tokio::join!(
        rpc_endpoint(&config.client, rpc0, id, method, params.clone()),
        rpc_endpoint(&config.client, rpc1, id, method, params.clone()),
        rpc_endpoint(&config.client, rpc2, id, method, params.clone()),
        rpc_endpoint(&config.client, rpc3, id, method, params),
    );
    let decode_response =
        |response: Result<Value, Status>| response.and_then(|value| decode(&value));
    select_quorum([
        decode_response(response0),
        decode_response(response1),
        decode_response(response2),
        decode_response(response3),
    ])
    .ok_or_else(policy_unavailable)
}

fn selector_only(method: &str) -> String {
    let selector = hash_bytes(method);
    format!("0x{}", hex::encode(&selector[..4]))
}

async fn contract_word(
    config: &PolicyConfig,
    id: u64,
    method: &str,
    block: &str,
) -> Result<[u8; 32], Status> {
    quorum_rpc(
        config,
        id,
        "eth_call",
        json!([{"to":config.contract.as_str(), "data":selector_only(method)}, block]),
        decode_rpc_word,
    )
    .await
}

fn decode_block_observation(value: &Value) -> Result<BlockObservation, Status> {
    Ok(BlockObservation {
        number: parse_quantity(value.get("number").ok_or_else(policy_unavailable)?)?,
        hash: decode_hex_fixed::<32>(
            value
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(policy_unavailable)?,
        )
        .ok_or_else(policy_unavailable)?,
    })
}

fn require_stable_block(
    selected: BlockObservation,
    confirmed: BlockObservation,
) -> Result<(), Status> {
    if confirmed != selected {
        return Err(policy_unavailable());
    }
    Ok(())
}

async fn require_anchored_block(
    config: &PolicyConfig,
    id: u64,
    block_number: u64,
    expected_hash: &[u8; 32],
) -> Result<(), Status> {
    let requested = format!("0x{block_number:x}");
    let block = quorum_rpc(
        config,
        id,
        "eth_getBlockByNumber",
        json!([requested, false]),
        decode_block_observation,
    )
    .await?;
    if block.number != block_number || block.hash != *expected_hash {
        return Err(unauthorized());
    }
    Ok(())
}

async fn authorize_calldata(
    config: &PolicyConfig,
    calldata: String,
) -> Result<BlockObservation, Status> {
    let chain = quorum_rpc(config, 1, "eth_chainId", json!([]), parse_quantity).await?;
    if chain != config.chain_id {
        return Err(unauthorized());
    }

    require_anchored_block(config, 2, 0, &config.anchors.genesis_block_hash).await?;
    require_anchored_block(
        config,
        3,
        config.anchors.deployment_block,
        &config.anchors.deployment_block_hash,
    )
    .await?;
    require_anchored_block(
        config,
        4,
        config.anchors.last_verified_block_number,
        &config.anchors.last_verified_block_hash,
    )
    .await?;

    let latest = quorum_rpc(
        config,
        5,
        "eth_getBlockByNumber",
        json!(["latest", false]),
        decode_block_observation,
    )
    .await?;
    if latest.number < config.anchors.last_verified_block_number {
        return Err(unauthorized());
    }
    let block = format!("0x{:x}", latest.number);

    let code = quorum_rpc(
        config,
        6,
        "eth_getCode",
        json!([config.contract.as_str(), block.as_str()]),
        decode_rpc_bytes,
    )
    .await?;
    if code.is_empty() || hash_bytes(&code) != config.runtime_code_hash {
        return Err(unauthorized());
    }

    let policy_version =
        rpc_word_as_u64(&contract_word(config, 7, "POLICY_VERSION()", &block).await?)?;
    let deployment_chain =
        rpc_word_as_u64(&contract_word(config, 8, "deploymentChainId()", &block).await?)?;
    let policy_domain = contract_word(config, 9, "policyDomain()", &block).await?;
    let domain_separator = contract_word(config, 10, "DOMAIN_SEPARATOR()", &block).await?;
    if policy_version != EXPECTED_POLICY_VERSION
        || deployment_chain != config.chain_id
        || policy_domain != config.policy_domain
        || domain_separator != config.domain_separator
    {
        return Err(unauthorized());
    }

    let allowed = quorum_rpc(
        config,
        11,
        "eth_call",
        json!([{"to":config.contract.as_str(), "data":calldata}, block.as_str()]),
        decode_authorized,
    )
    .await?;
    if !allowed {
        return Err(unauthorized());
    }

    // Every read above has a 3-of-4 canonical observation. Contract state uses
    // one explicit block; re-observe that number and hash before any MPC side
    // effect and fail closed if the validator quorum changed its view.
    let confirmed = quorum_rpc(
        config,
        12,
        "eth_getBlockByNumber",
        json!([block, false]),
        decode_block_observation,
    )
    .await?;
    require_stable_block(latest, confirmed)?;
    Ok(confirmed)
}

fn word_hex(value: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}

fn address_hex(value: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(value))
}

fn workflow_authorization_json(authorization: &SubmitAuthorization) -> Value {
    json!({
        "consentId": word_hex(&authorization.consent_id),
        "policyDomain": word_hex(&authorization.policy_domain),
        "taskId": word_hex(&authorization.task_id),
        "contextDigest": word_hex(&authorization.context_digest),
        "programDigest": word_hex(&authorization.program_digest),
        "programRoot": word_hex(&authorization.program_root),
        "profileDigest": word_hex(&authorization.profile_digest),
        "keysetDigest": word_hex(&authorization.keyset_digest),
        "keyId": word_hex(&authorization.key_id),
        "keyEpoch": word_hex(&authorization.key_epoch),
        "mpcContext": word_hex(&authorization.mpc_context),
        "outputType": word_hex(&authorization.output_type),
        "slot": word_hex(&authorization.slot),
        "inputBindingsDigest": word_hex(&authorization.input_bindings_digest),
        "finalOutputDigest": word_hex(&authorization.final_output_digest),
        "aggregateDigest": word_hex(&authorization.aggregate_digest),
        "policy": address_hex(&authorization.policy),
        "workflow": address_hex(&authorization.workflow),
        "recipient": address_hex(&authorization.recipient),
        "chainId": authorization.chain_id.to_string(),
        "workflowKind": authorization.workflow_kind,
    })
}

fn validate_workflow_cli_output(
    bytes: &[u8],
    chain_id: u64,
    runtime_code_hash: [u8; 32],
    consent_id: [u8; 32],
    workflow_kind: u8,
    block: BlockObservation,
) -> Result<(), ()> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    let chain_id_text = chain_id.to_string();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = vec![
        "blockHash",
        "blockNumber",
        "chainId",
        "consentId",
        "observationDigest",
        "policyCodeHash",
        "schema",
        "supportingValidators",
        "workflowRuntimeCodeHashes",
    ];
    expected.sort_unstable();
    if keys != expected
        || value["schema"].as_str() != Some("vcfhe-workflow-auth-result-v1")
        || value["chainId"].as_str() != Some(chain_id_text.as_str())
        || value["blockNumber"].as_u64() != Some(block.number)
        || decode_hex_fixed::<32>(value["blockHash"].as_str().ok_or(())?) != Some(block.hash)
        || decode_hex_fixed::<32>(value["consentId"].as_str().ok_or(())?) != Some(consent_id)
        || decode_hex_fixed::<32>(value["policyCodeHash"].as_str().ok_or(())?)
            != Some(runtime_code_hash)
        || decode_hex_fixed::<32>(value["observationDigest"].as_str().ok_or(())?)
            .filter(|digest| *digest != [0_u8; 32])
            .is_none()
    {
        return Err(());
    }
    let supporters = value["supportingValidators"].as_array().ok_or(())?;
    if !(VALIDATOR_QUORUM..=VALIDATOR_COUNT).contains(&supporters.len()) {
        return Err(());
    }
    let mut previous = 0_u64;
    for supporter in supporters {
        let id = supporter.as_u64().ok_or(())?;
        if !(1..=VALIDATOR_COUNT as u64).contains(&id) || id <= previous {
            return Err(());
        }
        previous = id;
    }
    let hashes = value["workflowRuntimeCodeHashes"].as_object().ok_or(())?;
    let expected_names: BTreeSet<&str> = if workflow_kind == 1 {
        ["workflow"].into_iter().collect()
    } else {
        ["availability", "game", "objective", "verifier"]
            .into_iter()
            .collect()
    };
    if hashes.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_names
        || hashes.values().any(|digest| {
            decode_hex_fixed::<32>(digest.as_str().unwrap_or_default())
                .filter(|value| *value != [0_u8; 32])
                .is_none()
        })
    {
        return Err(());
    }
    Ok(())
}

fn run_workflow_auth_cli(
    payload: Vec<u8>,
    chain_id: u64,
    runtime_code_hash: [u8; 32],
    consent_id: [u8; 32],
    workflow_kind: u8,
    block: BlockObservation,
) -> Result<(), ()> {
    let mut child = Command::new("/usr/local/bin/node")
        .arg(WORKFLOW_AUTH_SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ())?;
    child
        .stdin
        .take()
        .ok_or(())?
        .write_all(&payload)
        .map_err(|_| ())?;
    let output = child.wait_with_output().map_err(|_| ())?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return Err(());
    }
    validate_workflow_cli_output(
        &output.stdout,
        chain_id,
        runtime_code_hash,
        consent_id,
        workflow_kind,
        block,
    )
}

async fn verify_workflow_before_release(
    config: &PolicyConfig,
    authorization: &SubmitAuthorization,
    block: BlockObservation,
) -> Result<(), Status> {
    let payload = serde_json::to_vec(&json!({
        "authorization": workflow_authorization_json(authorization),
        "workflowManifest": authorization.workflow_manifest.clone(),
        "rpcUrls": config.rpc_urls.to_vec(),
        "blockNumber": block.number,
        "blockHash": word_hex(&block.hash),
        "expectedWindowSeconds": workflow_window_seconds()?,
        "timeoutMs": 5_000,
    }))
    .map_err(|_| unauthorized())?;
    let config_chain_id = config.chain_id;
    let config_runtime_hash = config.runtime_code_hash;
    let consent_id = authorization.consent_id;
    let workflow_kind = authorization.workflow_kind;
    tokio::task::spawn_blocking(move || {
        run_workflow_auth_cli(
            payload,
            config_chain_id,
            config_runtime_hash,
            consent_id,
            workflow_kind,
            block,
        )
    })
    .await
    .map_err(|_| unauthorized())?
    .map_err(|_| unauthorized())
}

async fn verify_linear_before_release(authorization: &SubmitAuthorization) -> Result<(), Status> {
    let Some(witness_digest) = authorization.linear_witness_digest else {
        return Ok(());
    };
    let witness_path =
        PathBuf::from(RELEASE_EVIDENCE_PATH).join(format!("{}.json", hex::encode(witness_digest)));
    let final_ciphertext = authorization.final_ciphertext.clone();
    let expected = (
        witness_digest,
        authorization.program_digest,
        authorization.input_bindings_digest,
        authorization.aggregate_digest,
        authorization.keyset_digest,
    );
    tokio::task::spawn_blocking(move || {
        let ready_path = Path::new(RELEASE_KEYSET_PATH).join("ready.json");
        let evaluation_key_path = Path::new(RELEASE_KEYSET_PATH).join("evaluation-key.bin");
        super::vcfhe_linear_release::verify_linear_release(
            super::vcfhe_linear_release::LinearReleaseFiles {
                witness_path: &witness_path,
                ready_path: &ready_path,
                evaluation_key_path: &evaluation_key_path,
            },
            super::vcfhe_linear_release::LinearReleaseExpected {
                witness_digest: expected.0,
                program_digest: expected.1,
                input_bindings_digest: expected.2,
                aggregate_digest: expected.3,
                keyset_digest: expected.4,
                final_ciphertext: &final_ciphertext,
            },
        )
        .map(|_| ())
        .map_err(|_| ())
    })
    .await
    .map_err(|_| unauthorized())?
    .map_err(|_| unauthorized())
}

pub(super) async fn authorize_user_decrypt(request: &UserDecryptionRequest) -> Result<(), Status> {
    let config = policy_config()?;
    let authorization = extract_submit_authorization(request, config)?;
    let authorized_block =
        authorize_calldata(config, submit_authorization_calldata(&authorization)).await?;
    verify_workflow_before_release(config, &authorization, authorized_block).await?;
    verify_linear_before_release(&authorization).await?;
    consume_submit_authorization(&authorization)
}

pub(super) async fn authorize_user_decryption_result(request: &RequestId) -> Result<(), Status> {
    let config = policy_config()?;
    let request_id = request_id_word(request)?;
    let wire = serde_json::to_vec(request).map_err(|_| unauthorized())?;
    let request_key = hash_bytes(&wire);
    authorize_calldata(
        config,
        result_authorization_calldata(&request_id, &request_key, &hash_bytes(wire)),
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Barrier,
        },
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vcfhe-onchain-release-{label}-{}-{nonce}-{}",
            std::process::id(),
            TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn sample_submit() -> SubmitAuthorization {
        SubmitAuthorization {
            request_id: [1; 32],
            request_key: [2; 32],
            submit_wire_digest: [3; 32],
            consent_id: [4; 32],
            final_output_digest: [5; 32],
            aggregate_digest: [6; 32],
            recipient_encryption_key_digest: [7; 32],
            recipient: [8; 20],
            key_id: [9; 32],
            key_epoch: [10; 32],
            mpc_context: [11; 32],
            output_type: [12; 32],
            workflow: [13; 20],
            chain_id: 14,
            policy_domain: [15; 32],
            policy: [16; 20],
            slot: [17; 32],
            workflow_kind: 2,
            task_id: [19; 32],
            context_digest: [20; 32],
            program_digest: [21; 32],
            program_root: [22; 32],
            profile_digest: [23; 32],
            keyset_digest: [24; 32],
            input_bindings_digest: [25; 32],
            input_bindings: vec![[26; 32]],
            workflow_manifest: json!({"schema":"vcfhe-workflow-deployment-v1"}),
            linear_witness_digest: None,
            final_ciphertext: vec![27; 32],
        }
    }

    fn sample_policy_config_json() -> Value {
        json!({
            "schema": "vcfhe-release-policy-config-v3",
            "chainId": 46853,
            "address": format!("0x{}", "11".repeat(20)),
            "runtimeCodeHash": format!("0x{}", "22".repeat(32)),
            "policyVersion": 3,
            "policyDomain": format!("0x{}", "33".repeat(32)),
            "domainSeparator": format!("0x{}", "44".repeat(32)),
            "genesisBlockHash": format!("0x{}", "55".repeat(32)),
            "deploymentBlock": 7,
            "deploymentBlockHash": format!("0x{}", "66".repeat(32)),
            "lastVerifiedBlockNumber": 9,
            "lastVerifiedBlockHash": format!("0x{}", "77".repeat(32))
        })
    }

    fn sample_request_context_json() -> Value {
        json!({
            "requestId": "0x01",
            "keyId": "0x02",
            "keyEpoch": "0x03",
            "mpcContext": "0x04",
            "outputDigest": "0x05",
            "outputType": 1,
            "recipient": "0x06",
            "authorization": {
                "kind": EXPECTED_AUTHORIZATION_KIND,
                "policyVersion": EXPECTED_POLICY_VERSION,
                "policy": "0x07",
                "policyDomain": "0x08",
                "slot": "0x09",
                "consentId": "0x0a",
                "chainId": 46853,
                "game": "0x0b",
                "workflowKind": 1,
                "taskId": "0x0c",
                "contextDigest": "0x0d",
                "programDigest": "0x0e",
                "programRoot": "0x0f",
                "profileDigest": "0x10",
                "keysetDigest": "0x11",
                "keyId": "0x12",
                "keyEpoch": "0x13",
                "mpcContext": "0x14",
                "aggregateDigest": "0x15",
                "outputDigest": "0x16",
                "outputType": "uint16",
                "recipient": "0x17",
                "inputBindings": ["0x18"],
                "workflowManifest": {"schema": "vcfhe-workflow-deployment-v1"},
                "linearWitnessDigest": "0x19"
            }
        })
    }

    #[test]
    fn request_context_is_bounded_and_rejects_unknown_fields() {
        let canonical = serde_json::to_vec(&sample_request_context_json()).unwrap();
        assert!(parse_request_context(&canonical).is_ok());
        assert!(parse_request_context(&vec![b'x'; MAX_EXTRA_DATA_BYTES + 1]).is_err());

        let mut unexpected_context = sample_request_context_json();
        unexpected_context["unexpected"] = json!(true);
        assert!(parse_request_context(&serde_json::to_vec(&unexpected_context).unwrap()).is_err());

        let mut unexpected_authorization = sample_request_context_json();
        unexpected_authorization["authorization"]["unexpected"] = json!(true);
        assert!(
            parse_request_context(&serde_json::to_vec(&unexpected_authorization).unwrap()).is_err()
        );
    }

    #[test]
    fn submit_selector_and_static_tuple_layout_are_pinned() {
        let bytes =
            hex::decode(submit_authorization_calldata(&sample_submit()).trim_start_matches("0x"))
                .unwrap();
        assert_eq!(&bytes[..4], &[0x90, 0xfe, 0x04, 0x5d]);
        assert_eq!(bytes.len(), 4 + 25 * 32);
        assert_eq!(&bytes[4 + 7 * 32..4 + 7 * 32 + 12], &[0_u8; 12]);
        assert_eq!(&bytes[4 + 7 * 32 + 12..4 + 8 * 32], &[8_u8; 20]);
        assert_eq!(bytes[4 + 17 * 32 + 31], 2);
    }

    #[test]
    fn input_binding_digest_matches_solidity_dynamic_array_encoding() {
        let values = [[0x11; 32], [0x22; 32]];
        let mut expected = vec![0_u8; 4 * 32];
        expected[31] = 32;
        expected[63] = 2;
        expected[64..96].copy_from_slice(&values[0]);
        expected[96..128].copy_from_slice(&values[1]);
        assert_eq!(abi_bytes32_array_digest(&values), hash_bytes(expected));
    }

    #[test]
    fn result_selector_and_layout_are_pinned() {
        let bytes = hex::decode(
            result_authorization_calldata(&[1; 32], &[2; 32], &[3; 32]).trim_start_matches("0x"),
        )
        .unwrap();
        assert_eq!(&bytes[..4], &[0x44, 0x5f, 0x39, 0x14]);
        assert_eq!(bytes.len(), 4 + 3 * 32);
    }

    #[test]
    fn logical_output_types_pin_the_wire_fhe_type() {
        assert_eq!(expected_fhe_type("bool").unwrap(), FheTypes::Uint64 as i32);
        assert_eq!(
            expected_fhe_type("uint16").unwrap(),
            FheTypes::Uint16 as i32
        );
        assert_eq!(
            expected_fhe_type("uint64").unwrap(),
            FheTypes::Uint64 as i32
        );
        assert!(expected_fhe_type("uint8").is_err());
    }

    #[test]
    fn v3_config_requires_ordered_chain_anchors() {
        let raw: RawPolicyConfig = serde_json::from_value(sample_policy_config_json()).unwrap();
        let (chain_id, anchors) = parse_policy_header(&raw).unwrap();
        assert_eq!(chain_id, 46853);
        assert_eq!(anchors.genesis_block_hash, [0x55; 32]);
        assert_eq!(anchors.deployment_block, 7);
        assert_eq!(anchors.deployment_block_hash, [0x66; 32]);
        assert_eq!(anchors.last_verified_block_number, 9);
        assert_eq!(anchors.last_verified_block_hash, [0x77; 32]);

        for field in [
            "genesisBlockHash",
            "deploymentBlock",
            "deploymentBlockHash",
            "lastVerifiedBlockNumber",
            "lastVerifiedBlockHash",
        ] {
            let mut value = sample_policy_config_json();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<RawPolicyConfig>(value).is_err());
        }

        let mut value = sample_policy_config_json();
        value["lastVerifiedBlockNumber"] = json!(6);
        let raw: RawPolicyConfig = serde_json::from_value(value).unwrap();
        assert!(parse_policy_header(&raw).is_err());

        let mut value = sample_policy_config_json();
        value["schema"] = json!("vcfhe-release-policy-config-v2");
        let raw: RawPolicyConfig = serde_json::from_value(value).unwrap();
        assert!(parse_policy_header(&raw).is_err());
    }

    #[test]
    fn rpc_configuration_requires_four_distinct_validator_endpoints() {
        let urls = parse_rpc_urls(
            "http://node1:8545,http://node2:8545,http://node3:8545,http://node4:8545",
        )
        .unwrap();
        assert_eq!(urls.len(), VALIDATOR_COUNT);
        assert_eq!(urls[0], "http://node1:8545/");

        assert!(parse_rpc_urls("http://node1:8545,http://node2:8545,http://node3:8545").is_err());
        assert!(parse_rpc_urls(
            "http://node1:8545,http://node2:8545,http://NODE1:8545/,http://node4:8545"
        )
        .is_err());
        assert!(parse_rpc_urls(
            "http://node1:8545,http://node2:8545,http://node3:8545,file:///node4"
        )
        .is_err());
    }

    #[test]
    fn quorum_accepts_three_identical_observations_when_one_is_unavailable() {
        let selected = select_quorum([Ok::<u64, ()>(42), Ok(42), Err(()), Ok(42)]);
        assert_eq!(selected, Some(42));
    }

    #[test]
    fn quorum_ignores_one_forged_observation() {
        let honest = BlockObservation {
            number: 23,
            hash: [0x51; 32],
        };
        let forged = BlockObservation {
            number: 23,
            hash: [0xa2; 32],
        };
        let selected = select_quorum([
            Ok::<BlockObservation, ()>(honest),
            Ok(honest),
            Ok(forged),
            Ok(honest),
        ]);
        assert_eq!(selected, Some(honest));
    }

    #[test]
    fn quorum_rejects_two_disagreements_or_unavailable_endpoints() {
        assert_eq!(
            select_quorum([Ok::<u64, ()>(42), Ok(42), Ok(43), Err(()),]),
            None
        );
        assert_eq!(
            select_quorum([Ok::<u64, ()>(42), Ok(42), Err(()), Err(()),]),
            None
        );
    }

    #[test]
    fn block_recheck_rejects_height_or_hash_instability() {
        let selected = BlockObservation {
            number: 31,
            hash: [0x73; 32],
        };
        assert!(require_stable_block(selected, selected).is_ok());

        let changed_height = BlockObservation {
            number: 32,
            hash: selected.hash,
        };
        let changed_hash = BlockObservation {
            number: selected.number,
            hash: [0x84; 32],
        };
        assert_eq!(
            require_stable_block(selected, changed_height)
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            require_stable_block(selected, changed_hash)
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
    }

    #[test]
    fn workflow_cli_evidence_is_strict_and_bound_to_the_selected_block() {
        let block = BlockObservation {
            number: 41,
            hash: [0x31; 32],
        };
        let runtime = [0x42; 32];
        let consent = [0x53; 32];
        let value = json!({
            "schema": "vcfhe-workflow-auth-result-v1",
            "chainId": "46853",
            "blockNumber": block.number,
            "blockHash": word_hex(&block.hash),
            "consentId": word_hex(&consent),
            "policyCodeHash": word_hex(&runtime),
            "supportingValidators": [1, 2, 4],
            "workflowRuntimeCodeHashes": {
                "availability": word_hex(&[0x61; 32]),
                "game": word_hex(&[0x62; 32]),
                "objective": word_hex(&[0x63; 32]),
                "verifier": word_hex(&[0x64; 32]),
            },
            "observationDigest": word_hex(&[0x75; 32]),
        });
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(validate_workflow_cli_output(&bytes, 46853, runtime, consent, 2, block).is_ok());

        let mut insufficient = value.clone();
        insufficient["supportingValidators"] = json!([1, 2]);
        assert!(validate_workflow_cli_output(
            &serde_json::to_vec(&insufficient).unwrap(),
            46853,
            runtime,
            consent,
            2,
            block,
        )
        .is_err());

        let mut changed_block = value;
        changed_block["blockHash"] = json!(word_hex(&[0x86; 32]));
        assert!(validate_workflow_cli_output(
            &serde_json::to_vec(&changed_block).unwrap(),
            46853,
            runtime,
            consent,
            2,
            block,
        )
        .is_err());
    }

    #[test]
    fn consumed_request_survives_stateless_recheck() {
        let directory = test_directory("restart");
        let request_id = [0x41; 32];
        let wire_digest = [0x52; 32];

        consume_request_at(&directory, &request_id, &wire_digest).unwrap();
        let marker = directory.join(hex::encode(request_id));
        let contents = fs::read_to_string(&marker).unwrap();
        assert_eq!(
            contents,
            format!(
                "VCFHE_KMS_RELEASE_CONSUMED_V1\nrequest_id={}\nsubmit_wire_digest={}\n",
                hex::encode(request_id),
                hex::encode(wire_digest)
            )
        );

        // The helper has no in-memory replay state. Reading the existing file
        // again models a newly started core using the same private volume.
        let error = consume_request_at(&directory, &request_id, &wire_digest).unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(marker.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_consumption_has_exactly_one_winner() {
        let directory = test_directory("concurrent");
        let request_id = [0x63; 32];
        let wire_digest = [0x74; 32];
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let directory = directory.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                consume_request_at(&directory, &request_id, &wire_digest)
            }));
        }
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| error.code() == tonic::Code::PermissionDenied));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unavailable_private_storage_fails_closed() {
        let root = test_directory("unavailable");
        fs::create_dir_all(&root).unwrap();
        let file_instead_of_directory = root.join("not-a-directory");
        fs::write(&file_instead_of_directory, b"occupied").unwrap();

        let error =
            consume_request_at(&file_instead_of_directory, &[0x85; 32], &[0x96; 32]).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        fs::remove_dir_all(root).unwrap();
    }
}
