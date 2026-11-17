use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha2Digest};
use sha3::Keccak256;
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct EvmKeccakHasher;

impl Hasher for EvmKeccakHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    pub step: u64,
    pub timestamp_utc: DateTime<Utc>,
    pub operation: String,
    pub inputs: Vec<String>,
    pub output: String,
    pub ciphertext_sha256: String,
    pub ciphertext_size_bytes: usize,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepProof {
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub leaf_hash: String,
    pub root: String,
    pub proof_hashes: Vec<String>,
}

impl StepProof {
    pub fn verify(&self) -> Result<bool> {
        let proof = MerkleProof::<EvmKeccakHasher>::new(
            self.proof_hashes
                .iter()
                .map(|hash| decode_hash(hash))
                .collect::<Result<Vec<_>>>()?,
        );

        let leaf_hash = decode_hash(&self.leaf_hash)?;
        let root = decode_hash(&self.root)?;

        Ok(proof.verify(root, &[self.leaf_index], &[leaf_hash], self.total_leaves))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBundle {
    pub session_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub merkle_root: String,
    pub events: Vec<TraceEvent>,
}

#[derive(Debug, Clone)]
pub struct TraceRecorder {
    session_id: String,
    created_at_utc: DateTime<Utc>,
    events: Vec<TraceEvent>,
}

impl TraceRecorder {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            created_at_utc: Utc::now(),
            events: Vec::new(),
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    pub fn record_event(
        &mut self,
        operation: impl Into<String>,
        inputs: Vec<String>,
        output: impl Into<String>,
        ciphertext_sha256: impl Into<String>,
        ciphertext_size_bytes: usize,
        metadata: BTreeMap<String, String>,
    ) -> &TraceEvent {
        let event = TraceEvent {
            step: self.events.len() as u64,
            timestamp_utc: Utc::now(),
            operation: operation.into(),
            inputs,
            output: output.into(),
            ciphertext_sha256: ciphertext_sha256.into(),
            ciphertext_size_bytes,
            metadata,
        };

        self.events.push(event);
        self.events
            .last()
            .expect("trace recorder has at least one event after push")
    }

    pub fn merkle_root(&self) -> Result<String> {
        let tree = self.build_tree()?;
        let root = tree.root().ok_or_else(|| anyhow!("trace has no root"))?;
        Ok(hex::encode(root))
    }

    pub fn proof_for_step(&self, leaf_index: usize) -> Result<StepProof> {
        ensure!(!self.events.is_empty(), "trace is empty");
        ensure!(leaf_index < self.events.len(), "leaf index out of bounds");

        let leaves = self.event_leaves()?;
        let tree = MerkleTree::<EvmKeccakHasher>::from_leaves(&leaves);
        let proof = tree.proof(&[leaf_index]);
        let root = tree.root().ok_or_else(|| anyhow!("trace has no root"))?;

        Ok(StepProof {
            leaf_index,
            total_leaves: leaves.len(),
            leaf_hash: hex::encode(leaves[leaf_index]),
            root: hex::encode(root),
            proof_hashes: proof
                .proof_hashes()
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        })
    }

    pub fn bundle(&self) -> Result<TraceBundle> {
        Ok(TraceBundle {
            session_id: self.session_id.clone(),
            generated_at_utc: self.created_at_utc,
            merkle_root: self.merkle_root()?,
            events: self.events.clone(),
        })
    }

    fn build_tree(&self) -> Result<MerkleTree<EvmKeccakHasher>> {
        ensure!(!self.events.is_empty(), "trace is empty");
        let leaves = self.event_leaves()?;
        Ok(MerkleTree::<EvmKeccakHasher>::from_leaves(&leaves))
    }

    fn event_leaves(&self) -> Result<Vec<[u8; 32]>> {
        self.events
            .iter()
            .map(event_leaf_hash)
            .collect::<Result<Vec<_>>>()
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha2Digest::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn keccak256_hex(bytes: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("failed to serialize value to json")
}

pub fn merkle_root_hex_from_serializables<T: Serialize>(items: &[T]) -> Result<String> {
    ensure!(
        !items.is_empty(),
        "cannot build a Merkle root from an empty list"
    );
    let leaves = serializable_leaves(items)?;
    let tree = MerkleTree::<EvmKeccakHasher>::from_leaves(&leaves);
    let root = tree
        .root()
        .ok_or_else(|| anyhow!("serializable tree has no root"))?;
    Ok(hex::encode(root))
}

pub fn merkle_proof_from_serializables<T: Serialize>(
    items: &[T],
    leaf_index: usize,
) -> Result<StepProof> {
    ensure!(!items.is_empty(), "cannot build a proof from an empty list");
    ensure!(leaf_index < items.len(), "leaf index out of bounds");

    let leaves = serializable_leaves(items)?;
    let tree = MerkleTree::<EvmKeccakHasher>::from_leaves(&leaves);
    let proof = tree.proof(&[leaf_index]);
    let root = tree
        .root()
        .ok_or_else(|| anyhow!("serializable tree has no root"))?;

    Ok(StepProof {
        leaf_index,
        total_leaves: leaves.len(),
        leaf_hash: hex::encode(leaves[leaf_index]),
        root: hex::encode(root),
        proof_hashes: proof
            .proof_hashes()
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
    })
}

fn event_leaf_hash(event: &TraceEvent) -> Result<[u8; 32]> {
    let payload = json_bytes(event)?;
    let digest = EvmKeccakHasher::hash(payload.as_slice());
    Ok(digest)
}

fn serializable_leaves<T: Serialize>(items: &[T]) -> Result<Vec<[u8; 32]>> {
    items
        .iter()
        .map(|item| {
            let payload = json_bytes(item)?;
            Ok(EvmKeccakHasher::hash(payload.as_slice()))
        })
        .collect::<Result<Vec<_>>>()
}

fn decode_hash(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid hex hash: {value}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte hash, got {} bytes", len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusion_proof_round_trip_verifies() {
        let mut recorder = TraceRecorder::new("session-test");

        for index in 0..3usize {
            let mut metadata = BTreeMap::new();
            metadata.insert("kind".to_string(), "unit-test".to_string());
            metadata.insert("index".to_string(), index.to_string());

            recorder.record_event(
                format!("op-{index}"),
                vec![format!("input-{index}")],
                format!("output-{index}"),
                sha256_hex(format!("ciphertext-{index}").as_bytes()),
                16 + index,
                metadata,
            );
        }

        let proof = recorder.proof_for_step(1).expect("proof should exist");
        assert!(proof.verify().expect("proof verification should run"));
        assert_eq!(
            proof.root,
            recorder.merkle_root().expect("root should be available")
        );
    }
}
