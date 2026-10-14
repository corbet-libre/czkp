//! Original R2 epoch, private witness, issuer certificate and presentation codecs.
//! Encoding, signature and binding checks grant no membership, currentness or
//! verified proof capability. The relying owner must authenticate the current
//! descriptor, verify the cached proof and atomically consume its fresh challenge.
use crate::{Error, MAX_INTEGER};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod presentation;
pub use presentation::{Context, Presentation, Record, Use, presentation_key};

/// Original epoch tree capacity, independent of the configured epoch duration.
pub const MAX_LEAVES: u32 = 1 << 20;

/// Bounded complete ciphertext object; independent of tree capacity.
pub const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
pub enum Purpose {
    #[serde(rename = "cblc.record-epoch.v3")]
    RecordEpochV3,
}

/// Public descriptor carried inside the original signed Beacon material.
/// Deserialization and validation do not authenticate it: the relying owner
/// must obtain these exact bytes through its current verified Charter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Epoch {
    pub purpose: Purpose,
    pub community: [u8; 32],
    pub policy_epoch: u64,
    pub epoch: u64,
    pub starts_at: u64,
    pub expires_at: u64,
    pub root: [u8; 32],
    /// Record issuer key authenticated by the original common epoch descriptor.
    pub issuer_key: [u8; 32],
    pub proof_scope: crate::ProofScope,
    pub leaf_count: u32,
    /// SHA-256 of the complete shuffled, unlabeled ciphertext object.
    pub download_digest: [u8; 32],
    pub download_bytes: u64,
}

impl Epoch {
    /// Check exact configured epoch boundaries and public encoding bounds.
    /// `period_seconds` comes from original authenticated Rulebook settings;
    /// there is no library default, grace interval, or member-selected TTL.
    pub fn validate(&self, community: &[u8; 32], period_seconds: u64) -> Result<(), Error> {
        if self.community != *community
            || self.policy_epoch > MAX_INTEGER
            || self.epoch == 0
            || self.epoch > MAX_INTEGER
            || period_seconds == 0
            || period_seconds > MAX_INTEGER
            || self.starts_at > MAX_INTEGER
            || self.expires_at > MAX_INTEGER
            || self.epoch.checked_mul(period_seconds) != Some(self.starts_at)
            || self.starts_at.checked_add(period_seconds) != Some(self.expires_at)
            || self.root == [0; 32]
            || self.issuer_key == [0; 32]
            || self.proof_scope.circuit_digest == [0; 32]
            || self.proof_scope.verifying_key_digest == [0; 32]
            || self.leaf_count == 0
            || self.leaf_count > MAX_LEAVES
            || self.download_digest == [0; 32]
            || !(1..=MAX_DOWNLOAD_BYTES).contains(&self.download_bytes)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    /// Time check only; authentication and newest-known-epoch fencing remain
    /// Charter-owned and cannot be replaced with this method's result.
    pub fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.starts_at {
            return Err(Error::ClockRollback);
        }
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// Preserve one immutable descriptor per record epoch, independently of the
    /// enclosing publication's revision. The caller authenticates both values
    /// and supplies the same configured period; this does not grant authority.
    /// Period changes need an explicit transition, never an implicit floor reset.
    pub fn check_successor(&self, previous: &Self, period_seconds: u64) -> Result<(), Error> {
        previous.validate(&previous.community, period_seconds)?;
        self.validate(&previous.community, period_seconds)?;
        if self.epoch < previous.epoch || self.policy_epoch < previous.policy_epoch {
            return Err(Error::Replay);
        }
        if self.epoch == previous.epoch && self != previous {
            return Err(Error::PolicyMismatch);
        }
        Ok(())
    }

    /// Match the complete public ciphertext object to its bounded descriptor.
    /// This neither authenticates the descriptor nor decrypts a member witness.
    /// Transports must enforce the same byte bound before allocating the input.
    pub fn check_object(&self, bytes: &[u8]) -> Result<(), Error> {
        if !(1..=MAX_DOWNLOAD_BYTES).contains(&self.download_bytes)
            || bytes.len() as u64 != self.download_bytes
        {
            return Err(Error::InvalidInput);
        }
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != self.download_digest {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    /// Depth of the power-of-two padded tree, at least one and at most 20 for a valid descriptor.
    /// Index remains private in the proof, and must be below `leaf_count`.
    pub fn depth(&self) -> u32 {
        (u32::BITS - self.leaf_count.saturating_sub(1).leading_zeros()).max(1)
    }
}

/// Private input held by the issuer while freezing the actual durable frontier
/// and inside Wallet after HPKE decryption. No Debug or public-value projection.
/// Supplying this value does not establish inclusion or accepted local state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Leaf {
    pub owner: [u8; 32],
    pub version: u64,
    pub state: [u8; 32],
    pub required_inbox: [u8; 32],
    /// Role class (member, admin, root) attested by the issuer for this epoch.
    #[serde(default)]
    pub role: u8,
    pub blinding: [u8; 32],
}

impl Leaf {
    /// Fixed transcript consumed by the original record epoch circuit.
    /// The maintained Poseidon2 implementation performs all hashing.
    pub fn commitment(&self, community: &[u8; 32], epoch: u64) -> Result<[u8; 32], Error> {
        if epoch == 0
            || epoch > MAX_INTEGER
            || self.version > MAX_INTEGER
            || self.blinding == [0; 32]
        {
            return Err(Error::InvalidInput);
        }
        crate::field(&self.state, true)?;
        use crate::poseidon::{hash, integer, limbs};
        let mut inputs = vec![epoch_domain(), integer(LEAF_TAG)];
        inputs.extend(limbs(community));
        inputs.push(integer(epoch));
        inputs.extend(limbs(&self.owner));
        inputs.push(integer(self.version));
        inputs.push(self.state);
        inputs.extend(limbs(&self.required_inbox));
        inputs.push(integer(u64::from(self.role)));
        inputs.extend(limbs(&self.blinding));
        hash(&inputs)
    }
}

/// Hash tag of an epoch leaf; interior nodes keep tag 2, so the two never share a transcript shape.
pub const LEAF_TAG: u64 = 3;

fn epoch_domain() -> [u8; 32] {
    let mut domain = [0; 32];
    let text = b"cblc.record-epoch.v2";
    domain[32 - text.len()..].copy_from_slice(text);
    domain
}

/// Poseidon2 adapter for the existing maintained Merkle tree library. Only
/// internal nodes (two bytes32 children) are hashed; leaves are already blinded.
#[derive(Clone)]
pub struct EpochTree;
impl rs_merkle::Hasher for EpochTree {
    type Hash = [u8; 32];
    fn hash(data: &[u8]) -> Self::Hash {
        use crate::poseidon::{hash, integer, limbs};
        // rs_merkle combines exactly two fixed-width child hashes.
        assert_eq!(data.len(), 64);
        let mut inputs = vec![epoch_domain(), integer(2)];
        let (children, _) = data.as_chunks::<32>();
        for child in children {
            inputs.extend(limbs(child));
        }
        hash(&inputs).expect("domain and 128-bit limbs are canonical fields")
    }
}

/// Same private packet shape for frozen and necessarily descended frontiers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedLeaf {
    /// Private opening of the public blinded leaf.
    pub leaf: Leaf,
    /// Standard Ed25519 signature on community, epoch and the blinded leaf.
    pub signature: Vec<u8>,
}

/// Domain-separated issuer statement for both frozen and descendant leaves.
pub fn certificate_bytes(
    community: &[u8; 32],
    epoch: u64,
    leaf: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if *community == [0; 32] || epoch == 0 || epoch > MAX_INTEGER {
        return Err(Error::InvalidInput);
    }
    crate::field(leaf, true)?;
    let mut bytes = b"cblc.record-leaf.v1\0".to_vec();
    bytes.extend_from_slice(community);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(leaf);
    Ok(bytes)
}
/// Verify the original issuer certificate only, not a proof or currentness authority.
pub fn verify_certificate(
    key: &[u8; 32],
    community: &[u8; 32],
    epoch: u64,
    leaf: &[u8; 32],
    signature: &[u8],
) -> Result<(), Error> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| Error::Signature)?;
    let signature =
        ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::Signature)?;
    key.verify_strict(&certificate_bytes(community, epoch, leaf)?, &signature)
        .map_err(|_| Error::Signature)
}
