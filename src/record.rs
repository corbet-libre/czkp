//! Canonical public epoch descriptor and private frontier leaf encoding.
//! These codecs grant no membership, currentness, or verified proof capability.
use crate::{Error, MAX_INTEGER};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bounded common object transport, independent of the configured epoch duration.
pub const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
pub enum Purpose {
    #[serde(rename = "cblc.record-epoch.v1")]
    RecordEpochV1,
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
            || self.proof_scope.circuit_digest == [0; 32]
            || self.proof_scope.verifying_key_digest == [0; 32]
            || self.leaf_count == 0
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

    /// Depth of the power-of-two padded tree, at least one and at most 32.
    /// Index remains private in the proof, and must be below `leaf_count`.
    pub fn depth(&self) -> u32 {
        (u32::BITS - self.leaf_count.saturating_sub(1).leading_zeros()).max(1)
    }
}

/// Private input held by the issuer while freezing the actual durable frontier
/// and inside Wallet after HPKE decryption. No Debug or public-value projection.
/// Supplying this value does not establish inclusion or accepted local state.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Leaf {
    pub owner: [u8; 32],
    pub version: u64,
    pub state: [u8; 32],
    pub required_inbox: [u8; 32],
    pub blinding: [u8; 32],
}

impl Leaf {
    /// Fixed transcript consumed by the original record epoch circuit.
    /// The maintained SHA-256 implementation performs all hashing.
    pub fn commitment(&self, community: &[u8; 32], epoch: u64) -> Result<[u8; 32], Error> {
        if epoch == 0
            || epoch > MAX_INTEGER
            || self.version > MAX_INTEGER
            || self.blinding == [0; 32]
        {
            return Err(Error::InvalidInput);
        }
        crate::field(&self.state, true)?;
        let mut hash = Sha256::new();
        hash.update(b"cblc.record-frontier.v1\0");
        hash.update(community);
        hash.update(epoch.to_be_bytes());
        hash.update(self.owner);
        hash.update(self.version.to_be_bytes());
        hash.update(self.state);
        hash.update(self.required_inbox);
        hash.update(self.blinding);
        Ok(hash.finalize().into())
    }
}
