//! Reusable public epoch statement and maintained Ed25519 presentation binding.
use super::Epoch;
use crate::{Error, MAX_INTEGER};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum Use {
    FirstContact,
    ForumListing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    pub purpose: Use,
    pub challenge: [u8; 32],
    pub expires_at: u64,
}

/// Public inputs of one cached proof. No per-request challenge or private state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub epoch: Epoch,
    pub owner: [u8; 32],
    pub presentation_key: [u8; 32],
    pub blinded_leaf: [u8; 32],
    pub certificate: Vec<u8>,
    pub shares: Option<[u16; 3]>,
}

/// The Ed25519 public key itself is a public proof input; no key hash is used.
pub fn presentation_key(public_key: &[u8; 32]) -> [u8; 32] {
    *public_key
}

impl Record {
    pub fn validate(&self) -> Result<(), Error> {
        let period = self
            .epoch
            .expires_at
            .checked_sub(self.epoch.starts_at)
            .ok_or(Error::InvalidInput)?;
        self.epoch.validate(&self.epoch.community, period)?;
        if self.epoch.community == [0; 32]
            || self.epoch.policy_epoch == 0
            || self.epoch.leaf_count > super::MAX_LEAVES
            || self.owner == [0; 32]
            || self.presentation_key == [0; 32]
            || self.blinded_leaf == [0; 32]
            || self.certificate.len() != 64
            || self
                .shares
                .is_some_and(|s| s.into_iter().map(u32::from).sum::<u32>() != 10_000)
        {
            return Err(Error::InvalidInput);
        }
        crate::field(&self.blinded_leaf, true)?;
        Ok(())
    }

    /// Fixed width message shared with the browser codec. No JSON canonicalizer.
    pub fn presentation_bytes(&self, context: &Context) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let e = &self.epoch;
        if context.challenge == [0; 32]
            || context.expires_at <= e.starts_at
            || context.expires_at > e.expires_at
            || context.expires_at > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        let mut out = b"cblc.record-presentation.v3\0".to_vec();
        out.extend_from_slice(&e.community);
        for value in [e.policy_epoch, e.epoch, e.starts_at, e.expires_at] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            &e.root,
            &e.proof_scope.circuit_digest,
            &e.proof_scope.verifying_key_digest,
        ] {
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&e.issuer_key);
        out.extend_from_slice(&e.leaf_count.to_be_bytes());
        out.extend_from_slice(&e.download_digest);
        out.extend_from_slice(&e.download_bytes.to_be_bytes());
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.presentation_key);
        out.extend_from_slice(&self.blinded_leaf);
        out.extend_from_slice(&self.certificate);
        out.push(u8::from(self.shares.is_some()));
        for value in self.shares.unwrap_or([0; 3]) {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.push(match context.purpose {
            Use::FirstContact => 0,
            Use::ForumListing => 1,
        });
        out.extend_from_slice(&context.challenge);
        out.extend_from_slice(&context.expires_at.to_be_bytes());
        Ok(out)
    }
}

/// Untrusted wire input. Success from `check_binding` is not proof verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Presentation {
    pub record: Record,
    pub context: Context,
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
    /// Original bounded hexadecimal ZK proof bundle, identical on each use.
    pub proof: String,
}

impl Presentation {
    /// Refuse stale epoch, wrong challenge/owner, missing proof and forged binding.
    /// The caller must still verify the proof and atomically consume its challenge.
    pub fn check_binding(
        &self,
        expected: &Context,
        epoch: &Epoch,
        owner: &[u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        if &self.record.epoch != epoch || &self.record.owner != owner || &self.context != expected {
            return Err(Error::Admission);
        }
        epoch.check_time(now)?;
        if now >= expected.expires_at {
            return Err(Error::Expired);
        }
        if self.proof.is_empty()
            || self.proof.len() > 8 * 1024 * 1024
            || self.proof.len() % 2 != 0
            || !self.proof.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::InvalidInput);
        }
        if presentation_key(&self.public_key) != self.record.presentation_key {
            return Err(Error::Signature);
        }
        super::verify_certificate(
            &epoch.issuer_key,
            &epoch.community,
            epoch.epoch,
            &self.record.blinded_leaf,
            &self.record.certificate,
        )?;
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| Error::Signature)?;
        let signature = Signature::from_slice(&self.signature).map_err(|_| Error::Signature)?;
        key.verify_strict(&self.record.presentation_bytes(expected)?, &signature)
            .map_err(|_| Error::Signature)
    }
}
