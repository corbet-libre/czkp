//! Canonical accepted-state and epoch-ancestry certificate transcripts and their
//! verification. czkp is the single owner of these signed formats: the issuer signs
//! the bytes encoded here and every verifier or holder checks through this module.
//! The accepted-state layout is also consumed by the Noir deposit relation and must
//! not change. Signing is done by the issuer; only verification lives here.
use crate::Error;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

const MAX_INTEGER: u64 = (1 << 53) - 1;
const STATE_DOMAIN: &[u8] = b"cssr.accepted-state.v1\0";
const ANCESTRY_DOMAIN: &[u8] = b"cblc.epoch-ancestry.v1\0";

/// Domain-separated certificate body. No opening or counterpart enters the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedState {
    /// Community hash.
    pub community: [u8; 32],
    /// Community-scoped opaque account owner.
    pub owner: [u8; 32],
    /// Accepted state commitment.
    pub state: [u8; 32],
    /// Digest of the pinned extension circuit manifest.
    pub scope: [u8; 32],
    /// Accepted version.
    pub version: u64,
    /// Issuer acceptance time, hidden inside anonymous deposit proofs.
    pub accepted_at: u64,
}

impl AcceptedState {
    /// Fixed encoding also checked inside the Noir deposit relation.
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = STATE_DOMAIN.to_vec();
        for field in [self.community, self.owner, self.state, self.scope] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.accepted_at.to_be_bytes());
        bytes
    }

    /// Verify the issuer's canonical low-S P-256 signature over these bytes.
    pub fn verify(&self, key: &[u8; 64], signature: &[u8; 64]) -> Result<(), Error> {
        verify_bytes(key, &self.bytes(), signature)
    }
}

/// Private minimum-frontier ancestry statement, distinct from a state certificate.
/// This body alone is never evidence of ancestry or a public member record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochAncestry {
    /// Community hash.
    pub community: [u8; 32],
    /// Community-scoped account owner, hidden in the eventual record proof.
    pub owner: [u8; 32],
    /// Published epoch number.
    pub epoch: u64,
    /// Published epoch root.
    pub root: [u8; 32],
    /// Exact blinded frozen leaf commitment in that root.
    pub frozen_leaf: [u8; 32],
    /// Newly accepted descendant commitment.
    pub state: [u8; 32],
    /// Newly accepted version.
    pub version: u64,
    /// Original update circuit manifest digest.
    pub circuit_digest: [u8; 32],
    /// Original update verification-key digest.
    pub verifying_key_digest: [u8; 32],
    /// Acceptance time of this descendant, never refreshed on retry.
    pub issued_at: u64,
}

impl EpochAncestry {
    /// Canonical fixed-width transcript: domain, community, owner, epoch, root,
    /// frozen leaf, state, version, both proof-scope digests, issuance time, in the
    /// compact message form. Digests are opaque; callers check circuit encodings.
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        if self.epoch == 0
            || self.epoch > MAX_INTEGER
            || self.version > MAX_INTEGER
            || self.issued_at == 0
            || self.issued_at > MAX_INTEGER
            || [
                self.community,
                self.owner,
                self.root,
                self.frozen_leaf,
                self.state,
                self.circuit_digest,
                self.verifying_key_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(Error::InvalidInput);
        }
        let mut bytes = ANCESTRY_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.community);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.root);
        bytes.extend_from_slice(&self.frozen_leaf);
        bytes.extend_from_slice(&self.state);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.circuit_digest);
        bytes.extend_from_slice(&self.verifying_key_digest);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        Ok(crate::compact::message(&bytes))
    }

    /// Verify the issuer's canonical low-S P-256 signature. The consumer must
    /// separately bind the expected epoch, owner and scope.
    pub fn verify(&self, key: &[u8; 64], signature: &[u8; 64]) -> Result<(), Error> {
        verify_bytes(key, &self.bytes()?, signature)
    }
}

fn verify_bytes(key: &[u8; 64], bytes: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    let mut encoded = [4; 65];
    encoded[1..].copy_from_slice(key);
    let key = VerifyingKey::from_sec1_bytes(&encoded).map_err(|_| Error::Signature)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
    // A high-S alias has a valid mathematical signature but a second wire encoding.
    if signature.normalize_s().is_some() {
        return Err(Error::Signature);
    }
    key.verify(bytes, &signature).map_err(|_| Error::Signature)
}

#[cfg(test)]
#[path = "../tests/internal/certificate.rs"]
mod tests;
