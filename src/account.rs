//! Canonical account statement and operator-acceptance transcripts and the strict
//! verification of the operator's acceptance. czkp is the single owner of these
//! signed formats for the Balance operator, the wallet holder and the relying
//! application. Economic validation of the fields stays with each caller; this
//! module only fixes the bytes and checks the signature.
use crate::{Error, ProofScope};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const STATEMENT_DOMAIN: &[u8] = b"cfrm.account.statement.v2\0";
const ACCEPTANCE_DOMAIN: &[u8] = b"cfrm.account.acceptance.v1\0";

/// The economic policy fields that enter the statement transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyFields {
    /// New account's initial available credit.
    pub initial_credit: u32,
    /// Mature total available plus reserved capacity.
    pub maximum_available: u32,
    /// Outgoing reservation amount.
    pub outgoing_reservation: u32,
    /// Incoming reservation amount.
    pub incoming_reservation: u32,
    /// Policy revision.
    pub policy_revision: u64,
    /// Inclusive policy activation time.
    pub policy_valid_from: u64,
    /// Exclusive policy expiry.
    pub policy_valid_until: u64,
    /// Account-age maturation period.
    pub newcomer_period: u64,
    /// Common proof and rate window.
    pub rate_window: u64,
    /// New account's rate-window admission limit.
    pub newcomer_admissions: u32,
    /// Mature account's rate-window admission limit.
    pub maximum_admissions: u32,
    /// Refill period.
    pub refill_period: u64,
    /// Refill units.
    pub refill_units: u32,
    /// Waiting interval for newly reserved contacts.
    pub abandon_after: u64,
}

impl PolicyFields {
    /// Append the fixed-width policy bytes used by the statement transcript.
    pub fn append(&self, bytes: &mut Vec<u8>) {
        for value in [
            self.initial_credit,
            self.maximum_available,
            self.outgoing_reservation,
            self.incoming_reservation,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.policy_revision,
            self.policy_valid_from,
            self.policy_valid_until,
            self.newcomer_period,
            self.rate_window,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.newcomer_admissions.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_admissions.to_be_bytes());
        bytes.extend_from_slice(&self.refill_period.to_be_bytes());
        bytes.extend_from_slice(&self.refill_units.to_be_bytes());
        bytes.extend_from_slice(&self.abandon_after.to_be_bytes());
    }
}

/// The complete public account statement fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementFields {
    /// Protocol version (currently 2).
    pub protocol_version: u32,
    /// Community hash.
    pub community: [u8; 32],
    /// Community-scoped account owner.
    pub owner: [u8; 32],
    /// Economic policy digest.
    pub policy_digest: [u8; 32],
    /// Authenticated common enrollment root.
    pub enrollment_root: [u8; 32],
    /// Statement observation time.
    pub now: u64,
    /// Exclusive proof horizon.
    pub valid_until: u64,
    /// True only for a genesis computation.
    pub genesis: bool,
    /// Previous account version.
    pub previous_version: u64,
    /// Next account version.
    pub next_version: u64,
    /// Previous state commitment.
    pub previous_state: [u8; 32],
    /// Next state commitment.
    pub next_state: [u8; 32],
    /// Settlement marker.
    pub settlement_marker: [u8; 32],
    /// Policy fields.
    pub policy: PolicyFields,
}

impl StatementFields {
    /// Fixed statement transcript (`cfrm.account.statement.v2`).
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = STATEMENT_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.protocol_version.to_be_bytes());
        for digest in [
            self.community,
            self.owner,
            self.policy_digest,
            self.enrollment_root,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.now.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until.to_be_bytes());
        bytes.push(u8::from(self.genesis));
        bytes.extend_from_slice(&self.previous_version.to_be_bytes());
        bytes.extend_from_slice(&self.next_version.to_be_bytes());
        for digest in [self.previous_state, self.next_state, self.settlement_marker] {
            bytes.extend_from_slice(&digest);
        }
        self.policy.append(&mut bytes);
        bytes
    }
}

/// Operator acceptance message (`cfrm.account.acceptance.v1`) for one statement.
/// For an extended request `request_digest` is the extended request digest.
pub fn acceptance_bytes(
    request_id: &[u8; 32],
    request_digest: &[u8; 32],
    scope: &ProofScope,
    accepted_at: u64,
    statement: &StatementFields,
) -> Vec<u8> {
    let mut bytes = ACCEPTANCE_DOMAIN.to_vec();
    bytes.extend_from_slice(request_id);
    bytes.extend_from_slice(request_digest);
    bytes.extend_from_slice(&scope.circuit_digest);
    bytes.extend_from_slice(&scope.verifying_key_digest);
    bytes.extend_from_slice(&accepted_at.to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(statement.bytes()));
    bytes
}

/// Strict Ed25519 verification of the operator's acceptance message under the
/// pinned operator key (no malleable signatures or small-order keys).
pub fn verify_acceptance(
    message: &[u8],
    operator_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    VerifyingKey::from_bytes(operator_key)
        .map_err(|_| Error::Signature)?
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error::Signature)
}

/// SHA-256 of the signed acceptance (message then signature): the value the
/// Balance status response uses for an embedded acceptance.
pub fn acceptance_digest(message: &[u8], signature: &[u8; 64]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(message);
    hash.update(signature);
    hash.finalize().into()
}

#[cfg(test)]
#[path = "../tests/internal/account.rs"]
mod tests;
