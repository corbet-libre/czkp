//! The account certificate issuer key ring. Extension artifacts pin only circuits and
//! verifying keys; the P-256 keys that sign accepted-state and ancestry certificates are
//! published in the community's signed verifier status as this ring. Every key keeps the
//! period it signed in (`valid_from` inclusive, `valid_until` exclusive, absent while the key
//! is current). Retired keys are never removed, so a certificate made before a rotation keeps
//! verifying at its own acceptance time, and never at a time outside its key's period.
use crate::Error;
use serde::{Deserialize, Serialize};

const MAX_INTEGER: u64 = (1 << 53) - 1;
/// Bound of one published ring.
pub const MAX_PERIODS: usize = 64;

/// One issuer key and the half-open period it signs certificates in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateKeyPeriod {
    /// Uncompressed affine P-256 coordinates without the SEC1 prefix (64 bytes).
    pub public_key: Vec<u8>,
    /// First second the key signs in (inclusive).
    pub valid_from: u64,
    /// First second the key no longer signs in; absent while the key is current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

impl CertificateKeyPeriod {
    /// Exclusive end of the period; an open period ends at the largest circuit integer.
    pub fn until(&self) -> u64 {
        self.valid_until.unwrap_or(MAX_INTEGER)
    }
    /// The key as fixed bytes.
    pub fn key(&self) -> Result<[u8; 64], Error> {
        self.public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidInput)
    }
    fn contains(&self, at: u64) -> bool {
        self.valid_from <= at && at < self.until()
    }
}

/// Publication rule: 1..=MAX_PERIODS periods, ordered and disjoint, every key a P-256
/// point, every bound a circuit integer, and only the last period may be open.
pub fn validate(ring: &[CertificateKeyPeriod]) -> Result<(), Error> {
    if ring.is_empty() || ring.len() > MAX_PERIODS {
        return Err(Error::InvalidInput);
    }
    for (i, period) in ring.iter().enumerate() {
        point(&period.key()?)?;
        let last = i + 1 == ring.len();
        if period.valid_from == 0
            || period.valid_from > MAX_INTEGER
            || period.until() <= period.valid_from
            || period.until() > MAX_INTEGER
            || (period.valid_until.is_none() && !last)
        {
            return Err(Error::InvalidInput);
        }
        if let Some(next) = ring.get(i + 1)
            && next.valid_from < period.until()
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

/// The key that signed at `at`; a time outside every period has no key.
pub fn key_at(ring: &[CertificateKeyPeriod], at: u64) -> Result<[u8; 64], Error> {
    validate(ring)?;
    ring.iter()
        .find(|period| period.contains(at))
        .ok_or(Error::PolicyMismatch)?
        .key()
}

/// The exact period a prover names by key and start (anonymous deposits hide the
/// acceptance time, so the relation itself binds it into this period).
pub fn period(
    ring: &[CertificateKeyPeriod],
    key: &[u8; 64],
    valid_from: u64,
) -> Result<CertificateKeyPeriod, Error> {
    validate(ring)?;
    ring.iter()
        .find(|period| period.public_key == key && period.valid_from == valid_from)
        .cloned()
        .ok_or(Error::PolicyMismatch)
}

/// The ring after making `current` the open key at `now`: the previous open period is
/// retired at `now` (or one second after its start) and the new period starts exactly
/// there. `None` when `current` already is the open key. Nothing is ever removed.
pub fn advance(
    ring: &[CertificateKeyPeriod],
    current: &[u8; 64],
    now: u64,
) -> Result<Option<Vec<CertificateKeyPeriod>>, Error> {
    point(current)?;
    if now == 0 || now > MAX_INTEGER {
        return Err(Error::InvalidInput);
    }
    let mut ring = ring.to_vec();
    if !ring.is_empty() {
        validate(&ring)?;
    }
    let mut from = now;
    if let Some(open) = ring.last_mut() {
        match open.valid_until {
            None if open.public_key == current => return Ok(None),
            None => {
                let until = now.max(open.valid_from.saturating_add(1));
                open.valid_until = Some(until);
                from = until;
            }
            Some(until) => from = now.max(until),
        }
    }
    if ring.len() >= MAX_PERIODS {
        return Err(Error::Capacity);
    }
    ring.push(CertificateKeyPeriod {
        public_key: current.to_vec(),
        valid_from: from,
        valid_until: None,
    });
    validate(&ring)?;
    Ok(Some(ring))
}

/// Verify an accepted-state certificate with the key of its own acceptance time.
pub fn verify_accepted(
    ring: &[CertificateKeyPeriod],
    state: &crate::certificate::AcceptedState,
    signature: &[u8; 64],
) -> Result<(), Error> {
    state.verify(&key_at(ring, state.accepted_at)?, signature)
}

/// Verify an ancestry certificate with the key of its own issuance time.
pub fn verify_ancestry(
    ring: &[CertificateKeyPeriod],
    ancestry: &crate::certificate::EpochAncestry,
    signature: &[u8; 64],
) -> Result<(), Error> {
    ancestry.verify(&key_at(ring, ancestry.issued_at)?, signature)
}

fn point(key: &[u8; 64]) -> Result<(), Error> {
    let mut encoded = [4; 65];
    encoded[1..].copy_from_slice(key);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
        .map(|_| ())
        .map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
#[path = "../tests/internal/issuer_keys.rs"]
mod tests;
