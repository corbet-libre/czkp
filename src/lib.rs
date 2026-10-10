//! Canonical encodings and maintained cryptographic adapters shared by accounting.
#![allow(missing_docs)]
#![forbid(unsafe_code)]
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod native;
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofScope {
    pub circuit_digest: [u8; 32],
    pub verifying_key_digest: [u8; 32],
}
pub const MAX_INTEGER: u64 = 9_007_199_254_740_991;

pub fn scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

pub fn decode<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != (N * 8).div_ceil(6) {
        return Err(Error::InvalidInput);
    }
    // The upstream canonical decoder rejects padding, ignored characters and
    // nonzero trailing bits. The exact encoded length fixes the output length.
    let mut decoded = [0; N];
    BASE64URL_NOPAD
        .decode_mut(value.as_bytes(), &mut decoded)
        .map_err(|_| Error::InvalidInput)?;
    Ok(decoded)
}

pub fn signature(key: &str, bytes: &[u8], value: &str) -> Result<(), Error> {
    let public = VerifyingKey::from_bytes(&decode::<32>(key)?).map_err(|_| Error::Signature)?;
    let signature = Signature::from_bytes(&decode::<64>(value)?);
    public
        .verify_strict(bytes, &signature)
        .map_err(|_| Error::Signature)?;
    Ok(())
}

pub fn digest(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(bytes))
}

/// BN254 scalar modulus, big endian. Commitments must be canonical field values.
const MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub fn field(value: &[u8; 32], nonzero: bool) -> Result<(), Error> {
    if value >= &MODULUS || (nonzero && *value == [0; 32]) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Admission,
    Signature,
    Expired,
    ClockRollback,
    Replay,
    Capacity,
    NoAllowance,
    PolicyMismatch,
    Storage,
    UnsupportedCapability,
    CryptoProvider,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
