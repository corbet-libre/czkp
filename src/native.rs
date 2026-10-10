//! Bounded public wire data for the isolated upstream Barretenberg worker.
//!
//! The worker uses the official generated Rust API. It owns no proof system,
//! reads no artifact files and initializes the authenticated setup in RAM.
use crate::ProofScope;
use serde::{Deserialize, Serialize};

/// One complete compressed chunk authenticated by Barretenberg itself.
pub const SRS_G1_BYTES: usize = 4 * 1024 * 1024;
/// Maximum supported verification-key snapshot.
pub const MAX_KEY_BYTES: usize = 1024 * 1024;
/// Maximum public proof size before hex encoding.
pub const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of explicitly bound public field elements.
pub const MAX_PUBLIC_INPUTS: usize = 4096;
/// Maximum proofs in one indivisible verification request.
pub const MAX_PROOFS: usize = 65;
/// Aggregate public-input bound across one request.
pub const MAX_TOTAL_PUBLIC_INPUTS: usize = 32_768;
/// Complete JSON envelope bound, including byte-array public inputs.
pub const MAX_REQUEST_BYTES: usize =
    2 * (SRS_G1_BYTES + MAX_KEY_BYTES + MAX_PROOF_BYTES) + 8 * 1024 * 1024;

/// One proof and its complete ordered public inputs.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof<'a> {
    /// Canonical big-endian BN254 scalar field elements.
    pub public_inputs: &'a [[u8; 32]],
    /// Lower-case hex of the upstream proof bytes.
    pub proof: &'a str,
}

/// Borrowed, public-only request. No witness or member opening belongs here.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Request<'a> {
    /// Authenticated circuit and verification-key identity.
    pub scope: &'a ProofScope,
    /// Lower-case hex of the authenticated verification key.
    pub verification_key: &'a str,
    /// Lower-case hex of the authenticated compressed G1 chunk.
    pub srs_g1: &'a str,
    /// Lower-case hex of the authenticated G2 point.
    pub srs_g2: &'a str,
    /// All proofs must verify; there is no partial success verdict.
    pub proofs: &'a [Proof<'a>],
}

/// Minimal worker verdict; diagnostics never enter the public result.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Verdict {
    /// True only after every upstream verification succeeds.
    pub verified: bool,
    /// Exact authenticated request scope.
    pub proof_scope: ProofScope,
}

#[cfg(feature = "native-worker")]
mod worker;
#[cfg(feature = "native-worker")]
pub use worker::run_worker;
