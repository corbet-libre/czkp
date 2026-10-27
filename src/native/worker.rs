use super::{
    MAX_KEY_BYTES, MAX_PROOF_BYTES, MAX_PROOFS, MAX_PUBLIC_INPUTS, MAX_REQUEST_BYTES,
    MAX_TOTAL_PUBLIC_INPUTS, SRS_G1_BYTES, Verdict,
};
use crate::{Error, ProofScope, field};
use barretenberg_rs::{
    BarretenbergApi, backends::FfiBackend, generated_types::ProofSystemSettings,
};
use data_encoding::HEXLOWER;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    scope: ProofScope,
    verification_key: String,
    srs_g1: String,
    srs_g2: String,
    proofs: Vec<Proof>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proof {
    public_inputs: Vec<[u8; 32]>,
    proof: String,
}

fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, Error> {
    if value.is_empty() || value.len() > maximum * 2 {
        return Err(Error::InvalidInput);
    }
    HEXLOWER
        .decode(value.as_bytes())
        .or(Err(Error::InvalidInput))
}

fn verify(request: Request) -> Result<Verdict, Error> {
    if request.scope.circuit_digest == [0; 32]
        || request.proofs.is_empty()
        || request.proofs.len() > MAX_PROOFS
        || request.srs_g1.len() != SRS_G1_BYTES * 2
        || request.srs_g2.len() != 256
    {
        return Err(Error::InvalidInput);
    }
    let mut total_bytes = 0usize;
    let mut total_fields = 0usize;
    let mut proofs = Vec::with_capacity(request.proofs.len());
    for item in &request.proofs {
        if item.public_inputs.is_empty() || item.public_inputs.len() > MAX_PUBLIC_INPUTS {
            return Err(Error::InvalidInput);
        }
        total_fields += item.public_inputs.len();
        if total_fields > MAX_TOTAL_PUBLIC_INPUTS {
            return Err(Error::InvalidInput);
        }
        for value in &item.public_inputs {
            field(value, false)?;
        }
        let proof = decode(&item.proof, MAX_PROOF_BYTES)?;
        total_bytes += proof.len();
        if proof.len() % 32 != 0 || total_bytes > MAX_PROOF_BYTES {
            return Err(Error::InvalidInput);
        }
        proofs.push(proof);
    }
    let key = decode(&request.verification_key, MAX_KEY_BYTES)?;
    let key_digest: [u8; 32] = Sha256::digest(&key).into();
    if key_digest != request.scope.verifying_key_digest {
        return Err(Error::InvalidInput);
    }
    let g1 = decode(&request.srs_g1, SRS_G1_BYTES)?;
    let g2 = decode(&request.srs_g2, 128)?;
    // A fresh process has no global CRS factory. Unlike the upstream CLI, this
    // entry point never installs its filesystem/network factory first.
    let backend = FfiBackend::new().or(Err(Error::CryptoProvider))?;
    let mut api = BarretenbergApi::new(backend);
    api.srs_init_srs(&g1, 131_072, &g2)
        .or(Err(Error::CryptoProvider))?;
    for (item, proof) in request.proofs.iter().zip(proofs) {
        let result = api
            .circuit_verify(
                &key,
                item.public_inputs
                    .iter()
                    .map(|value| value.to_vec())
                    .collect(),
                proof
                    .as_chunks::<32>()
                    .0
                    .iter()
                    .map(|value| value.to_vec())
                    .collect(),
                ProofSystemSettings {
                    ipa_accumulation: false,
                    oracle_hash_type: "poseidon2".into(),
                    disable_zk: false,
                    optimized_solidity_verifier: false,
                },
            )
            .or(Err(Error::CryptoProvider))?;
        if !result.verified {
            return Err(Error::CryptoProvider);
        }
    }
    api.destroy().or(Err(Error::CryptoProvider))?;
    Ok(Verdict {
        verified: true,
        proof_scope: request.scope,
    })
}

/// Run exactly one bounded batch in this isolated process.
///
/// The host sets `CZKP_NATIVE_MEMORY_MIB` before spawning; address-space and core
/// dump limits are applied through a maintained safe API before input parsing.
/// The host must discard stderr and kill/reap this process at its deadline.
pub fn run_worker() -> Result<(), Error> {
    let memory: u64 = std::env::var("CZKP_NATIVE_MEMORY_MIB")
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(Error::InvalidInput)?;
    if !(256..=65_536).contains(&memory) {
        return Err(Error::InvalidInput);
    }
    let bytes = memory * 1024 * 1024;
    rlimit::Resource::AS
        .set(bytes, bytes)
        .or(Err(Error::CryptoProvider))?;
    rlimit::Resource::CORE
        .set(0, 0)
        .or(Err(Error::CryptoProvider))?;
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .or(Err(Error::CryptoProvider))?;
    if input.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidInput);
    }
    let request = serde_json::from_slice(&input).or(Err(Error::InvalidInput))?;
    let verdict = verify(request)?;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &verdict).or(Err(Error::CryptoProvider))?;
    output.write_all(b"\n").or(Err(Error::CryptoProvider))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const KEY: [u8; 32] = [5; 32];

    fn key_hex() -> String {
        HEXLOWER.encode(&KEY)
    }

    fn key_digest() -> [u8; 32] {
        Sha256::digest(KEY).into()
    }

    fn valid_proof() -> Proof {
        Proof {
            public_inputs: vec![[0; 32]],
            proof: "00".repeat(32),
        }
    }

    fn valid_request() -> Request {
        Request {
            scope: ProofScope {
                circuit_digest: [1; 32],
                verifying_key_digest: key_digest(),
            },
            verification_key: key_hex(),
            srs_g1: "00".repeat(SRS_G1_BYTES),
            srs_g2: "00".repeat(128),
            proofs: vec![valid_proof()],
        }
    }

    fn invalid(request: Request) {
        assert!(matches!(verify(request), Err(Error::InvalidInput)));
    }

    fn refused_until_crypto(request: Request) {
        assert!(matches!(verify(request), Err(Error::CryptoProvider)));
    }

    #[test]
    fn decode_accepts_exact_boundary_hex() {
        assert_eq!(decode("00112233", 4), Ok(vec![0x00, 0x11, 0x22, 0x33]));
    }

    #[test]
    fn decode_accepts_short_hex() {
        assert_eq!(decode("00", 1024), Ok(vec![0]));
    }

    #[test]
    fn decode_refuses_empty() {
        assert_eq!(decode("", 1024), Err(Error::InvalidInput));
    }

    #[test]
    fn decode_refuses_overlong_valid_hex() {
        assert_eq!(decode(&"00".repeat(5), 4), Err(Error::InvalidInput));
    }

    #[test]
    fn decode_uses_double_maximum_not_sum() {
        assert_eq!(decode(&"00".repeat(8), 8), Ok(vec![0; 8]));
    }

    #[test]
    fn verify_refuses_zero_circuit_digest() {
        let mut request = valid_request();
        request.scope.circuit_digest = [0; 32];
        invalid(request);
    }

    #[test]
    fn verify_refuses_empty_proofs() {
        let mut request = valid_request();
        request.proofs.clear();
        invalid(request);
    }

    #[test]
    fn verify_refuses_too_many_proofs() {
        let mut request = valid_request();
        request.proofs = (0..MAX_PROOFS + 1).map(|_| valid_proof()).collect();
        invalid(request);
    }

    #[test]
    fn verify_accepts_exactly_max_proofs_shape_until_crypto() {
        let mut request = valid_request();
        request.proofs = (0..MAX_PROOFS).map(|_| valid_proof()).collect();
        refused_until_crypto(request);
    }

    #[test]
    fn verify_refuses_short_srs_g1() {
        let mut request = valid_request();
        request.srs_g1 = "00".to_string();
        invalid(request);
    }

    #[test]
    fn verify_refuses_srs_g1_at_sum_not_product_length() {
        let mut request = valid_request();
        request.srs_g1 = "00".repeat(SRS_G1_BYTES / 2 + 1);
        invalid(request);
    }

    #[test]
    fn verify_refuses_srs_g1_at_half_length() {
        let mut request = valid_request();
        request.srs_g1 = "00".repeat(SRS_G1_BYTES / 2);
        invalid(request);
    }

    #[test]
    fn verify_refuses_short_srs_g2() {
        let mut request = valid_request();
        request.srs_g2 = "00".to_string();
        invalid(request);
    }

    #[test]
    fn verify_refuses_empty_public_inputs() {
        let mut request = valid_request();
        request.proofs[0].public_inputs.clear();
        invalid(request);
    }

    #[test]
    fn verify_refuses_too_many_public_inputs() {
        let mut request = valid_request();
        request.proofs[0].public_inputs = vec![[0; 32]; MAX_PUBLIC_INPUTS + 1];
        invalid(request);
    }

    #[test]
    fn verify_accepts_exactly_max_public_inputs_shape_until_crypto() {
        let mut request = valid_request();
        request.proofs[0].public_inputs = vec![[0; 32]; MAX_PUBLIC_INPUTS];
        refused_until_crypto(request);
    }

    #[test]
    fn verify_refuses_excess_total_public_inputs() {
        let mut request = valid_request();
        request.proofs = (0..9)
            .map(|_| Proof {
                public_inputs: vec![[0; 32]; 4000],
                proof: "00".repeat(32),
            })
            .collect();
        invalid(request);
    }

    #[test]
    fn verify_accepts_exactly_max_total_public_inputs_shape_until_crypto() {
        let mut request = valid_request();
        request.proofs = (0..8)
            .map(|_| Proof {
                public_inputs: vec![[0; 32]; 4096],
                proof: "00".repeat(32),
            })
            .collect();
        refused_until_crypto(request);
    }

    #[test]
    fn verify_refuses_excess_total_proof_bytes() {
        let mut request = valid_request();
        request.proofs = (0..5)
            .map(|_| Proof {
                public_inputs: vec![[0; 32]],
                proof: "00".repeat(1024 * 1024),
            })
            .collect();
        invalid(request);
    }

    #[test]
    fn verify_accepts_exactly_max_total_proof_bytes_shape_until_crypto() {
        let mut request = valid_request();
        request.proofs = (0..4)
            .map(|_| Proof {
                public_inputs: vec![[0; 32]],
                proof: "00".repeat(1024 * 1024),
            })
            .collect();
        refused_until_crypto(request);
    }

    #[test]
    fn verify_refuses_proof_length_not_multiple_of_32() {
        let mut request = valid_request();
        request.proofs[0].proof = "00".repeat(31);
        invalid(request);
    }

    #[test]
    fn verify_accepts_well_shaped_request_until_crypto() {
        refused_until_crypto(valid_request());
    }
}
