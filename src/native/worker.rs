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
