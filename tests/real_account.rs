#![cfg(all(feature = "process", not(target_arch = "wasm32")))]
//! The shipped worker verifies real public account proofs, not an accepting stub.
use czkp::process::{ProcessVerifier, ProcessVerifierConfig};
use czkp::{Error, ProofScope};
use serde::Deserialize;
use std::{fs, path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    statement: serde_json::Value,
    proof: String,
    proof_scope: ProofScope,
}

#[test]
fn maintained_account_proofs_bind_state_and_refuse_tampering() {
    let source = PathBuf::from(
        std::env::var("CVFY_FIXTURE_SOURCE").expect("CI must generate real public proof fixtures"),
    );
    let records: Vec<Record> =
        serde_json::from_slice(&fs::read(source.join(".proof-test/records.json")).unwrap())
            .unwrap();
    assert_eq!(records.len(), 2);
    let node = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("node"))
        .find(|p| p.is_absolute() && p.is_file())
        .unwrap();
    for record in records {
        let verifier = ProcessVerifier::new(ProcessVerifierConfig {
            node: node.clone(),
            script: source.join("runtime/accounting/node-verifier.mjs"),
            artifact_config: source.join(".proof-test/config.json"),
            scope: record.proof_scope.clone(),
            timeout: Duration::from_secs(180),
            maximum_parallel: 1,
            max_proof_bytes: 1024 * 1024,
            node_heap_megabytes: 4096,
        })
        .unwrap();
        assert_eq!(verifier.scope(), record.proof_scope);
        let proof = data_encoding::HEXLOWER
            .decode(record.proof.as_bytes())
            .unwrap();
        assert!(verifier.verify(&record.statement, &proof).is_ok());
        let mut corrupt = proof.clone();
        corrupt[0] ^= 1;
        assert!(verifier.verify(&record.statement, &corrupt).is_err());
        let mut changed = record.statement.clone();
        changed["nextState"][31] =
            serde_json::json!(changed["nextState"][31].as_u64().unwrap() ^ 1);
        assert!(verifier.verify(&changed, &proof).is_err());
    }
}

#[test]
fn maintained_neutral_suite_proofs_cross_the_rust_process_boundary() {
    let source = PathBuf::from(
        std::env::var("CVFY_FIXTURE_SOURCE").expect("CI must generate real public proof fixtures"),
    );
    let records: Vec<Record> =
        serde_json::from_slice(&fs::read(source.join(".neutral-suite/records.json")).unwrap())
            .unwrap();
    assert_eq!(records.len(), 2);
    let node = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("node"))
        .find(|p| p.is_absolute() && p.is_file())
        .unwrap();
    for record in records {
        let config = ProcessVerifierConfig {
            node: node.clone(),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("runtime/node-verifier.mjs"),
            artifact_config: source.join(".neutral-suite/config.json"),
            scope: record.proof_scope.clone(),
            timeout: Duration::from_secs(180),
            maximum_parallel: 1,
            max_proof_bytes: 1024 * 1024,
            node_heap_megabytes: 4096,
        };
        let verifier = ProcessVerifier::new(config.clone()).unwrap();
        let proof = data_encoding::HEXLOWER
            .decode(record.proof.as_bytes())
            .unwrap();
        assert!(verifier.verify(&record.statement, &proof).is_ok());

        let mut corrupt = proof.clone();
        corrupt[0] ^= 1;
        assert_eq!(
            verifier.verify(&record.statement, &corrupt),
            Err(Error::CryptoProvider)
        );

        let mut changed = record.statement.clone();
        let byte = changed["input"]["community"][0]
            .as_str()
            .unwrap()
            .parse::<u8>()
            .unwrap();
        changed["input"]["community"][0] = serde_json::json!((byte ^ 1).to_string());
        assert_eq!(
            verifier.verify(&changed, &proof),
            Err(Error::CryptoProvider)
        );

        let mut extra = record.statement.clone();
        extra["input"]["extra"] = serde_json::json!(0);
        assert_eq!(verifier.verify(&extra, &proof), Err(Error::CryptoProvider));

        let mut foreign = config;
        foreign.scope.verifying_key_digest[0] ^= 1;
        assert_eq!(
            ProcessVerifier::new(foreign)
                .unwrap()
                .verify(&record.statement, &proof),
            Err(Error::CryptoProvider)
        );
        // Neither genuine success nor a refusal may leak the single worker permit.
        assert!(verifier.verify(&record.statement, &proof).is_ok());
    }
}
