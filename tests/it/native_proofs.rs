//! Real upstream-generated proofs qualify native verification; no accepting stub.
#![cfg(all(feature = "native-worker", not(target_arch = "wasm32")))]
use czkp::{
    ProofScope,
    native::{self, Verdict},
};
use serde::Deserialize;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    public_inputs: Vec<[u8; 32]>,
    proof: String,
    proof_scope: ProofScope,
}

fn verify(request: &native::Request<'_>) -> Option<Verdict> {
    let input = serde_json::to_vec(request).unwrap();
    assert!(input.len() <= native::MAX_REQUEST_BYTES);
    let mut command = Command::new(env!("CARGO_BIN_EXE_czkp-bb-worker"));
    command
        .env_clear()
        .env("CZKP_NATIVE_MEMORY_MIB", "4096")
        .env("HARDWARE_CONCURRENCY", "1")
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|path| ("LLVM_PROFILE_FILE", path)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(4097).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            let _ = reader.join();
            panic!("native verification timed out");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let wrote = writer.join().unwrap();
    let output = reader.join().unwrap();
    assert!(Instant::now() < deadline);
    assert!(output.len() <= 4096);
    if !status.success() {
        return None;
    }
    wrote.unwrap();
    Some(serde_json::from_slice(&output).unwrap())
}

#[test]
fn genuine_account_batch_verifies_and_changed_inputs_or_setup_refuse() {
    let directory = PathBuf::from(
        std::env::var_os("CZKP_FIXTURE_SOURCE").expect("CI must provide actual proof fixtures"),
    )
    .join(".proof-test");
    let records: Vec<Record> =
        serde_json::from_slice(&fs::read(directory.join("native-records.json")).unwrap()).unwrap();
    assert_eq!(records.len(), 2);
    let key = data_encoding::HEXLOWER.encode(&fs::read(directory.join("vk.bin")).unwrap());
    let g1 = fs::read(directory.join("setup/g1.dat")).unwrap();
    let g1 = data_encoding::HEXLOWER.encode(&g1[..native::SRS_G1_BYTES]);
    let g2 = data_encoding::HEXLOWER.encode(&fs::read(directory.join("setup/g2.dat")).unwrap());
    let proofs: Vec<_> = records
        .iter()
        .map(|record| {
            assert_eq!(record.proof_scope, records[0].proof_scope);
            native::Proof {
                public_inputs: &record.public_inputs,
                proof: &record.proof,
            }
        })
        .collect();
    let request = native::Request {
        scope: &records[0].proof_scope,
        verification_key: &key,
        srs_g1: &g1,
        srs_g2: &g2,
        proofs: &proofs,
    };
    let verdict = verify(&request).unwrap();
    assert!(verdict.verified);
    assert_eq!(verdict.proof_scope, records[0].proof_scope);
    let mut changed = records[1].public_inputs.clone();
    changed[0][31] ^= 1;
    let changed_proofs = [
        native::Proof {
            public_inputs: &records[0].public_inputs,
            proof: &records[0].proof,
        },
        native::Proof {
            public_inputs: &changed,
            proof: &records[1].proof,
        },
    ];
    assert!(
        verify(&native::Request {
            proofs: &changed_proofs,
            ..request
        })
        .is_none()
    );
    let invalid_g2 = "00".repeat(128);
    assert!(
        verify(&native::Request {
            srs_g2: &invalid_g2,
            ..request
        })
        .is_none()
    );
}
