//! Exercise the actual isolated worker's input boundary without accepting a proof.
#![cfg(all(feature = "native-worker", not(target_arch = "wasm32")))]
use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn refused(input: &[u8], memory: Option<&str>) {
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_czkp-bb-worker"));
    command
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(memory) = memory {
        command.env("CZKP_NATIVE_MEMORY_MIB", memory);
    }
    #[cfg(feature = "native-worker")]
    if let Some(path) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", path);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        // The returned handle stays owned by the join handle until after child
        // completion. Oversized input must refuse while stdin remains open.
        (input.len() > czkp::native::MAX_REQUEST_BYTES).then_some(stdin)
    });
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            panic!("worker did not refuse bounded input");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(writer.join().unwrap());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    // No CRS cache, request or proof data is written to this working directory.
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn actual_worker_rejects_memory_configuration_and_oversized_input_before_eof() {
    for memory in [None, Some(""), Some("NaN"), Some("255"), Some("65537")] {
        refused(b"", memory);
    }
    for input in [b"".as_slice(), b"null", b"{}", b"{\"scope\":true}"] {
        refused(input, Some("256"));
    }
    refused(
        &vec![b' '; czkp::native::MAX_REQUEST_BYTES + 1],
        Some("256"),
    );
}

#[test]
fn actual_worker_rejects_shape_fields_and_key_binding_without_native_crypto() {
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};
    let key = [5; 32];
    let digest: [u8; 32] = Sha256::digest(key).into();
    let request = serde_json::json!({
        "scope":{"circuitDigest":vec![1;32],"verifyingKeyDigest":digest},
        "verificationKey":HEXLOWER.encode(&key),
        "srsG1":"00".repeat(czkp::native::SRS_G1_BYTES),"srsG2":"00".repeat(128),
        "proofs":[{"publicInputs":vec![[0;32]],"proof":"00".repeat(32)}]
    });
    for case in 0..13 {
        let mut bad = request.clone();
        match case {
            0 => bad["scope"]["circuitDigest"] = serde_json::json!(vec![0; 32]),
            1 => bad["proofs"] = serde_json::json!([]),
            2 => bad["proofs"] = serde_json::json!(vec![bad["proofs"][0].clone(); 66]),
            3 => bad["srsG1"] = serde_json::json!("00"),
            4 => bad["srsG2"] = serde_json::json!("00"),
            5 => bad["proofs"][0]["publicInputs"] = serde_json::json!([]),
            6 => bad["proofs"][0]["publicInputs"] = serde_json::json!(vec![[255; 32]]),
            7 => bad["proofs"][0]["proof"] = serde_json::json!(""),
            8 => bad["proofs"][0]["proof"] = serde_json::json!("0g"),
            9 => bad["proofs"][0]["proof"] = serde_json::json!("00"),
            10 => bad["verificationKey"] = serde_json::json!("00"),
            11 => bad["scope"]["verifyingKeyDigest"] = serde_json::json!(vec![0; 32]),
            _ => bad["unexpected"] = serde_json::json!(true),
        }
        refused(&serde_json::to_vec(&bad).unwrap(), Some("256"));
    }
}
