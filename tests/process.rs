#![cfg(all(feature = "process", not(target_arch = "wasm32")))]
//! Integration tests for the public contract.
use czkp::process::{ProcessVerificationFailure, ProcessVerifier, ProcessVerifierConfig};
use czkp::{Error, ProofScope};
use std::{fs, time::Duration};
fn node() -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|path| path.join("node"))
        .find(|path| path.is_absolute() && path.is_file())
        .expect("CI must install Node for real process tests")
}
#[test]
fn reject_bad_configuration_and_failed_worker() {
    let dir = tempfile::tempdir().unwrap();
    let config = ProcessVerifierConfig {
        node: node(),
        script: dir.path().join("worker.mjs"),
        artifact_config: dir.path().join("manifest.json"),
        scope: ProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        },
        timeout: Duration::from_millis(500),
        maximum_parallel: 1,
        max_proof_bytes: 100,
        node_heap_megabytes: 64,
    };
    fs::write(
        &config.script,
        "process.stdin.resume(); setInterval(()=>{},1000)",
    )
    .unwrap();
    let verifier = ProcessVerifier::new(config.clone()).unwrap();
    // serde_json cannot encode array-valued map keys. Refuse serialization
    // failure without panicking or consuming the only worker permit.
    let invalid_statement = std::collections::BTreeMap::from([(vec![1, 2], 1)]);
    assert_eq!(
        verifier.verify(&invalid_statement, &[1]),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        verifier.verify_detailed(&invalid_statement, &[1]),
        Err(ProcessVerificationFailure::InvalidInput)
    );
    assert_eq!(
        verifier.verify(&"x".repeat(128 * 1024), &[1]),
        Err(Error::InvalidInput)
    );
    assert_eq!(verifier.verify(&1, &[1]), Err(Error::CryptoProvider));
    fs::write(
        &config.script,
        "process.stdin.resume(); process.stdout.write('x'.repeat(5000))",
    )
    .unwrap();
    assert_eq!(verifier.verify(&1, &[1]), Err(Error::CryptoProvider));
    assert_eq!(verifier.verify(&1, &[]), Err(Error::InvalidInput));
    for field in 0..13 {
        let mut bad = config.clone();
        match field {
            0 => bad.node = "node".into(),
            1 => bad.script = "worker.mjs".into(),
            2 => bad.artifact_config = "manifest.json".into(),
            3 => bad.scope.circuit_digest = [0; 32],
            4 => bad.scope.verifying_key_digest = [0; 32],
            5 => bad.timeout = Duration::ZERO,
            6 => bad.timeout = Duration::from_secs(301),
            7 => bad.maximum_parallel = 0,
            8 => bad.maximum_parallel = 65,
            9 => bad.max_proof_bytes = 0,
            10 => bad.max_proof_bytes = 4 * 1024 * 1024 + 1,
            11 => bad.node_heap_megabytes = 63,
            _ => bad.node_heap_megabytes = 4097,
        }
        assert!(ProcessVerifier::new(bad).is_err());
    }
    for output in [
        "",
        "{}",
        "null",
        "{\"verified\":false,\"proofScope\":{\"circuitDigest\":[],\"verifyingKeyDigest\":[]}}",
    ] {
        fs::write(
            &config.script,
            format!("process.stdin.resume(); process.stdout.write({output:?});"),
        )
        .unwrap();
        assert_eq!(verifier.verify(&1, &[1]), Err(Error::CryptoProvider));
    }
    // A nonexistent executable is a transport failure, never proof acceptance.
    let mut unavailable = config;
    unavailable.node = dir.path().join("absent-node");
    assert_eq!(
        ProcessVerifier::new(unavailable).unwrap().verify(&1, &[1]),
        Err(Error::CryptoProvider)
    );
}

#[test]
fn transport_delivers_a_bounded_multi_proof_bundle_without_accepting_it() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = dir.path().join("size.json");
    let config = ProcessVerifierConfig {
        node: node(),
        script: dir.path().join("worker.mjs"),
        artifact_config: receipt.clone(),
        scope: ProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        },
        timeout: Duration::from_secs(5),
        maximum_parallel: 1,
        max_proof_bytes: 4 * 1024 * 1024,
        node_heap_megabytes: 64,
    };
    // This worker records only the received byte count and always refuses proof
    // acceptance. The test checks pipe framing/capacity, not cryptography.
    fs::write(&config.script, "import {writeFileSync} from 'node:fs'; const chunks=[]; for await(const c of process.stdin) chunks.push(c); const r=JSON.parse(Buffer.concat(chunks)); writeFileSync(process.argv[2], String(r.proof.length/2)); process.exitCode=1;").unwrap();
    let verifier = ProcessVerifier::new(config.clone()).unwrap();
    assert_eq!(
        verifier.verify(&1, &vec![5; 2 * 1024 * 1024]),
        Err(Error::CryptoProvider)
    );
    assert_eq!(
        fs::read_to_string(&receipt).unwrap(),
        (2 * 1024 * 1024).to_string()
    );
    assert_eq!(
        verifier.verify(&1, &vec![5; 4 * 1024 * 1024 + 1]),
        Err(Error::InvalidInput)
    );
    // Closing the real read end while a large write is pending must fail and
    // release capacity; no fabricated successful worker response is involved.
    fs::write(&config.script, "process.exit(1);").unwrap();
    assert_eq!(
        verifier.verify(&1, &vec![5; 2 * 1024 * 1024]),
        Err(Error::CryptoProvider)
    );
    fs::write(
        &config.script,
        "process.stdin.resume(); process.exitCode=1;",
    )
    .unwrap();
    assert_eq!(verifier.verify(&1, &[1]), Err(Error::CryptoProvider));
    let mut oversized = config;
    oversized.max_proof_bytes += 1;
    assert!(ProcessVerifier::new(oversized).is_err());
}

#[test]
fn bounded_process_capacity_is_shared_and_released_after_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("started");
    let config = ProcessVerifierConfig {
        node: node(),
        script: dir.path().join("worker.mjs"),
        artifact_config: marker.clone(),
        scope: ProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        },
        timeout: Duration::from_secs(2),
        maximum_parallel: 1,
        max_proof_bytes: 100,
        node_heap_megabytes: 64,
    };
    // An actual hung process tests admission and cleanup. It cannot accept a
    // proof and supplies no replacement accounting or cryptographic behavior.
    fs::write(
        &config.script,
        "import {writeFileSync} from 'node:fs'; process.stdin.resume(); writeFileSync(process.argv[2], 'started'); setInterval(()=>{},1000);",
    )
    .unwrap();
    let verifier = ProcessVerifier::new(config.clone()).unwrap();
    let busy = verifier.clone();
    let worker = std::thread::spawn(move || busy.verify_detailed(&1, &[1]));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(verifier.verify(&1, &[1]), Err(Error::Capacity));
    assert_eq!(
        verifier.verify_detailed(&1, &[1]),
        Err(ProcessVerificationFailure::Capacity)
    );
    assert_eq!(
        worker.join().unwrap(),
        Err(ProcessVerificationFailure::Timeout)
    );
    fs::write(
        &config.script,
        "process.stdin.resume(); process.exitCode=1;",
    )
    .unwrap();
    assert_eq!(verifier.verify(&1, &[1]), Err(Error::CryptoProvider));
}

#[test]
fn valid_json_cannot_turn_refusal_or_foreign_scope_into_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let config = ProcessVerifierConfig {
        node: node(),
        script: dir.path().join("worker.mjs"),
        artifact_config: dir.path().join("config.json"),
        scope: ProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        },
        timeout: Duration::from_secs(5),
        maximum_parallel: 1,
        max_proof_bytes: 100,
        node_heap_megabytes: 64,
    };
    let verifier = ProcessVerifier::new(config.clone()).unwrap();
    let mut foreign = config.scope.clone();
    foreign.circuit_digest[0] ^= 1;
    for (verified, scope) in [(false, config.scope.clone()), (true, foreign)] {
        let verdict = serde_json::json!({"verified": verified, "proofScope": scope});
        fs::write(
            &config.script,
            format!(
                "process.stdin.resume(); process.stdout.write({:?});",
                verdict.to_string()
            ),
        )
        .unwrap();
        assert_eq!(verifier.verify(&1, &[1]), Err(Error::CryptoProvider));
        assert_eq!(
            verifier.verify_detailed(&1, &[1]),
            Err(if verified {
                ProcessVerificationFailure::ScopeMismatch
            } else {
                ProcessVerificationFailure::ProofRejected
            })
        );
    }
}

#[test]
fn per_call_failure_distinguishes_lifecycle_from_bounded_verdict_refusal() {
    use ProcessVerificationFailure as Failure;
    let dir = tempfile::tempdir().unwrap();
    let config = ProcessVerifierConfig {
        node: node(),
        script: dir.path().join("worker.mjs"),
        artifact_config: dir.path().join("config.json"),
        scope: ProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        },
        timeout: Duration::from_secs(5),
        maximum_parallel: 1,
        max_proof_bytes: 1024 * 1024,
        node_heap_megabytes: 64,
    };
    let verifier = ProcessVerifier::new(config.clone()).unwrap();
    let clone = verifier.clone();
    // Every actual child here refuses. No transport stub fabricates accepted
    // crypto. Reuse both handles to detect stale per-call state or leaked permits.
    for (script, failure, category) in [
        (
            "process.stdin.resume(); process.stderr.write('PRIVATE-WORKER-MARKER'); process.exitCode=23;",
            Failure::WorkerExit,
            "worker_exit",
        ),
        (
            "process.stdin.resume(); process.stdout.write('PRIVATE-OUTPUT-MARKER');",
            Failure::VerdictDecode,
            "verdict_decode",
        ),
        (
            "process.stdin.resume(); process.stdout.write('x'.repeat(5000));",
            Failure::OutputTooLarge,
            "output_too_large",
        ),
    ] {
        fs::write(&config.script, script).unwrap();
        let actual = verifier.verify_detailed(&"PRIVATE-REQUEST-MARKER", &[1]);
        assert_eq!(actual, Err(failure));
        assert_eq!(actual.unwrap_err().category(), category);
        assert_eq!(clone.verify(&1, &[1]), Err(failure.error()));
    }
    // An abnormal termination is distinct from the worker's explicit exit.
    #[cfg(unix)]
    {
        fs::write(
            &config.script,
            "process.stdin.resume(); process.stdin.on('end',()=>process.kill(process.pid,'SIGKILL'));",
        )
        .unwrap();
        assert_eq!(
            verifier.verify_detailed(&1, &[1]),
            Err(Failure::WorkerTerminated)
        );
        assert_eq!(clone.verify(&1, &[1]), Err(Error::CryptoProvider));
    }
    // A short-lived failed worker can also break the pending request pipe.
    // Preserve the lifecycle cause rather than reporting the secondary write.
    fs::write(&config.script, "process.exit(23);").unwrap();
    assert_eq!(
        verifier.verify_detailed(&1, &vec![1; config.max_proof_bytes]),
        Err(Failure::WorkerExit)
    );
    fs::write(&config.script, "process.exit(0);").unwrap();
    assert_eq!(
        verifier.verify_detailed(&1, &vec![1; config.max_proof_bytes]),
        Err(Failure::Write)
    );
    assert_eq!(
        clone.verify(&1, &vec![1; config.max_proof_bytes]),
        Err(Error::CryptoProvider)
    );
    assert_eq!(
        verifier.verify_detailed(&1, &[]),
        Err(Failure::InvalidInput)
    );
    assert_eq!(
        verifier.verify_detailed(&"x".repeat(3 * 1024 * 1024), &[1]),
        Err(Failure::InvalidInput)
    );
    let mut unavailable = config;
    unavailable.node = dir.path().join("absent-node");
    let unavailable = ProcessVerifier::new(unavailable).unwrap();
    assert_eq!(unavailable.verify_detailed(&1, &[1]), Err(Failure::Spawn));
    assert_eq!(unavailable.verify(&1, &[1]), Err(Error::CryptoProvider));
}
