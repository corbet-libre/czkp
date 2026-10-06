//! Bounded native transport for a configured maintained proof verifier.
use crate::{Error, ProofScope};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
/// Trusted host configuration. Use absolute paths to a shipped verification
/// adapter and authenticated policy artifacts, never paths from peer requests.
#[derive(Clone, Debug)]
pub struct ProcessVerifierConfig {
    pub node: PathBuf,
    pub script: PathBuf,
    pub artifact_config: PathBuf,
    pub scope: ProofScope,
    pub timeout: Duration,
    pub maximum_parallel: usize,
    pub max_proof_bytes: usize,
    pub node_heap_megabytes: usize,
}

#[derive(Clone)]
pub struct ProcessVerifier {
    config: Arc<ProcessVerifierConfig>,
    active: Arc<AtomicUsize>,
}

/// Value-free failure from one verification attempt. This never contains a
/// request, worker output, stderr, path, OS error message or exit-code value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessVerificationFailure {
    /// The proof or serialized request exceeds the configured input contract.
    InvalidInput,
    /// All configured worker permits are in use.
    Capacity,
    /// The configured executable could not be started.
    Spawn,
    /// A configured child pipe was unavailable.
    Pipe,
    /// The child exceeded its configured deadline; kill and reap were attempted.
    Timeout,
    /// Observing the child status failed; cleanup was attempted.
    Wait,
    /// The child returned an unsuccessful exit code.
    WorkerExit,
    /// The child terminated without an exit code, for example by a signal.
    WorkerTerminated,
    /// Writing the complete request failed.
    Write,
    /// Reading the bounded response failed.
    Read,
    /// The response exceeded its fixed byte limit.
    OutputTooLarge,
    /// The response was not an exact verdict envelope.
    VerdictDecode,
    /// The worker returned an explicit negative verdict.
    ProofRejected,
    /// The verdict did not name the configured proof scope.
    ScopeMismatch,
}

impl ProcessVerificationFailure {
    /// The original public error, preserving the ordinary verifier contract.
    pub fn error(self) -> Error {
        match self {
            Self::InvalidInput => Error::InvalidInput,
            Self::Capacity => Error::Capacity,
            _ => Error::CryptoProvider,
        }
    }

    /// A fixed label suitable for a bounded diagnostic, without request values.
    pub fn category(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::Capacity => "capacity",
            Self::Spawn => "spawn",
            Self::Pipe => "pipe",
            Self::Timeout => "timeout",
            Self::Wait => "wait",
            Self::WorkerExit => "worker_exit",
            Self::WorkerTerminated => "worker_terminated",
            Self::Write => "write",
            Self::Read => "read",
            Self::OutputTooLarge => "output_too_large",
            Self::VerdictDecode => "verdict_decode",
            Self::ProofRejected => "proof_rejected",
            Self::ScopeMismatch => "scope_mismatch",
        }
    }
}

impl ProcessVerifier {
    pub fn new(config: ProcessVerifierConfig) -> Result<Self, Error> {
        if !config.node.is_absolute()
            || !config.script.is_absolute()
            || !config.artifact_config.is_absolute()
            || config.scope.circuit_digest == [0; 32]
            || config.scope.verifying_key_digest == [0; 32]
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(300)
            || !(1..=64).contains(&config.maximum_parallel)
            || !(1..=4 * 1024 * 1024).contains(&config.max_proof_bytes)
            || !(64..=4096).contains(&config.node_heap_megabytes)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            config: Arc::new(config),
            active: Arc::new(AtomicUsize::new(0)),
        })
    }
}

struct ActivePermit(Arc<AtomicUsize>);
impl Drop for ActivePermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ProcessVerifier {
    pub fn scope(&self) -> ProofScope {
        self.config.scope.clone()
    }

    pub fn verify(&self, statement: &impl Serialize, proof: &[u8]) -> Result<(), Error> {
        self.verify_detailed(statement, proof)
            .map_err(ProcessVerificationFailure::error)
    }

    /// Verify through the same worker and acceptance checks, retaining only a
    /// value-free failure category for this call. No global diagnostic is stored.
    pub fn verify_detailed(
        &self,
        statement: &impl Serialize,
        proof: &[u8],
    ) -> Result<(), ProcessVerificationFailure> {
        if proof.is_empty() || proof.len() > self.config.max_proof_bytes {
            return Err(ProcessVerificationFailure::InvalidInput);
        }
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.config.maximum_parallel).then_some(n + 1)
            })
            .map_err(|_| ProcessVerificationFailure::Capacity)?;
        let _permit = ActivePermit(self.active.clone());
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a, S> {
            statement: &'a S,
            proof: String,
            proof_scope: &'a ProofScope,
        }
        // The fixed std slice writer refuses oversized public statements before
        // an unbounded allocation or process spawn. Proof hex has an exact 2x
        // expansion; 64 KiB covers the public statement and envelope metadata.
        let limit = self.config.max_proof_bytes * 2 + 64 * 1024;
        let mut bytes = vec![0; limit];
        let mut remaining = bytes.as_mut_slice();
        serde_json::to_writer(
            &mut remaining,
            &Request {
                statement,
                proof: data_encoding::HEXLOWER.encode(proof),
                proof_scope: &self.config.scope,
            },
        )
        .or(Err(ProcessVerificationFailure::InvalidInput))?;
        let written = limit - remaining.len();
        bytes.truncate(written);
        self.verify_bytes(bytes)
    }

    fn verify_bytes(&self, bytes: Vec<u8>) -> Result<(), ProcessVerificationFailure> {
        let mut child = Command::new(&self.config.node)
            .arg(format!(
                "--max-old-space-size={}",
                self.config.node_heap_megabytes
            ))
            .arg(&self.config.script)
            .arg(&self.config.artifact_config)
            .env_remove("NODE_OPTIONS")
            .env_remove("NODE_PATH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .or(Err(ProcessVerificationFailure::Spawn))?;
        // Dedicated bounded readers avoid pipe deadlock. Kill and reap on every
        // deadline/error before joining them. The shipped worker spawns no children.
        let mut stdin = child.stdin.take().ok_or(ProcessVerificationFailure::Pipe)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessVerificationFailure::Pipe)?;
        let writer = thread::spawn(move || stdin.write_all(&bytes));
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(4097).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + self.config.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                result => {
                    let failure = if result.is_err() {
                        ProcessVerificationFailure::Wait
                    } else {
                        ProcessVerificationFailure::Timeout
                    };
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(failure);
                }
            }
        };
        let wrote = writer.join().ok().is_some_and(|v| v.is_ok());
        let output = reader.join();
        // Join both pipes before returning. Child lifecycle failures take
        // precedence over a broken pipe caused by that same child failure.
        let status = status?;
        if !status.success() {
            return Err(if status.code().is_some() {
                ProcessVerificationFailure::WorkerExit
            } else {
                ProcessVerificationFailure::WorkerTerminated
            });
        }
        if !wrote {
            return Err(ProcessVerificationFailure::Write);
        }
        let output = output
            .or(Err(ProcessVerificationFailure::Read))?
            .or(Err(ProcessVerificationFailure::Read))?;
        if output.len() > 4096 {
            return Err(ProcessVerificationFailure::OutputTooLarge);
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Verdict {
            verified: bool,
            proof_scope: ProofScope,
        }
        let verdict: Verdict =
            serde_json::from_slice(&output).or(Err(ProcessVerificationFailure::VerdictDecode))?;
        if !verdict.verified {
            return Err(ProcessVerificationFailure::ProofRejected);
        }
        if verdict.proof_scope != self.config.scope {
            return Err(ProcessVerificationFailure::ScopeMismatch);
        }
        Ok(())
    }
}
