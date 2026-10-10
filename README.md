# czkp

Canonical BN254 field and base64url encodings, SHA-256 through RustCrypto, and strict Ed25519 verification through dalek. No proof system, secrets, state or policy is implemented here. `ProofScope` identifies a pinned circuit and verification key. Existing protocol domains remain unchanged.

Survey (2026-09-30): [RustCrypto sha2](https://crates.io/crates/sha2) and [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) match the existing wire format and remain dependencies. [Noir](https://github.com/noir-lang/noir) and [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg) remain the proof system; the process verifier is in cvfy and policy circuits in cblc. Bulletproofs was considered but would replace the existing relation and protocol without migration evidence.

CI runs stable Rust formatting, clippy with warnings denied, and tests against the retained dependency graph. No workstation builds. See [CONTRACT](docs/CONTRACT.md).

Copyright 2026 Julian Y. Richard Corbet. LGPL-3.0-only WITH LGPL-3.0-linking-exception; see [LICENSE.md](LICENSE.md).

The separate JavaScript client/prover bridge exports `/verify` and `/prove` over
Barretenberg and Noir peer dependencies. These exports remain available to holder
consumers such as cwlt; they are excluded from the Rust package. cblc/cvfy use
them only for test fixture generation and cross-checks, never in their production
server verification path. The verifier accepts public statements
and an application-supplied public-input encoder; the prover is holder-only and
consumes witnesses transiently. The embedding authenticates artifact snapshots.
No application account policy or persistent state lives in these adapters.

The `abi` entry encodes witnesses and public inputs from an authenticated Noir
ABI, including nested structures. It rejects noncanonical fields, overflows,
unsafe integers and extra struct members. Witness objects stay private.
The prover can explicitly select upstream `Wasm` or `NativeUnixSocket`; explicit
selection never silently falls back. Browser callers always use Wasm workers.
This retained bridge does not introduce a frontend into the native server libraries.

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.

## Native verification worker

The `native-worker` feature builds `czkp-bb-worker` and exposes
`czkp::native::run_worker`. It uses maintained `barretenberg-rs` major5 and the
matching authenticated upstream static library; `BB_LIB_DIR` must be provisioned
explicitly before building to avoid upstream build-script downloads. CI checks
the retained SDK version against `.ci/native-sdk.json`. Updating that artifact
identity requires proof-format qualification, not an exact manifest version pin.

A fresh isolated process initializes the supplied compressed 4 MiB G1 chunk and
128-byte G2 snapshot through upstream `SrsInitSrs`, then verifies an ordered
batch using the official `noir-recursive` API. Upstream authenticates the setup
chunk and G2 point; the host must authenticate complete artifact provenance.
No stock `bb` CLI is used because its startup installs filesystem/network CRS
handling. The worker reads no artifact files or network and writes only a
minimal verdict to stdout. All request bytes remain in RAM.

Owned Rust forbids unsafe code. Upstream FFI/C++ cryptography remains an external
dependency in this isolated executable. The host sets explicit memory/thread
limits, discards stderr, bounds stdout, and kills/reaps on one whole-batch
deadline; `cvfy::NativeVerifier` supplies that boundary. A worker executable is
trusted host configuration, never selected by a proof. Default and Wasm core
builds do not enable the native SDK.

Primary API: [official Rust SDK](https://github.com/AztecProtocol/aztec-packages/tree/v5.2.1/barretenberg/rust/barretenberg-rs),
[memory SRS initialization](https://github.com/AztecProtocol/aztec-packages/blob/v5.2.1/barretenberg/cpp/src/barretenberg/bbapi/bbapi_srs.cpp).
