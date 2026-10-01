# czkp

Canonical BN254 field and base64url encodings, SHA-256 through RustCrypto, and strict Ed25519 verification through dalek. No proof system, secrets, state or policy is implemented here. `ProofScope` identifies a pinned circuit and verification key. Existing protocol domains remain unchanged.

Survey (2026-09-30): [RustCrypto sha2](https://crates.io/crates/sha2) and [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) match the existing wire format and remain dependencies. [Noir](https://github.com/noir-lang/noir) and [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg) remain the proof system; the process verifier is in cvfy and policy circuits in cblc. Bulletproofs was considered but would replace the existing relation and protocol without migration evidence.

GitHub Actions runs stable Rust formatting, clippy with warnings denied, and tests. No workstation builds. See [CONTRACT](docs/CONTRACT.md).

Copyright 2026 Julian Y. Richard Corbet. LGPL-3.0-only WITH LGPL-3.0-linking-exception; see [LICENSE.md](LICENSE.md).

The JavaScript package separately exports `/verify` and `/prove` over pinned
Barretenberg and Noir peer dependencies. The verifier accepts public statements
and an application-supplied public-input encoder; the prover is holder-only and
consumes witnesses transiently. The embedding authenticates artifact snapshots.
No application account policy or persistent state lives in these adapters.

The `abi` entry encodes witnesses and public inputs from an authenticated Noir
ABI, including nested structures. It rejects noncanonical fields, overflows,
unsafe integers and extra struct members. Witness objects stay private.
The prover can explicitly select upstream `Wasm` or `NativeUnixSocket`; explicit
selection never silently falls back. Browser callers always use Wasm workers.

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
