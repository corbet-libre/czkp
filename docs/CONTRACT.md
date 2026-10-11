# czkp contract

Canonical BN254 field and base64url encodings, SHA-256 through RustCrypto, and strict Ed25519 verification through dalek. No proof system, secrets, state or policy is implemented here. `ProofScope` identifies a pinned circuit and verification key. Existing protocol domains remain unchanged.

Survey (2026-09-30): [RustCrypto sha2](https://crates.io/crates/sha2) and [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) match the existing wire format and remain dependencies. [Noir](https://github.com/noir-lang/noir) and [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg) remain the proof system; the process verifier is in cvfy and policy circuits in cblc. Bulletproofs was considered but would replace the existing relation and protocol without migration evidence.

Source extraction: maintained adapters from cfrm; substantive accounting policy remains in cblc. This package is not independently a complete private-account relation.

The separate JavaScript client/prover bridge exports `/verify` and `/prove` over
Barretenberg and Noir peer dependencies. It remains available to holder consumers
such as cwlt and is excluded from the Rust package. Its use by cblc/cvfy is
test-only fixture generation and cross-checking; their production server path
uses the safe Rust native adapter and isolated worker described in the
[README](../README.md#native-verification-worker). The verifier accepts public statements
and an application-supplied public-input encoder; the prover is holder-only and
consumes witnesses transiently. The embedding authenticates artifact snapshots.
No application account policy or persistent state lives in these adapters.

There is one prover version across server, wallet and browser: Barretenberg 5.2.1
with Noir 1.0.0-beta.26. Fixture generation, the Rust production manifest (which
authenticates its matching native library at build time) and the JS packages'
peer ranges all name it; the retired 5.0.0 key group is refused everywhere.

Optional `schema` derives the existing `ProofScope` wire schema with Utoipa,
matching Door's owner-type registry. This describes shape only; it grants no
trust in member-supplied circuit/key digests. No parallel scope DTO is defined.
The optional `schema` feature also exposes maintained Schemars `JsonSchema`
for the same canonical `ProofScope` type. This lets containing owner types derive
Serde-compatible tagged-enum schemas without duplicating the scope fields.
Native and actual Wasm vectors check the fixed 32-byte bounds.
