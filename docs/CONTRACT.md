# czkp contract

Canonical BN254 field and base64url encodings, SHA-256 through RustCrypto, and strict Ed25519 verification through dalek. No proof system, secrets, state or policy is implemented here. `ProofScope` identifies a pinned circuit and verification key. Existing protocol domains remain unchanged.

Survey (2026-09-30): [RustCrypto sha2](https://crates.io/crates/sha2) and [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) match the existing wire format and remain dependencies. [Noir](https://github.com/noir-lang/noir) and [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg) remain the proof system; the process verifier is in cvfy and policy circuits in cblc. Bulletproofs was considered but would replace the existing relation and protocol without migration evidence.

Source extraction: maintained adapters from cfrm; substantive accounting policy remains in cblc. This package is not independently a complete private-account relation.

The JavaScript package separately exports `/verify` and `/prove` over pinned
Barretenberg and Noir peer dependencies. The verifier accepts public statements
and an application-supplied public-input encoder; the prover is holder-only and
consumes witnesses transiently. The embedding authenticates artifact snapshots.
No application account policy or persistent state lives in these adapters.

Optional `schema` derives the existing `ProofScope` wire schema with Utoipa,
matching Door's owner-type registry. This describes shape only; it grants no
trust in member-supplied circuit/key digests. No parallel scope DTO is defined.
The optional `schema` feature also exposes maintained Schemars `JsonSchema`
for the same canonical `ProofScope` type. This lets containing owner types derive
Serde-compatible tagged-enum schemas without duplicating the scope fields.
Native and actual Wasm vectors check the fixed 32-byte bounds.
