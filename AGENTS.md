# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Shared zero-knowledge core: encoding, hashes, prove and verify, separately selectable.
- Provides encoding, hashing and prove/verify plumbing to `cssr`, `cvfy` and `cwlt`.
- Holds no secrets and no state.
- No own proof system: the upstream system (for example Noir/Barretenberg) stays a dependency.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use Crow with the canonical Forgejo repository.
