# czkp agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p czkp` — native suite, green
  (lib `12`, record `11`, voucher `12`, rulebook `7`, standing `6`,
  compact + encoding `2` each; native worker/proof binaries `0`
  without `--all-features`), exit 0
- `~/agents/scratch/cbuild <lane> fmt -p czkp -- --check` — must be clean
- Full gate (clippy `--locked --all-targets --all-features`, native
  worker with provisioned `BB_LIB_DIR`, fixture suite, wasm-pack,
  nightly 100% coverage) runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Owned Rust forbids `unsafe`; FFI/C++ stays an external isolated executable
  -> `src/lib.rs:3` + clippy gate in `.ci/verify.sh`
- Strict Ed25519: small-order and non-curve-point keys refused
  -> `tests/internal/account.rs::an_operator_key_that_is_not_a_curve_point_is_refused`
- Canonical encodings reject noncanonical fields, overflows, extra members
  -> `tests/encoding.rs::signatures_and_canonical_encodings`, `tests/abi.test.mjs`
- No silent backend fallback; Wasm/Native selection is explicit
  -> `tests/native_worker.rs::actual_worker_rejects_memory_configuration_and_oversized_input_before_eof`
- Worker is RAM-only, single-use, minimal verdict on stdout
  -> `tests/native_worker.rs::actual_worker_rejects_shape_fields_and_key_binding_without_native_crypto`
- Key binding and shape bounds checked before any native crypto
  -> `tests/native_worker.rs::actual_worker_rejects_shape_fields_and_key_binding_without_native_crypto`
- Only genuine upstream proofs verify; batch verifies all or nothing
  -> `tests/native_proofs.rs::genuine_account_batch_verifies_and_changed_inputs_or_setup_refuse`

Pointers: `src/lib.rs`, `src/native.rs`, `src/native/worker.rs`,
`docs/CONTRACT.md`, `docs/COVERAGE.md`, `.ci/native-sdk.json`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
LGPL-3.0-only WITH linking exception; no GPL/AGPL-only code; never publish to a registry.
