//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/internal` stays put (the library compiles it via `#[path]`).
mod common;
mod compact;
mod encoding;
mod native_proofs;
mod native_worker;
mod record;
mod rulebook;
mod standing;
mod voucher;
