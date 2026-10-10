//! Single-use native verifier. All cryptography belongs to upstream Barretenberg.
#![forbid(unsafe_code)]

fn main() {
    if czkp::native::run_worker().is_err() {
        std::process::exit(1);
    }
}
