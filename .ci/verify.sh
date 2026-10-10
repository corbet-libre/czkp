#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"
python3 -B .ci/test-native-sdk.py
python3 -B .ci/check-native-sdk.py

# dependency-policy gate (ci.yml dependency-policy job).
python3 .github/check-first-party.py
# check gate (ci.yml check job). The resolve job's npm/cargo update is
# intentionally not preserved: verify runs against the committed snapshot.
rustc --version
cargo fmt --check || { cargo fmt; git diff > formatting.patch; exit 1; }
cargo check --locked --lib --no-default-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --all-features --bin czkp-bb-worker
czkp_target_dir="${CARGO_TARGET_DIR:-target}"
czkp_worker="$(realpath "$czkp_target_dir/debug/czkp-bb-worker")"
set +e
env -i CZKP_NATIVE_MEMORY_MIB=256 "$czkp_worker" </dev/null
czkp_worker_status=$?
set -e
test "$czkp_worker_status" -eq 1
mkdir -p fixture-source
tar -xf fixture-source.tar -C fixture-source
cp fixture-package-lock.json fixture-source/package-lock.json
npm ci --ignore-scripts --no-audit --no-fund --prefix fixture-source
(cd fixture-source && node .ci/check-fixture-suite.ts && node tests/real-proof.mjs && node .ci/native-fixture-inputs.ts)
export CZKP_FIXTURE_SOURCE="$PWD/fixture-source"
cargo test --locked --all-features
# Native process/FFI features cannot execute in Wasm. Keep every portable core
# vector on the actual Wasm target; native worker vectors execute above.
wasm-pack test --node --features schema
node --test tests/abi.test.mjs

# coverage gate (ci.yml coverage job, nightly branch instrumentation).
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
)
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
