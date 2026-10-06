#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS=2 CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc -Vv
sha256sum Cargo.lock
python3 .github/check-first-party.py --archive
case "${1:?selected check required}" in
  native|coverage)
    cargo fmt --check
    cargo clippy --locked --all-targets --all-features -- -D warnings
    bash .ci/fixture.sh acquire
    bash .ci/fixture.sh
    export CVFY_FIXTURE_SOURCE="$PWD/fixture-source"
    if [[ "$1" == native ]]; then
      cargo test --locked --all-features
    else
      cargo llvm-cov --locked --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json
      cargo llvm-cov report --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
      cargo llvm-cov report --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
      python3 .github/test-source-coverage.py
      python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
    fi
    ;;
  wasm)
    wasm-pack test --node --all-features
    node --test tests/abi.test.mjs
    ;;
  dependency-policy) cargo deny --locked check advisories licenses ;;
  resolve)
    cargo update
    python3 .github/check-first-party.py --archive
    date -u +%FT%TZ > resolver.txt
    rustc -Vv >> resolver.txt
    sha256sum Cargo.lock >> resolver.txt
    cat resolver.txt
    : "${CARGO_TARGET_DIR:?persistent artifact root required}"
    mkdir -p "$CARGO_TARGET_DIR/ci-receipts"
    receipt=$(mktemp -d "$CARGO_TARGET_DIR/ci-receipts/${CI_COMMIT_SHA:?}.XXXXXXXX")
    cp Cargo.lock resolver.txt "$receipt/"
    sha256sum "$receipt/Cargo.lock" "$receipt/resolver.txt"
    printf 'RESOLUTION_ARTIFACTS=%s\n' "$receipt"
    ;;
  *) exit 2 ;;
esac
sha256sum Cargo.lock
