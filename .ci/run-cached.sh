#!/usr/bin/env bash
# Execute the manifest's selected checks with content-keyed result reuse.
set -euo pipefail
exec 2>&1
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
: "${CI_REPOSITORY_URL:?Missing canonical repository identity}"
: "${CHECKS:?Missing declared check selection}"
if [ "$CHECKS" != "verify,advisories" ] && [ "$CHECKS" != "resolve-dependencies" ] && [ "$CHECKS" != "resolve-npm" ]; then
  echo "CHECKS must be verify,advisories, resolve-dependencies or resolve-npm, got: $CHECKS" >&2
  exit 2
fi
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
namespace=$(printf '%s' "$CI_REPOSITORY_URL" | sha256sum | cut -c1-24)
state="$cache_root/ccid-cached/$namespace"
toolchains=${CI_TOOLCHAIN_ROOT:-$cache_root/ccid-cached/toolchains}
[[ $toolchains = /* ]] || { echo 'CI_TOOLCHAIN_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$state" "$toolchains"
exec 9>"$state/lock"
flock -w "${CI_TIMEOUT:-2700}" 9
mkdir -p "$state/moon-cache/hashes" "$state/moon-cache/outputs" "$state/moon-home"
mkdir -p .moon/cache
# Tool installation is an explicit part of this job, in persistent CI storage.
# Node 24 matches all three ci.yml setup-node steps; npm ships with nix nodejs
# and serves the fixture `npm ci` + proofs generation (see verify.sh).
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436?narHash=sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#nodejs" "$tool_source#python3" "$tool_source#cargo-deny" "$tool_source#cargo-llvm-cov" "$tool_source#wasm-pack")
for path in $tool_paths; do PATH="$path/bin:$PATH"; done
export PROTO_HOME="$toolchains/proto"
export MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
# Shared-first toolchain lock: jobs share a provisioned toolchain and take
# exclusive only to provision missing pieces. Same lock file, so old
# whole-job-exclusive runners interoperate (they just serialize).
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
cargo_bin=$(rustup which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
export ARTIFACT_ROOT="${ARTIFACT_ROOT:-$state/release-artifacts}"
mkdir -p "$ARTIFACT_ROOT"
"$CCID_BIN" render --repo "$PWD" --check
proto --version
moon --version
rustc -vV
cargo --version
node --version
npm --version
python3 --version
cargo-deny --version
rustup run nightly rustc -vV
rustup run nightly cargo llvm-cov --version
if [ "$CHECKS" = "resolve-dependencies" ] || [ "$CHECKS" = "resolve-npm" ]; then
  exec "$CCID_BIN" check --repo "$PWD" --check "$CHECKS"
fi
echo 'czkp:stage=fixture-resolve'
# Fetch current fixture source and retain its committed historical-suite lock.
# npm ci below must consume that exact lock: an npm update would silently
# replace the proof-format compatibility vector with a different SDK suite.
rm -rf fixture-source fixture-source.tar fixture-package-lock.json fixture-source.txt
git clone --depth 1 https://git.corbet.ch/corbet-fsl/cblc.git fixture-source
git -C fixture-source rev-parse HEAD > fixture-source.txt
(cd fixture-source && git archive HEAD > ../fixture-source.tar)
cp fixture-source/package-lock.json fixture-package-lock.json
export CZKP_FIXTURE_HEAD="$(cat fixture-source.txt)"
export CZKP_FIXTURE_LOCK_SHA="$(sha256sum fixture-package-lock.json | cut -d ' ' -f1)"
retain_coverage() {
  local status=$?
  trap - EXIT
  for report in coverage.json coverage.lcov coverage.txt fixture-source.txt fixture-package-lock.json; do
    if [[ -f "$report" && ! -L "$report" ]]; then
      mkdir -p "$ARTIFACT_ROOT/$CI_COMMIT_SHA" || status=1
      cp -- "$report" "$ARTIFACT_ROOT/$CI_COMMIT_SHA/$report" || status=1
    fi
  done
  exit "$status"
}
trap retain_coverage EXIT
nix-shell .ci/check-shell.nix --run 'export PATH="$(dirname "$CCID_BIN"):$PATH"; set -e; "$CCID_BIN" cached --repo "$PWD" --check verify; exec "$CCID_BIN" check --repo "$PWD" --check advisories'
