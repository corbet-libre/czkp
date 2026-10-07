#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
# On Crow this original URL resolves only through the verified main-observed
# source closure. On hosted CI resolve archives it once for all later jobs.
if [[ "${1:-}" == acquire ]]; then
  test ! -e fixture-source
  git clone --single-branch --branch main https://git.corbet.ch/corbet-libs/cblc.git fixture-source
  git -C fixture-source rev-parse HEAD > fixture-source.txt
  git -C fixture-source archive HEAD > fixture-source.tar
  sha256sum fixture-source.tar fixture-source/package-lock.json > fixture-source.sha256
  exit 0
fi
if [[ ! -d fixture-source ]]; then
  mkdir fixture-source
  tar -xf fixture-source.tar -C fixture-source
fi
npm ci --ignore-scripts --no-audit --no-fund
(cd fixture-source && npm ci --ignore-scripts --no-audit --no-fund && node tests/real-proof.mjs)

CVFY_FIXTURE_SOURCE="$PWD/fixture-source" node tests/suite.test.mjs
