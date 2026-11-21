#!/usr/bin/env bash
# The full gate, with no internet.
#
# Everything runs inside a throwaway namespace that has no network at all,
# so a test cannot pass by fetching anything, and the foundation is proven to
# work offline. Then railscheck confirms no safety test was skipped or removed.
# No sudo needed on kernels that allow unprivileged user namespaces.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${TMPDIR:-/tmp}/afw-rails"
mkdir -p "$out"

NFT="${AFW_NFT:-$(command -v nft || true)}"
if [[ -z "$NFT" ]]; then
  dir="${TMPDIR:-/tmp}/afw-lab-nft"
  if [[ ! -x "$dir/nft" ]]; then
    mkdir -p "$dir" && (cd "$dir" && apt-get download nftables libnftables1 >/dev/null && for f in *.deb; do dpkg -x "$f" root; done)
    lib="$(dirname "$(find "$dir/root" -name 'libnftables.so*' | head -1)")"
    printf '#!/bin/sh\nLD_LIBRARY_PATH="%s" exec "%s/root/usr/sbin/nft" "$@"\n' "$lib" "$dir" >"$dir/nft"
    chmod +x "$dir/nft"
  fi
  NFT="$dir/nft"
fi

# Build everything first, while the network is still there for dependencies.
go mod download
go build ./...
go test -c -tags lab -o "$out/lab.test" ./internal/daemon
go build -o "$out/railscheck" ./internal/tools/railscheck

export AFW_NFT="$NFT" GOPROXY=off GOFLAGS=-mod=mod
# RAILS_SUDO=1 uses sudo for the namespace, for hosts (such as CI runners)
# that do not allow unprivileged user namespaces.
enter=(unshare -rn)
if [[ "${RAILS_SUDO:-}" == 1 ]]; then
  enter=(sudo env "PATH=$PATH" "HOME=$HOME" "GOCACHE=$(go env GOCACHE)" "GOMODCACHE=$(go env GOMODCACHE)"
    "GOPROXY=off" "GOFLAGS=-mod=mod" "AFW_NFT=$NFT" unshare -n)
fi
"${enter[@]}" sh -c '
  set -e
  ip link set lo up
  if ip route get 1.1.1.1 >/dev/null 2>&1; then echo "refusing to run: the namespace has a route to the internet"; exit 1; fi
  go test -json ./... > "'"$out"'/unit.json" || true
  "'"$out"'/lab.test" -test.v=test2json -test.run TestLab > "'"$out"'/lab.raw" 2>&1 || true
'
if [[ "${RAILS_SUDO:-}" == 1 ]]; then
  sudo chown -R "$(id -u)" "$out" "$(go env GOCACHE)" "$(go env GOMODCACHE)"
fi
go tool test2json -p lab < "$out/lab.raw" > "$out/lab.json"
cat "$out/unit.json" "$out/lab.json" | "$out/railscheck" rails.txt
