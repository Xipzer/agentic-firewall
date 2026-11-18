#!/usr/bin/env bash
# Runs the kernel lab tests in a throwaway user + network namespace.
# No sudo needed on kernels that allow unprivileged user namespaces.
# Nothing touches the host's real network or firewall.
set -euo pipefail
cd "$(dirname "$0")/.."
NFT="${AFW_NFT:-$(command -v nft || true)}"
if [[ -z "$NFT" ]]; then
  # Fetch nft without installing it system-wide (Debian/Ubuntu).
  dir="${TMPDIR:-/tmp}/afw-lab-nft"
  mkdir -p "$dir" && (cd "$dir" && apt-get download nftables libnftables1 >/dev/null && for f in *.deb; do dpkg -x "$f" root; done)
  lib="$(dirname "$(find "$dir/root" -name 'libnftables.so*' | head -1)")"
  cat >"$dir/nft" <<SH
#!/bin/sh
LD_LIBRARY_PATH="$lib" exec "$dir/root/usr/sbin/nft" "\$@"
SH
  chmod +x "$dir/nft"
  NFT="$dir/nft"
fi
export AFW_NFT="$NFT"
go test -c -tags lab -o /tmp/afw-lab.test ./internal/daemon
exec unshare -rn /tmp/afw-lab.test -test.v -test.run 'TestLab' "$@"
