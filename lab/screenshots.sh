#!/usr/bin/env bash
# Regenerates docs/screenshots from the demo (simulated traffic, no root).
# Needs a Chromium-family browser: set CHROME, or have one on PATH or in the
# Playwright cache. The access token is read from the demo's output and is
# never printed.
set -euo pipefail
cd "$(dirname "$0")/.."
out=docs/screenshots
port="${PORT:-7845}"
browser="${CHROME:-}"
for c in chrome-headless-shell chromium chromium-browser google-chrome; do
  [[ -z "$browser" ]] && browser="$(command -v "$c" || true)"
done
[[ -z "$browser" ]] && browser="$(ls -d "$HOME"/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell 2>/dev/null | sort | tail -1 || true)"
[[ -x "$browser" ]] || { echo "no Chromium found: set CHROME=/path/to/chrome"; exit 1; }

tmp="$(mktemp -d)"
go build -o "$tmp/afw" ./cmd/afw
"$tmp/afw" demo -listen "127.0.0.1:$port" >"$tmp/url" 2>/dev/null &
demo=$!
trap 'kill $demo 2>/dev/null || true; rm -rf "$tmp"' EXIT
for _ in $(seq 1 100); do [[ -s "$tmp/url" ]] && break; sleep 0.1; done
[[ -s "$tmp/url" ]] || { echo "the demo did not start"; exit 1; }
token="$(sed 's/.*#t=//' "$tmp/url")"

mkdir -p "$out"
shot() { # name route width height [dark|light]
  local scheme=1; [[ "${5:-dark}" == dark ]] && scheme=0
  "$browser" --no-sandbox --hide-scrollbars --force-color-profile=srgb --window-size="$3,$4" \
    --blink-settings=preferredColorScheme=$scheme --virtual-time-budget=6000 \
    --screenshot="$out/$1.png" "http://127.0.0.1:$port/#t=$token&go=$2" >/dev/null 2>&1
  echo "  $out/$1.png"
}
shot now-dark  now 1280 1010 dark
shot now-light now 1280 1010 light
shot activity  activity 1280 760 dark
shot source    'activity?s=194.26.135.84' 1280 900 dark
shot coverage  coverage 1280 960 dark
shot system    system 1280 990 dark
shot phone     now 400 1000 dark
