#!/usr/bin/env bash
# Builds the browser client (crates/wasm) and generates its JS glue into
# browser/pkg/ (not committed):
#
#   browser/pkg/csl_eth_wasm.js        ES module (`wasm-bindgen --target web`)
#   browser/pkg/csl_eth_wasm_bg.wasm
#   browser/pkg/csl_eth_wasm.d.ts
#
# wasm-bindgen-cli is pinned in mise.toml to the exact version of the
# `wasm-bindgen` crate (the two must match); `mise install` at the repo root
# installs it. Profile `wasm` (Cargo.toml): release, no debug info, fat LTO,
# one codegen unit.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$repo/browser/pkg"
cd "$repo"

if command -v mise >/dev/null 2>&1; then
  bindgen=(mise exec -- wasm-bindgen)
else
  bindgen=(wasm-bindgen)
fi

crate_version="$(sed -n '/^name = "wasm-bindgen"$/{n;s/^version = "\(.*\)"$/\1/p;}' Cargo.lock)"
cli_version="$("${bindgen[@]}" --version | awk '{print $2}')"
if [[ "$crate_version" != "$cli_version" ]]; then
  echo "build-wasm: wasm-bindgen-cli $cli_version does not match the wasm-bindgen crate $crate_version (Cargo.lock); run \`mise install\` in $repo" >&2
  exit 1
fi

# blst (BLS12-381, behind helios's sync-committee signature check) is
# compiled to wasm32 by clang, but Apple's ar silently drops non-Mach-O
# members and leaves an empty libblst.a, so the link fails on missing blst_*
# symbols. Archive with the toolchain's llvm-ar (rustup component
# llvm-tools, pinned in mise.toml) unless the caller chose an archiver.
if [[ -z "${AR_wasm32_unknown_unknown:-}" ]]; then
  sysroot="$(rustc --print sysroot)"
  host="$(rustc -vV | sed -n 's/^host: //p')"
  llvm_ar="$sysroot/lib/rustlib/$host/bin/llvm-ar"
  if [[ -x "$llvm_ar" ]]; then
    export AR_wasm32_unknown_unknown="$llvm_ar"
  elif command -v llvm-ar >/dev/null 2>&1; then
    export AR_wasm32_unknown_unknown="$(command -v llvm-ar)"
  else
    echo "build-wasm: no llvm-ar; run \`mise install\` in $repo (rust component llvm-tools) or set AR_wasm32_unknown_unknown" >&2
    exit 1
  fi
fi

cargo build --profile wasm --target wasm32-unknown-unknown -p csl-eth-wasm "$@"

wasm="target/wasm32-unknown-unknown/wasm/csl_eth_wasm.wasm"
mkdir -p "$out"
"${bindgen[@]}" --target web --out-dir "$out" --out-name csl_eth_wasm "$wasm"

size() { wc -c <"$1" | tr -d ' '; }
echo "cargo output: $wasm $(size "$wasm") bytes"
echo "browser/pkg/csl_eth_wasm_bg.wasm $(size "$out/csl_eth_wasm_bg.wasm") bytes ($(gzip -9c "$out/csl_eth_wasm_bg.wasm" | wc -c | tr -d ' ') gzipped)"
