#!/bin/sh
# Build the path-clean zero-import WebAssembly verifier (`r5e_verify_rs.wasm`).
#
# Uses `--remap-path-prefix` to strip host filesystem paths (`$HOME`,
# `$CARGO_HOME`, `$RUSTUP_HOME`, and the checkout directory) from embedded Rust
# panic-location strings. Cross-machine bit-for-bit WASM reproducibility across
# differing host toolchains has not yet been independently tested.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"

RUSTFLAGS="--remap-path-prefix=$REPO_ROOT=. --remap-path-prefix=$CARGO_HOME_DIR=/workspace/.cargo --remap-path-prefix=$RUSTUP_HOME_DIR=/workspace/.rustup --remap-path-prefix=$HOME=/workspace" \
  cargo build --target wasm32-unknown-unknown --release --offline --locked --lib

WASM_OUT="$REPO_ROOT/target/wasm32-unknown-unknown/release/r5e_verify_rs.wasm"

if command -v strings >/dev/null 2>&1; then
  if strings "$WASM_OUT" | grep -Fq "$HOME"; then
    echo "error: unremapped host path found in $WASM_OUT" >&2
    exit 1
  fi
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$WASM_OUT"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$WASM_OUT"
fi
