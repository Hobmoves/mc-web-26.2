#!/usr/bin/env bash
# Builds the WASM client into web/pkg. Needs: rustup target add wasm32-unknown-unknown
# and `cargo install wasm-bindgen-cli` (version must match the wasm-bindgen crate).
set -euo pipefail
cd "$(dirname "$0")"
cargo build -p mc-web --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir web/pkg target/wasm32-unknown-unknown/release/mc_web.wasm
