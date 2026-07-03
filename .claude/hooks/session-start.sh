#!/bin/bash
set -euo pipefail

# Only needed in Claude Code on the web containers; local checkouts manage
# their own toolchains.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Keep in sync with RUST_VERSION in .github/workflows/ci.yml. The mpz
# dependencies require rustc >= 1.95, so a container's default stable
# toolchain may be too old to build the workspace.
RUST_VERSION=1.96.0

if ! rustup toolchain list | grep -q "^${RUST_VERSION}"; then
  rustup toolchain install "${RUST_VERSION}" --profile minimal -c clippy,rustfmt
fi
rustup default "${RUST_VERSION}"

# Nightly is needed for `cargo +nightly fmt` (rustfmt.toml uses
# imports_granularity) and for the harness WASM build (rust-src).
rustup toolchain install nightly --profile minimal -c rustfmt,rust-src
rustup target add wasm32-unknown-unknown
rustup +nightly target add wasm32-unknown-unknown

# wasm-pack 0.14+ is required by crates/wasm and crates/harness. Best-effort:
# core builds and tests do not need it, and the install is cached after the
# first container snapshot.
if ! command -v wasm-pack >/dev/null 2>&1; then
  cargo install wasm-pack --locked ||
    echo "warning: wasm-pack install failed; crates/wasm and crates/harness builds will not work" >&2
fi

cd "${CLAUDE_PROJECT_DIR}"
cargo fetch --locked
