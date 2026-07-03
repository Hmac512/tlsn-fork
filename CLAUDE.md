# TLSNotary

Rust implementation of the TLSNotary protocol: a Prover and a
Verifier/Notary jointly run a TLS session with MPC so the Verifier can
attest to the transcript without seeing the Prover's secrets. Built on the
`mpz` MPC library (git-pinned in the root `Cargo.toml`).

## Toolchain

- **rustc 1.96.0** (see `RUST_VERSION` in `.github/workflows/ci.yml`). The
  `mpz` dependencies require >= 1.95; older stable toolchains fail during
  `cargo build` with an MSRV error on `mpz-fields`.
- **nightly** with `rustfmt` (rustfmt.toml uses `imports_granularity`) and
  `rust-src` (harness WASM build).
- `wasm32-unknown-unknown` target on both toolchains; `wasm-pack` 0.14+
  for `crates/wasm` and `crates/harness`.
- `clang` >= 16 for the WASM build; OpenSSL dev headers.

`.claude/hooks/session-start.sh` installs all of the above in Claude Code
on the web sessions.

## Commands

```sh
cargo +nightly fmt --check --all                                # format (nightly!)
cargo clippy --all-features --all-targets --locked -- -D warnings
cargo build --all-targets --locked
cargo test --locked
# integration tests (slow, release-ish profile):
cargo test --locked --profile tests-integration --workspace \
  --exclude tlsn-tls-core --exclude tlsn-sdk-core -- --include-ignored
```

`./pre-commit-check.sh` runs all of the above. `Cargo.lock` is committed —
always build/test with `--locked`.

Integration tests need `RAYON_NUM_THREADS=32` (CI sets it) to avoid a rayon
deadlock (issue #548).

### Sandboxed/proxied environments

`tlsn-harness-plot` depends (via `charming`/`deno_core`) on the `v8` crate,
whose build script downloads a prebuilt static library at build time. Behind
a restrictive egress proxy that download 403s and the build fails. Everything
else is unaffected — exclude it:

```sh
cargo build --all-targets --locked --workspace --exclude tlsn-harness-plot
cargo test  --locked --workspace --exclude tlsn-harness-plot
```

`crates/examples-zk` is intentionally outside the workspace (pulls a ~1 GB
Noir git dependency); build it from its own directory only when needed.

## Workspace layout

- `crates/tlsn` — top-level protocol library: `prover::Prover`,
  `verifier::Verifier`, `Session`, proxy mode.
- `crates/core` (`tlsn-core`) — shared data model: transcript, commitments,
  connection/cert types, hashing, merkle.
- `crates/mpc-tls` — the 2PC TLS engine: `MpcTlsLeader` (Prover side),
  `MpcTlsFollower` (Verifier side), record layer.
- `crates/attestation` — Notary-signed `Attestation`, `Request`,
  `Presentation`, secrets/proofs for selective disclosure.
- `crates/components/*` — MPC building blocks: `deap`, `cipher` (2PC AES),
  `hmac-sha256` (TLS 1.2 PRF), `key-exchange` (3-party ECDH).
- `crates/tls-core` — rustls-derived TLS primitives.
- `crates/formats` — HTTP/JSON selective-disclosure parsers.
- `crates/sdk-core` — platform-agnostic SDK (`Io` trait) for
  WASM/mobile/native; `crates/wasm` — browser bindings.
- `crates/harness/*` — test/bench harness (native + browser); `runner setup`
  needs root for a virtual network.
- `crates/server-fixture/*`, `crates/tls-server-fixture`,
  `crates/data-fixtures` — test servers and sample data.
- `crates/examples` — runnable examples; start the fixture first:
  `PORT=4000 cargo run --bin tlsn-server-fixture`, then e.g.
  `SERVER_PORT=4000 cargo run --release --example basic`.
