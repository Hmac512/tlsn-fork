# Clean-room TLSN-style notarized TLS: v0 implementation plan

A staged plan for a from-scratch Rust workspace that reproduces the
**behavior and security arguments** of a TLSNotary-style notarized-TLS
system, at a deliberately reduced v0 threat model. This is functional and
protocol equivalence, not a port of any existing codebase: the MPC and
notary logic is hand-rolled on top of standard low-level primitive crates.

This document is **planning only**. It specifies what to build, in what
order, with what invariants and tests. It does not implement or scaffold
crates.

---

## 1. What v0 is, in one paragraph

A **prover** wants to convince a **verifier** that specific bytes were
exchanged over TLS 1.2 with a named server, without revealing the whole
transcript. Prover and verifier jointly act as the TLS *client*: they run a
three-party handshake so that neither holds the session keys alone, co-run
the AES-GCM record layer so the verifier co-authenticates every ciphertext
without seeing plaintext, and after the connection closes the prover commits
to byte ranges of the transcript and interactively proves selected ranges to
the verifier. v0 assumes a **semi-honest prover and an honest verifier**, and
is built so that upgrading to a malicious prover is a later milestone, not a
rewrite.

---

## 2. Resolved design decisions

These are decided. Do not re-litigate; the rationale is one line each.

| Decision | Choice | Rationale |
|---|---|---|
| TLS version / suite | TLS 1.2, ECDHE-P256, AES-128-GCM **only** | One cipher path removes agility branches that dominate a first implementation's complexity and test surface. |
| Security model | Semi-honest prover, honest verifier; malicious prover as a later configurable mode | Proportional to a first working system; the hard MPC hardening is where most effort would otherwise sink. |
| Verification | Interactive prover→verifier in v0; portable attestation later | An interactive proof needs no signing, no notary key management, no serialized artifact — the smallest thing that proves the architecture. |
| Disclosure granularity | Byte ranges in v0; HTTP-aware committing later | Ranges are format-agnostic and exercise the full commit/reveal machinery; HTTP parsing is orthogonal and additive. |
| Decryption | Deferred-only (buffer, reveal server-write key to prover after close) | One mode. Online decryption adds a mid-session MPC keystream path with no v0 payoff. |
| Networking | async/tokio from day one | The protocol is round-trip-bound; retrofitting async later is a rewrite of every I/O boundary. |

---

## 3. Open questions (with recommended answers)

These the implementing agent must resolve. Each has a recommendation.

1. **Serialization codec.** *Recommend `bincode` v2 with an explicit,
   versioned envelope.* It is compact, deterministic, and needs no schema
   IDL; a leading `u16` protocol-version field guards forward changes.
   `serde` derives keep the door open to swap codecs later.
2. **Wire framing.** *Recommend length-delimited frames
   (`tokio_util::codec::LengthDelimitedCodec`) carrying a small typed
   envelope `{ version, session_id, phase, msg_type, payload }`.* Framing is
   separated from message semantics so fuzzers can target each independently.
3. **How the joint-client TLS state machine is obtained.** *Recommend a
   minimal hand-rolled TLS 1.2 client restricted to the one suite*, rather
   than forking a rustls-like stack. Rationale: the record layer and key
   schedule are *not* a normal client — key derivation and encryption are
   split across two parties, so most of a general client's machinery would be
   torn out and its abstractions fought. A hand-rolled client scoped to
   ECDHE-P256/AES-128-GCM is a few thousand lines, fully inspectable, and the
   parts that matter (handshake transcript hashing, ClientKeyExchange, record
   framing) are exactly the parts we must control. The cost — reimplementing
   certificate-chain verification — is mitigated by using `webpki`/`rustls`
   *primitives* for chain validation only (see dependency policy). Revisit if
   the hand-rolled handshake transcript proves error-prone against real
   servers.
4. **Session-id derivation.** *Recommend a random 16-byte id minted by the
   party that initiates the session, echoed in every frame*, distinct from
   any TLS-level identifier. It is a routing/telemetry handle, never a
   security binding; security binding uses the handshake transcript hash and
   server ephemeral key (below).
5. **Transcript representation.** *Recommend a direction-tagged, append-only
   byte log with an index of TLS record boundaries* — `sent` and `recv` as
   contiguous byte vectors plus `Vec<RecordMeta{ offset, len, seq,
   content_type }>`. Byte ranges (`RangeSet<usize>`) address into the
   contiguous view; record metadata supports tag/keystream work. This is the
   one representation both commitments (byte ranges) and the record layer
   (per-record) can share.

---

## 4. Threat model (v0)

v0 defends only what a **semi-honest prover** and **honest verifier** leave
open. Where a property only bites under a *malicious* prover, the correct v0
output is a named **deferral**, not a manufactured defense.

| Actor / property | Capability | What stops it in v0 | Milestone | Deferred to malicious mode |
|---|---|---|---|---|
| Semi-honest-but-curious prover | Follows protocol, tries to learn verifier secrets or later misreport | Verifier holds no plaintext-relevant secret the prover shouldn't derive; keys are additively shared, prover only ever recombines its own outputs | M3–M4 | Forgery/deviation defenses (below) |
| Honest verifier (privacy) | Follows protocol, must not learn redacted bytes | Plaintext stays private to prover in the record layer (ciphertext decoded to both, plaintext is prover's private input); commitments are hiding (salted hashes); only revealed ranges opened | M4–M6 | — (honest-verifier privacy is the v0 target) |
| Network adversary | Observe, drop, reorder, inject on prover↔verifier and client↔server links | TLS 1.2 record MAC (AES-GCM tag) rejects tampering/injection on the server link; framed, session-tagged, sequence-checked prover↔verifier channel over an authenticated transport (TLS to verifier); TCP ordering | M3–M4 | Adversarial-prover-controlled reordering of the *proof* transcript |
| **Malicious prover / colluding prover+verifier** | Deviate from protocol, lie about inputs, equivocate | **OUT OF SCOPE.** Semi-honest assumption excludes it | — | Entire §11 hardening set |

Per integrity-style property — **defend or defer**:

| Property | v0 stance | Concrete mechanism / deferral |
|---|---|---|
| Record **tampering** (server link) | Defend | AES-128-GCM tag verified during the co-run record layer; a modified ciphertext fails tag reconstruction. |
| Record **reordering** (server link) | Defend | TLS 1.2 per-record sequence number feeds the GCM nonce/AAD; out-of-order records fail authentication. |
| **Replay** (server link) | Defend | TLS sequence numbers are monotonic within a session; a replayed record has the wrong seq and fails. |
| **Truncation** (session end) | Defend (semi-honest) | TLS `close_notify` is a distinguished record; its presence/absence is recorded. Under semi-honest assumptions the prover reports the true close. **Malicious truncation → defer.** |
| Prover **equivocation** (commit to A, reveal B) | Defer | Only a malicious prover equivocates; the hiding/binding of salted-hash commitments makes *accidental* mismatch detectable, but binding a lying prover to its ciphertext needs the §11 commitment-to-ciphertext proof. |
| Prover **lying about plaintext** (claim wrong bytes as the decryption) | Defer | The verifier co-authenticated the *ciphertext*; proving the revealed plaintext is that ciphertext's true decryption is the §11 binding proof. In v0 the semi-honest prover decrypts honestly with the revealed key. |
| Prover **inconsistent key shares** (skew the handshake) | Defer | Dual-PMS in-circuit equality check (§11). A semi-honest prover supplies consistent shares. |
| Prover↔verifier **proof-channel tampering** | Defend | Runs over an authenticated transport (the prover connects to the verifier over TLS); framing + session id + sequence guard misrouting. |

The "defer" rows are the expected, correct answers. Manufacturing v0
defenses against attacks the semi-honest assumption already excludes would be
wasted effort and is explicitly not wanted.

---

## 5. Dependency policy

Hand-roll the **notary/MPC protocol logic**: share conversion, joint
handshake orchestration, the record-layer share protocol, commitments. Do
**not** hand-write cryptographic primitives, and do **not** pull in any
TLSN-specific, MPC-framework, or ZK-framework dependency.

| ALLOWED (thin adapters over these) | DISALLOWED category | One-line reason |
|---|---|---|
| `sha2`, `blake3` (hashing) | Any MPC framework (garbling, OT-extension, secret-sharing runtimes) | v0 has no malicious-secure MPC; hand-rolled semi-honest share conversion is the whole point. |
| `aes`, `aes-gcm`, `ctr`, `ghash` (cipher/AEAD primitives) | Any ZK framework (SNARK/STARK/VOLE-ZK libraries) | v0 has no ZK layer; pulling one in prejudges §11 and bloats the tree. |
| `p256`, `elliptic-curve` (P-256 arithmetic) | Any TLSN / notary library | Clean-room: reproducing behavior, not depending on the reference. |
| `hkdf`, `hmac` (key derivation / PRF building blocks) | High-level "TLS-MPC" or "2PC-TLS" crates | Same. |
| `rand`, `rand_chacha` (RNG; ChaCha for seeded determinism) | A general TLS *stack* used as the joint client (e.g. driving rustls end-to-end) | The joint client is not a normal client; we need control of the split key schedule. `rustls`/`webpki` are used for cert-chain *validation primitives only*. |
| `subtle` (constant-time), `zeroize` (secret hygiene) | Homomorphic-encryption / Paillier libraries | Share conversion is OLE-from-OT, not Paillier — deliberately. |
| `serde` + `bincode` (serialization) | | |
| `tokio`, `tokio-util` (async, framing) | | |
| `tracing`, `metrics` (observability) | | |
| `webpki` / `rustls` **cert-verification primitives only** | | Chain validation is a solved problem; reimplementing X.509 path building is out of scope and dangerous. |
| `proptest`, `criterion`, `cargo-fuzz` target crates (test/bench) | | |

If a *future* malicious-security layer needs a ZK dependency, that is stated
only in §11 and pulled in only when that milestone begins.

---

## 6. Workspace architecture

A single Cargo workspace, multiple crates chosen for clean boundaries and no
cyclic dependencies. Dependency direction flows strictly upward: types →
adapters → protocol logic → role binaries.

| Crate | One responsibility | Key invariants |
|---|---|---|
| `nt-types` | Protocol message types, `SecurityMode`, session/phase enums, error taxonomy, wire envelope | No I/O, no crypto. Serializable types are the *only* things that cross the wire. Secret-bearing types live elsewhere. |
| `nt-transcript` | Direction-tagged transcript log, record index, byte-range addressing, redaction views | A range either lies fully inside authenticated data or is rejected. Redacted view never materializes hidden bytes. |
| `nt-crypto` | Thin, audited wrappers over primitive crates: hashing, AES-CTR keystream, GHASH, P-256, HKDF/PRF pieces, commitments | Each wrapper is a leaf; no protocol logic. Constant-time where the primitive is. Secret types zeroize. |
| `nt-mpc` | Hand-rolled semi-honest share conversion (A2M/M2A over OLE-from-OT), GF(2^128) and P-256 share arithmetic | Pure protocol algebra over an abstract channel; no TLS knowledge. Semi-honest-correct only (stated, not hidden). |
| `nt-tls` | Minimal TLS 1.2 client state machine (one suite), record framing, handshake transcript hashing, cert-chain validation via `webpki` | Emits/consumes records; delegates key material to the split key schedule. Never holds a full session key. |
| `nt-prover` | Prover-side orchestration: setup, joint handshake, record co-run, commitment, interactive prove | Owns plaintext; drives `SecurityMode`. Typed phase state machine. |
| `nt-verifier` | Verifier-side orchestration: setup, handshake co-run, ciphertext co-authentication, interactive verify | Never receives plaintext or blinders for redacted ranges. Typed phase state machine. |
| `nt-cli` | Dev/CLI tooling: run a prover or verifier, point at a fixture server, dump telemetry | No protocol logic; wiring only. |
| `nt-testutil` | Test fixtures: deterministic RNG seeding, a local TLS-like/stock TLS 1.2 fixture server, golden-vector loaders | Test-only; never a dependency of shipping crates. |

**State machines.** Prover and verifier each model their phases as an
explicit typed state machine (`Setup → Handshake → Records → Committed →
Proving → Done`), with transitions consuming `self` and returning the next
state so invalid transitions are unrepresentable. Message decoding validates
the envelope `phase` against the current state.

**The `SecurityMode` seam.** `SecurityMode` (an enum:
`SemiHonestV0`, and a reserved `MaliciousProver` variant that v0 constructs
never select) is threaded through the orchestration layer of `nt-prover` /
`nt-verifier`. It is the **one** place a little extra indirection is
justified: the handshake, record-layer, and commitment orchestrators expose
post-phase hooks (no-ops in v0) where the §11 checks will attach. v0 does not
stub the checks — the hooks exist as interface points, called with v0
implementations that do nothing beyond the semi-honest path.

**Secret-bearing types.** Session keys, key shares, blinders, and
unrevealed plaintext live in dedicated types in `nt-crypto`/`nt-transcript`
that:
- do **not** derive `Debug`/`Display` (a manual `Debug` prints a redaction
  marker only),
- do **not** derive `Clone` or `serde` (justification required at any use
  site that needs an exception; none expected in v0),
- implement `Zeroize`/`ZeroizeOnDrop`,
- own their lifetime explicitly — key shares are dropped at the phase
  boundary where they are no longer needed (server-write key survives to the
  deferred-decryption step, then drops).

No macros, `unsafe`, DSLs, or framework-style generics beyond what a plain
trait per seam requires.

---

## 7. Protocol phases mapped to the spine

The five reference phases and where they live:

1. **Setup / preprocessing** — parties agree `max_sent` / `max_recv` up
   front; all correlated randomness (OLE/OT correlations for share
   conversion, keystream/tag material sizing) is allocated before the server
   connection opens. Sizes fixed at commit time: overshoot wastes
   preallocated correlations, undershoot aborts. *Lineage: pre-allocated
   correlated randomness sized from declared transcript bounds.*
2. **Three-party handshake** — prover and verifier each sample an independent
   P-256 ephemeral secret; the ClientKeyExchange carries the **sum** of their
   public keys; the server does ordinary ECDH and stays oblivious. The PMS
   (x-coordinate of the combined point) is derived as **additive shares** via
   A2M/M2A share conversion over OLE-from-OT. The TLS 1.2 PRF runs in 2PC
   over the shared PMS; neither party holds a complete write key. *Lineage:
   additive EC point-addition shares via A2M/M2A over OLE-from-OT; TLS 1.2
   PRF evaluated in 2PC over shared PMS.*
3. **2PC record layer** — AES-128 as key-schedule + per-block circuits in CTR
   mode for keystream; XOR of keystream into data is a cheap separate step.
   GHASH is **not** in-circuit: `H` is computed once, additively shared out,
   and tag/polynomial work happens on GF(2^128) shares (odd powers via share
   conversion, even powers by local squaring). Ciphertext decoded to both;
   plaintext private to prover. **Deferred decryption only**: incoming
   records buffered; after close the server-write key is revealed to the
   prover for local decryption. *Lineage: AES-CTR keystream via per-block
   evaluation; GHASH via shared H-powers, odd powers by share conversion.*
4. **Commitment** — after close, the prover commits to byte ranges as salted
   hashes `H(msg ‖ blinder)` with per-span random blinders; each span is an
   independent commitment (no Merkle tree in v0). *Lineage: salted-hash range
   commitments.*
5. **Verification (interactive)** — the verifier is convinced that (a) the
   session was a real TLS session with the claimed server (cert chain +
   handshake signature over the ephemeral key bind identity), (b) revealed
   ranges are the true plaintext of the authenticated ciphertext, and (c)
   redacted ranges stay hidden. *Lineage: interactive selective-disclosure
   over co-authenticated ciphertext.*

---

## 8. Security & privacy requirements

**Roles / trust (v0).** Prover is semi-honest and owns plaintext. Verifier
is honest, co-authenticates ciphertext, and must never learn redacted bytes.
Neither holds a full session key during the live session.

**Transcript integrity & commitment.** Integrity of the *session* comes from
TLS 1.2 AEAD (tampering/reorder/replay above). Commitment integrity comes
from collision-resistant salted hashes; each committed range is independently
openable.

**Selective disclosure / redaction.** The verifier receives a partial
transcript containing only revealed ranges plus the blinders needed to open
them; redacted bytes and their blinders never leave the prover. Redaction
boundaries are validated: a reveal must be a subset of a committed range.

**Binding to session identity and ranges.** The handshake transcript hash and
the server ephemeral key bind the proof to *this* session with *this* server;
cert-chain validation (`webpki`) binds the ephemeral key to the server name
via the server's handshake signature. Range openings bind to committed spans
by hash equality.

**Domain / session binding.** Every prover↔verifier frame carries the session
id and phase; the interactive proof is bound to the handshake transcript hash
so a proof cannot be lifted onto another session.

**RNG.** Production randomness from the OS CSPRNG (`rand`); tests use seeded
`rand_chacha` for determinism. The two are distinguished at a single
injection point (an `Rng` passed into constructors), never by a global.

**Zeroization.** Key shares, session keys, blinders, and unrevealed plaintext
zeroize on drop; drops happen at the earliest phase boundary that no longer
needs them.

**Constant-time.** Comparisons of secrets (tag checks, commitment openings
where a secret is compared) use `subtle`. Share arithmetic avoids
secret-dependent branches.

**Privacy-safe logging / never-cross-a-boundary lists.**
- **Never logged:** session keys, key shares, blinders, unrevealed plaintext,
  raw PMS or shares of it.
- **Never serialized / sent:** the same set, plus the verifier's private
  handshake share except as the protocol's defined messages require.
- **Never crosses a process/network boundary:** unrevealed plaintext and its
  blinders (only revealed ranges + their blinders do).
Error messages name the phase and error category, never secret values.

---

## 9. Logging & observability

Structured `tracing` throughout; a stuck session must be diagnosable to the
phase without exposing secrets. One span per phase, nested under a session
span.

**Required fields** on events/spans: `role`, `session_id`, `peer_id`,
`phase`, `transcript_offset`/`range`, `msg_type`, `elapsed`, `retry_count`,
`net_state`, `commit_step`/`verify_step`, `error_category`.

**Metrics:** per-phase latency, peak memory, bandwidth (bytes per direction
per phase), transcript size, commitment size, and CPU hotspots (share
conversion, PRF-in-2PC, GHASH share work, preprocessing bandwidth).

**Privacy-safe by default:** transcript content is referenced by
offset/length, never value. A documented "reproducing failures from logs"
guide explains how to replay a failed session from the seeded RNG + frame
log **without** any secret material.

---

## 10. Milestones

Seven milestones. Each leaves the repo compiling, tested, and reviewable.
Each names the construction it reproduces.

### M1 — Protocol types, transcript, workspace skeleton
- **Goal:** the type spine and transcript handling everything else builds on.
- **Crates/modules:** `nt-types`, `nt-transcript`, `nt-testutil` (seeds,
  loaders).
- **Scope:** wire envelope + codec; `SecurityMode` enum and the phase enums;
  error taxonomy; transcript log with record index and `RangeSet` addressing;
  redaction view.
- **Invariants:** ranges outside authenticated data are rejected; redaction
  view cannot materialize hidden bytes; envelope round-trips.
- **Tests:** unit (serde round-trip, transcript slicing, range math);
  property (range union/subset, serde round-trip, redaction boundaries);
  negative (malformed envelope, out-of-bounds ranges).
- **Acceptance:** transcript + envelope pass property tests; no crate below
  `nt-types` in the dep graph depends upward.
- **Risks:** transcript representation churn — mitigated by fixing it here
  (open question #5) before dependents exist.
- **Observability:** span/field vocabulary defined as constants.
- **Lineage:** direction-tagged transcript with byte-range addressing.
- **Seam:** `SecurityMode` defined here as an interface; no behavior yet.

### M2 — Crypto adapters + share-conversion primitives
- **Goal:** audited primitive wrappers and the semi-honest share conversion
  the handshake and record layer both need.
- **Crates/modules:** `nt-crypto`, `nt-mpc`.
- **Scope:** hashing/PRF/AES-CTR/GHASH/P-256 wrappers with secret types +
  zeroization; OLE-from-OT correlation generation (semi-honest); A2M and M2A
  conversion over an abstract channel; GF(2^128) and P-256 share arithmetic.
- **Invariants:** conversions are semi-honest-correct (round-trip A2M∘M2A =
  identity on shares); secret types don't derive `Debug`/`Clone`/`serde`.
- **Tests:** golden vectors for each primitive (AES-CTR, GHASH, HKDF, P-256
  scalar mult) **before** any integration; property (A2M/M2A round-trip over
  random shares, additive/multiplicative homomorphism); negative (mismatched
  correlation counts).
- **Acceptance:** share conversion reconstructs correct products/sums over
  thousands of randomized property runs against an in-process channel.
- **Risks:** subtle field-endianness / bit-order bugs in GF(2^128) —
  mitigated by golden vectors.
- **Observability:** counters for correlations consumed vs. allocated.
- **Lineage:** A2M/M2A share conversion over OLE-from-OT; GF(2^128) share
  arithmetic with local squaring for even powers.
- **Explicitly not here:** no dual-PMS check, no ZK, no IT-MACs.

### M3 — Joint three-party handshake
- **Goal:** a real TLS 1.2 ECDHE-P256 handshake driven jointly, server
  oblivious, session keys existing only as shares.
- **Crates/modules:** `nt-tls` (handshake + record framing), `nt-mpc`,
  `nt-prover`/`nt-verifier` (handshake orchestration), `nt-crypto` (PRF).
- **Scope:** independent ephemeral secrets; summed ClientKeyExchange; PMS as
  additive shares via M2; TLS 1.2 PRF in 2PC over the shared PMS → shared
  write keys; cert-chain validation; handshake transcript hashing.
- **Invariants:** neither party ever assembles a full write key; the server
  sees a standard handshake; the combined public key is a valid curve point.
- **Tests:** integration (prover+verifier complete a handshake to a **stock,
  unmodified TLS 1.2 server** fixture — the differential test that our joint
  client is wire-valid); golden vectors (PRF outputs vs. known TLS 1.2 test
  vectors); negative (bad server cert → reject; wrong ephemeral share →
  handshake fails cleanly).
- **Acceptance:** a stock TLS 1.2 server accepts the joint client's handshake;
  session keys verified reconstructable only by combining both shares (test
  only).
- **Risks:** handshake transcript-hash mismatches against real servers —
  mitigated by testing against a stock server early.
- **Observability:** per-handshake-step span; round-trip counter.
- **Lineage:** additive EC point-addition shares via A2M/M2A over
  OLE-from-OT; TLS 1.2 PRF in 2PC.
- **Seam:** post-handshake hook (empty in v0) where the dual-PMS equality
  check attaches later.

### M4 — 2PC record layer (deferred decryption)
- **Goal:** co-run AES-128-GCM records so the verifier co-authenticates
  ciphertext without plaintext; buffer inbound; reveal server-write key after
  close.
- **Crates/modules:** `nt-tls` (record layer), `nt-mpc`, `nt-crypto`,
  `nt-prover`/`nt-verifier`.
- **Scope:** AES-CTR keystream via per-block evaluation from shared key;
  XOR-in as a separate step; GHASH `H` computed once and additively shared;
  tag via shared H-powers (odd via conversion, even by squaring); ciphertext
  decoded to both, plaintext private to prover; outbound request encrypted;
  inbound buffered; deferred decryption after `close_notify`.
- **Invariants:** verifier never obtains plaintext during the session; tag
  authenticates every record; server-write key revealed **only after** the
  ciphertext transcript is fixed.
- **Tests:** golden vectors (GCM tag/keystream vs. `aes-gcm` on known
  key/nonce); integration (full request/response with a stock server, then
  deferred decrypt yields correct plaintext); property (tag holds over random
  record sizes); negative (tampered ciphertext → tag fails; reorder →
  auth fails).
- **Acceptance:** end-to-end request to a stock TLS 1.2 server, response
  buffered and correctly decrypted post-close; verifier holds only
  ciphertext + tags.
- **Risks:** GHASH share bookkeeping across records — mitigated by
  per-record golden vectors.
- **Observability:** bandwidth + GHASH-share-work metrics; per-record span.
- **Lineage:** AES-CTR keystream per-block; GHASH via shared H-powers.
- **Seam:** post-close hook (empty) where in-circuit tag verification
  attaches later.

### M5 — Commitments
- **Goal:** salted-hash byte-range commitments over the closed transcript.
- **Crates/modules:** `nt-transcript`, `nt-crypto`, `nt-prover`.
- **Scope:** per-span random blinders; `H(msg ‖ blinder)` per range;
  independent commitments; commitment set + secret (blinder) store; the
  prover's commitment-config builder over byte ranges.
- **Invariants:** blinders are fresh per span and never leave the prover; a
  commitment reveals nothing about short/low-entropy spans without its
  blinder; committed ranges are subsets of authenticated data.
- **Tests:** unit (commit/open round-trip); property (open matches iff bytes
  and blinder match; disjoint spans independent); negative (wrong blinder,
  wrong bytes, overlapping-range handling).
- **Acceptance:** commit-then-open succeeds for arbitrary range sets; opening
  with a mutated byte or blinder fails.
- **Risks:** low — self-contained.
- **Observability:** commitment count/size metrics.
- **Lineage:** salted-hash range commitments.
- **Seam:** commitment API shaped so a future commitment-to-ciphertext
  binding proof can consume the same range/secret structures.

### M6 — Interactive verification
- **Goal:** the interactive prover→verifier proof that revealed ranges are
  the true plaintext of the co-authenticated ciphertext, for the claimed
  server, with redacted ranges hidden.
- **Crates/modules:** `nt-prover`, `nt-verifier`, `nt-types`,
  `nt-transcript`.
- **Scope:** prover reveals selected ranges + blinders; verifier checks (a)
  session identity (cert chain + handshake signature over ephemeral key, from
  M3 state), (b) revealed plaintext decrypts the authenticated ciphertext
  under the revealed server-write key (semi-honest: verifier recomputes
  AES-CTR over the revealed ranges and checks against stored ciphertext), (c)
  redacted ranges absent; outputs a verified partial transcript.
- **Invariants:** verifier accepts only ranges that open against commitments
  *and* match the ciphertext; redacted positions are marked, never inferred.
- **Tests:** integration (full prove/verify over M3–M5 output); negative
  (bad commitment, wrong domain/session binding, wrong key, out-of-range
  disclosure, reordered/replayed/truncated proof messages tested under the
  **semi-honest** assumption — malicious-adversarial versions marked
  deferred); property (any subset of committed ranges verifies).
- **Acceptance:** the plan's acceptance test (§14) passes end-to-end for a
  redaction example (reveal some ranges, hide others).
- **Risks:** conflating "verifier recomputes CTR" (valid at semi-honest)
  with a malicious-secure binding proof — mitigated by naming the boundary in
  code and in §11.
- **Observability:** per-verify-step span; verification outcome metric.
- **Lineage:** interactive selective disclosure over co-authenticated
  ciphertext.

### M7 — End-to-end, hardening of ergonomics, docs
- **Goal:** a runnable v0: CLI drives a prover and verifier against a fixture
  server; full docs; benches; WAN-simulated and concurrency tests.
- **Crates/modules:** `nt-cli`, `nt-testutil`, all crates' docs.
- **Scope:** wire the phases into runnable prover/verifier binaries; a
  deterministic fixture server; criterion benches; WAN-latency+loss harness;
  many-session concurrency test; the docs of §12.
- **Invariants:** default `cargo test` is deterministic (seeded); networked/
  non-deterministic tests are feature-gated and excluded by default.
- **Tests:** end-to-end against a local TLS-like session; concurrency (N
  simultaneous sessions); WAN-simulated latency; benchmarks recorded as a
  baseline.
- **Acceptance:** `nt-cli` completes a notarized session end-to-end; benches
  produce a baseline for §13 dimensions.
- **Risks:** flaky networked tests polluting CI — mitigated by feature-gating.
- **Observability:** the full metric set emitted and sampled in the e2e run.
- **Lineage:** integration of all above.

No "build everything at once" milestone exists by construction.

---

## 11. Where malicious security plugs in later

This section **describes**; it does not implement, and v0 pulls in none of
these dependencies. Each seam named in the milestones is where a future
`SecurityMode::MaliciousProver` path would attach. The construction lineage
is a QuickSilver-style **VOLE-ZK with IT-MACs** (one field element per AND
gate; information-theoretic MACs `M = K + x·Δ` over GF(2^128), a batched
random-linear-combination consistency check) — named for lineage only.

| Seam (milestone) | Future check | Construction that fills it | Rough cost |
|---|---|---|---|
| Post-close re-proof hook (M4) | Re-prove the co-run computations were done honestly | Post-hoc VOLE-ZK re-execution of the session's circuits | One extra pass over the AES circuits in ZK; dominated by AND-gate count of the record layer. |
| Commitment-to-ciphertext binding (M5) | Prove committed plaintext is the true decryption of the authenticated ciphertext | In-ZK AES-CTR consistency: revealed/committed bytes ⊕ keystream = stored ciphertext | ~one AES-128 circuit per committed block, in ZK; ~6.4k AND gates/block × one field element each. |
| Dual-PMS equality check (M3) | Detect a prover that fed inconsistent key shares | Run the share conversion twice and check `PMS₀ ⊕ PMS₁ = 0` inside a circuit | One extra share-conversion pass + a small equality circuit; cheap relative to the record layer. |
| In-circuit tag verification (M4) | Authenticate received records from the *verifier's* side against a malicious prover | Recompute J0/GHASH in ZK from shared key wires and check against wire tags | One GHASH+block-cipher evaluation per record in ZK. |

Only when a malicious-security milestone begins would a VOLE-ZK dependency
enter the tree. The v0 interfaces (the empty hooks, the range/secret
structures, the `SecurityMode` enum) are shaped so these attach without
touching the semi-honest data path.

---

## 12. Documentation requirements

Docs live next to code. Required:
- `/docs`: this plan; a protocol spec (phases, messages, state machines); a
  roles-and-phases explainer; a glossary of protocol terms (PMS, share
  conversion, GHASH powers, blinder, redaction, ephemeral key, etc.);
  test-vector documentation (what each golden vector covers and its source).
- Crate-level docs on every crate stating its one responsibility and
  invariants.
- Public-API docs with misuse warnings on secret-bearing types and on the
  `SecurityMode` seam ("v0 is semi-honest; do not present this as
  malicious-secure").
- Diagrams: the full-session sequence (setup → handshake → records →
  commit → verify) and the record-layer share flow.
- A stated **security-assumptions** page: exactly the v0 threat model, with a
  prominent pointer to §11 for what is *not* defended.

---

## 13. Performance requirements

**Measure before optimizing.** Establish M7 benches as a baseline; optimize
only against numbers.

Dimensions: loopback latency; WAN-simulated latency (added delay + loss);
prover/verifier CPU; memory by transcript size; bandwidth overhead;
commitment size; concurrent sessions; large-transcript scaling.

Cost decomposition — **freight / couriers / factory**:
- **Freight (bandwidth):** preprocessing correlations dominate; measure bytes
  moved per declared `max_sent`/`max_recv`. GHASH-share and PRF-in-2PC
  traffic are secondary.
- **Couriers (round trips):** the handshake and request-send sit **inside the
  live-server window** and are latency-critical; count round trips there
  ruthlessly. Setup and post-close commitment/verification are **outside**
  the window — throughput matters, latency less.
- **Factory (local compute):** AES-CTR block evaluation, GF(2^128) squaring
  for even GHASH powers, hashing for commitments.

Instrument each likely hotspot: share conversion (correlations
consumed/sec, conversion latency), PRF-in-2PC (round trips, bytes), GHASH
share work (field ops/record), preprocessing bandwidth (bytes vs. declared
sizes). Flag in telemetry which phase is inside vs. outside the live-server
window so a regression is attributed correctly.

---

## 14. Testing strategy

Testing is designed in per milestone, not bolted on.

- **Unit:** serialization, encoding, transcript slicing, commitments,
  redaction, state transitions.
- **Property (`proptest`):** transcript ranges (union/subset/disjoint),
  serde round-trips, commitment open-consistency, redaction boundaries,
  invalid-input rejection, A2M/M2A round-trip.
- **Negative:** malformed proofs, bad commitments, wrong domain/session
  binding, wrong keys, invalid disclosure ranges. For reordered / replayed /
  truncated inputs, test that v0 behaves correctly **under its semi-honest
  assumption**; mark the malicious-adversarial versions as **deferred**.
- **Integration:** prover/verifier flows per phase.
- **End-to-end:** against a local deterministic TLS-like session.
- **Golden vectors:** per protocol layer (AES-CTR, GHASH, HKDF/PRF, P-256,
  commitments) **before** integration of that layer.
- **Differential testing — standard-TLS layer only:** does the joint client
  produce a handshake and records a **stock, unmodified TLS 1.2 server**
  accepts. TLSN-artifact differential testing (attestations, portable wire
  formats) is **N/A for v0** — there is no portable artifact to diff.
- **Fuzz (`cargo-fuzz`):** parsers, wire messages, transcript decoding,
  verification inputs.
- **Benchmarks (`criterion`):** latency, bandwidth, memory, transcript
  scaling, commitment/verification cost.
- **WAN-simulated:** artificial latency + loss.
- **Concurrency:** many simultaneous sessions.
- **Determinism:** seeded RNG by default; networked/non-deterministic tests
  feature-gated and excluded from default runs.

Both soundness (correctness, negative cases) and performance are covered.

---

## 15. Tooling (matches this repository)

This plan's workspace inherits the tooling already present in this repo (it
is **not** an empty checkout — see Plan assumptions):

- **`rustfmt.toml`** exists: `imports_granularity = "Crate"`,
  `wrap_comments = true`, plus an `ignore` list. Formatting therefore runs on
  **nightly** (`cargo +nightly fmt`) because `imports_granularity` is a
  nightly rustfmt feature.
- **CI** (`.github/workflows/ci.yml`) pins `RUST_VERSION: 1.96.0` and runs:
  `cargo clippy --all-features --all-targets --locked -- -D warnings`
  (stable), `cargo +nightly fmt --check --all`, `cargo build --all-targets
  --locked`, `cargo test`, and a WASM build job. New crates must build clean
  under `-D warnings` and be formatted by nightly rustfmt.
- **`pre-commit-check.sh`** runs fmt + clippy + build + test + integration
  tests; new crates plug into it without changes.
- **`Cargo.lock` is committed**; build and test with `--locked`.
- **No markdown linter / formatter** is configured in the repo, so there is
  no markdown lint step to run for this document. If one is desired later,
  add it to CI explicitly rather than assuming it.

Do not invent tooling beyond the above.

---

## 16. Non-goals for v0

Explicitly out of scope (each deferred, not forgotten):
- Malicious-prover security (→ the configurable mode, §11).
- Malicious-secure hardening of share conversion / record layer: dual-PMS
  check, in-circuit tag verification, DEAP-style dual execution (§11).
- Portable notary-signed attestation and a presentation/verify split.
- HTTP-aware / JSON-field commitments (v0 is byte ranges).
- Online (non-deferred) decryption.
- Browser extension; mobile; production deployment; production key
  management.
- TLS versions other than 1.2; suites other than AES-128-GCM-ECDHE-P256.
- Arbitrary web-app UX.
- Any ZK/MPC framework dependency.
- Day-one parity with every TLSN feature.

Where scope is contested, the recommendation is always the **narrow v0 that
proves the core architecture first**.

---

## 17. Plan assumptions

Everything guessed or reconciled, stated plainly:
- **The working directory is not an empty repository.** The task framed a
  "new, empty Rust repository," but the actual checkout is the existing
  TLSNotary fork. This plan is written as a clean-room *design* for a fresh
  workspace (crate names prefixed `nt-` to avoid colliding with the existing
  `tlsn-*` crates), while the tooling section (§15) reflects the tooling that
  genuinely exists in this checkout, per the instruction to match reality and
  not invent tooling. No existing crates are modified; only
  `docs/tlsn-rust-rebuild-plan.md` is added.
- **Crate names** (`nt-*`) are proposals; the implementing agent may rename.
- **`bincode` v2, length-delimited framing, hand-rolled TLS 1.2 client** are
  recommendations (§3), not mandates — each with rationale to override
  knowingly.
- **AND-gate counts** cited in §11 (~6.4k/AES-128 block) are the standard
  Bristol-fashion figure, given for cost intuition only.
- **The fixture server** for differential testing is assumed to be a stock,
  unmodified TLS 1.2 server supporting ECDHE-P256/AES-128-GCM.
- **`webpki`/`rustls` primitives** are assumed acceptable for cert-chain
  validation despite the "hand-roll the client" stance, because X.509 path
  building is out of scope to reimplement.
- **Committee of one:** the semi-honest/honest-verifier model is taken as
  fixed per §2; every "defer" in §4 depends on it.

---

## 18. Acceptance test for this plan

> **A reviewer familiar with TLSNotary must be able to take any TLSN feature
> and either find where in the milestones it lands, or find it explicitly in
> non-goals.**

This is satisfied by construction:
- **In the milestones:** three-party handshake → M3; additive PMS shares /
  share conversion → M2–M3; 2PC AES-GCM record layer → M4; GHASH-via-shares →
  M4; deferred decryption → M4; salted-hash commitments → M5; selective
  disclosure / redaction → M5–M6; session-identity binding (cert chain +
  ephemeral key) → M3/M6; interactive verification → M6; setup/preprocessing
  with fixed sizes → M1/M2; transcript model → M1.
- **In non-goals / deferrals:** malicious-prover security, dual-PMS check,
  in-circuit tag verification, DEAP dual execution → §16 + §11; portable
  attestation and presentation/verify split → §16 + §11 (interfaces
  preserved); HTTP/JSON-field commitments → §16; online decryption → §16;
  encoding/Merkle-tree commitments, notary signing, browser extension, other
  TLS versions/suites → §16.

Any feature not in a milestone is deliberately in §16; any mechanism in a
milestone names the construction it reproduces (§10 lineage lines), making
"avoid obvious architectural mistakes" a checkable property.
