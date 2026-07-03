# Clean-room TLSN-style notarized TLS: v0 implementation plan

A staged plan for a from-scratch Rust workspace that reproduces the
**behavior and security arguments** of a TLSNotary-style notarized-TLS
system, at a deliberately reduced v0 threat model.

This is a **clean-room implementation from an independently written spec**.
The plan is reference-informed — it was refined against the behavior of
existing MPC-TLS systems — but the implementation is written from RFCs,
papers, primitive-crate docs, and this document, not by copying any
reference codebase (see §18, clean-room hygiene). The MPC and notary logic is
hand-rolled on top of standard low-level primitive crates.

This document is **planning only**. It specifies what to build, in what
order, with what invariants and tests. It does not implement or scaffold
crates. It targets a **fresh, empty repository**: everything — workspace,
tooling, CI — is a deliverable of the milestones below.

---

## 1. What v0 is, in one paragraph

A **prover** wants to convince a **verifier** that specific bytes were
exchanged over TLS 1.2 with a named server, without revealing the whole
transcript. Prover and verifier jointly act as the TLS *client*: they run a
three-party handshake so that neither holds the session keys alone, co-run
the AES-GCM record layer so the verifier co-authenticates every ciphertext
without seeing plaintext, and after the connection closes the prover commits
to byte ranges of the transcript and interactively proves selected ranges to
the verifier. Underneath sit two hand-rolled 2PC engines: **arithmetic share
conversion** (for the elliptic-curve handshake and GHASH) and a **boolean
garbled-circuit engine** (for the AES and SHA-256 circuits) — both
semi-honest. v0 assumes a **semi-honest prover and an honest-but-curious
verifier**, and is built so that upgrading to a malicious prover is a later
milestone, not a rewrite.

---

## 2. Resolved design decisions

Decided. Do not re-litigate; the rationale is one line each.

| Decision | Choice | Rationale |
|---|---|---|
| TLS version / suite | TLS 1.2, ECDHE-secp256r1, AES-128-GCM **only** (full profile in §3) | One cipher path removes agility branches that dominate a first implementation's complexity and test surface. |
| Security model | Semi-honest prover, honest-but-curious verifier; malicious prover as a later configurable mode | Proportional to a first working system; the malicious-secure hardening is where most effort would otherwise sink. |
| Boolean 2PC engine | **Hand-rolled semi-honest half-gate garbled circuits** (own crate, `nt-garble`) | AES and SHA-256 are boolean circuits; arithmetic share conversion cannot evaluate them. This is the largest single v0 component (§13, M3). |
| Verification | Interactive prover→verifier in v0; portable attestation later | An interactive proof needs no signing, no notary key management, no serialized artifact — the smallest thing that proves the architecture. |
| Disclosure granularity | Byte ranges in v0; HTTP-aware committing later | Ranges are format-agnostic and exercise the full commit/reveal machinery; HTTP parsing is orthogonal and additive. |
| Decryption | **Deferred for application-data records only**; handshake and alert records decrypt online | You cannot finish a TLS 1.2 handshake without decrypting the server Finished online; app data is the only thing safely deferrable. |
| PRF variant | **Normal full-2PC PRF** (all SHA-256 compressions in 2PC) | The reduced/low-bandwidth variant reveals intermediate PRF hashes; that privacy cost is not worth it in v0 (§16, §20). |
| Proof-channel auth | Verifier presents a **pinned certificate/public key**; prover connects over TLS | Binds the proof channel; an unauthenticated dev mode exists but is compiled out of release builds (§10). |
| Networking | async/tokio from day one | The protocol is round-trip-bound; retrofitting async later is a rewrite of every I/O boundary. |

---

## 3. Normative TLS profile

The joint client offers and accepts **exactly** this profile; anything else
is a hard abort (§10). This is not a simplification to relax later without a
design change.

| Parameter | v0 value |
|---|---|
| TLS version | 1.2 only (offer 1.2; abort on any other negotiated version) |
| Curve | secp256r1 (P-256) only |
| Cipher suites offered | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` |
| Extended master secret (RFC 7627) | **REQUIRED** — offered; **hard-abort if the server does not negotiate it** (§10 failure table; session-binding rationale in the paragraph below this table) |
| SNI | Required (server_name always sent) |
| ALPN | Offer `http/1.1` only |
| Compression | null only |
| Session resumption / tickets | Disabled |
| Renegotiation | Disabled |
| Client authentication | Unsupported |
| TLS False Start | Disabled |

EMS being mandatory is load-bearing for session binding: the master secret is
bound to the handshake `session_hash`, so the transcript the proof commits to
cannot be silently detached from the handshake that authenticated the server.

---

## 4. Open questions (with recommended answers)

The implementing agent resolves these; each has a recommendation.

1. **Wire serialization codec.** *Recommend `bincode` v2 with an explicit,
   versioned envelope* — compact, deterministic, no IDL; a leading `u16`
   protocol-version field guards changes. **Caveat:** the codec governs
   *wire framing only*. Commitment bytes are defined by the canonical,
   length-prefixed layout in §10/M6 and are **never** derived from
   bincode/serde output.
2. **Wire framing.** *Recommend length-delimited frames
   (`tokio_util::codec::LengthDelimitedCodec`)* carrying a typed envelope
   `{ version, session_id, phase, msg_type, payload }`, so fuzzers can target
   framing and semantics independently.
3. **How the joint-client TLS state machine is obtained.** *Recommend a
   minimal hand-rolled TLS 1.2 client restricted to the §3 profile*, rather
   than forking a general stack. The record layer and key schedule are *not*
   a normal client — key derivation and encryption are split across two
   parties — so most of a general client's machinery would be fought. Scoped
   to §3 it is a few thousand lines, fully inspectable. Certificate-chain
   validation is the one part delegated to `webpki`/`rustls` primitives (§5).
4. **Session-id derivation.** *Recommend a random 16-byte id minted by the
   initiator, echoed in every frame*, distinct from any TLS identifier — a
   routing/telemetry handle, never a security binding. Security binding uses
   the transcript manifest (§10/M6).
5. **Transcript representation.** *Recommend a direction-tagged, append-only
   byte log with a TLS-record index* — `sent`/`recv` as contiguous byte
   vectors plus `Vec<RecordMeta{ offset, len, seq, content_type }>`. Byte
   ranges (`RangeSet<usize>`) address the contiguous view; record metadata
   drives per-record keystream/tag work.

   **The transcript coordinate model (normative).** An offset is a 0-based
   index into the concatenated **application-data plaintext stream of one
   direction** (record headers, handshake, and alert bytes are excluded).
   Ranges are half-open `[start, end)`. Because AES-CTR is length-preserving,
   the *same* offset addresses the corresponding ciphertext byte via the
   record index (`plaintext offset ↔ (record seq, offset-in-record)`). Every
   range in this plan — commitment spans (M6), redaction/reveal boundaries
   (M1, M7), per-record keystream and tag work (M5), and the future binding
   proofs of §14 — uses these coordinates and no others.

---

## 5. Threat model (v0)

v0 defends only what a **semi-honest prover** and **honest-but-curious
verifier** leave open. Where a property only bites under a *malicious*
prover, the correct v0 output is a named **deferral**, not a manufactured
defense.

| Actor / property | Capability | What stops it in v0 | Milestone | Deferred to malicious mode |
|---|---|---|---|---|
| Semi-honest prover | Follows protocol, tries to learn verifier secrets or later misreport | Verifier holds no plaintext-relevant secret the prover shouldn't derive; keys are additively shared, prover recombines only its own outputs | M4–M5 | Forgery/deviation defenses (below) |
| Honest-**but-curious** verifier (privacy) | Follows protocol, but inspects everything it legitimately receives | **Can't-learn, not won't-look**: the prover's keystream share is a one-time pad on plaintext; commitments are hiding; disclosure reveals keystream-share bytes only at revealed offsets (M7); the verifier never reconstructs a full write key | M5–M7 | — (honest-but-curious privacy is the v0 target; per-phase table below) |
| Network adversary | Observe, drop, reorder, inject on either link | TLS 1.2 AES-GCM tag rejects tampering/injection on the server link; framed, session-tagged, sequence-checked prover↔verifier channel over an authenticated (pinned-cert) transport; TCP ordering | M4–M5 | Adversarial-prover-controlled reordering of the *proof* transcript |
| **Malicious prover / colluding prover+verifier** | Deviate from protocol, lie about inputs, equivocate | **OUT OF SCOPE.** Semi-honest assumption excludes it | — | Entire §14 hardening set |

Per integrity-style property — **defend or defer**:

| Property | v0 stance | Concrete mechanism / deferral |
|---|---|---|
| Record **tampering** (server link) | Defend | AES-128-GCM tag verified during the co-run record layer; a modified ciphertext fails tag reconstruction. |
| Record **reordering** (server link) | Defend | TLS 1.2 per-record sequence number feeds the GCM nonce/AAD; out-of-order records fail authentication. |
| **Replay** (server link) | Defend | TLS sequence numbers are monotonic within a session; a replayed record has the wrong seq and fails. |
| **Truncation** (session end) | Defend (semi-honest) | The content-type→mode mapping is prover-asserted and **verifier-checked** (M5): a `close_notify` cannot be hidden inside a private record, so a hidden closing alert is rejected. Under semi-honest the prover reports the true close. **Malicious truncation → defer.** |
| Prover **equivocation** (commit to A, reveal B) | Defer | Only a malicious prover equivocates; hiding/binding of the domain-separated commitments makes *accidental* mismatch detectable, but binding a lying prover to its ciphertext needs the §14 commitment-to-ciphertext proof. |
| Prover **lying about plaintext** | Defer | The verifier co-authenticated the *ciphertext*; proving revealed plaintext is that ciphertext's true decryption is the §14 binding proof. In v0 the semi-honest prover supplies its true keystream shares. |
| Prover **inconsistent key shares** (skew the handshake) | Defer | Dual-PMS in-circuit equality check (§14). A semi-honest prover supplies consistent shares. |
| Prover↔verifier **proof-channel tampering** | Defend | Authenticated transport (prover connects to the verifier's pinned cert); framing + session id + sequence guard misrouting. |

The "defer" rows are the expected, correct answers.

### Which "honest" the verifier is, per phase

"Honest verifier" conflates **honest-for-correctness** (follows the protocol)
with **honest-for-privacy** (doesn't exploit what it sees). v0 assumes the
first everywhere; the second it must not need — redaction has to hold against
an honest-but-*curious* verifier (**can't-learn**), or it is not privacy.

| Phase | Correctness assumption | Privacy against a curious verifier (mechanism) |
|---|---|---|
| Setup | Follows allocation protocol | Nothing secret exchanged; sizes are public by design. |
| Handshake | Well-formed ephemeral share; runs PRF 2PC honestly | Can't-learn: the verifier's PMS/key shares are uniformly random alone; the prover's shares are never sent. |
| Record layer (sent) | Co-computes keystream honestly | Can't-learn: the verifier sees `pt ⊕ ks_P` (prover's keystream share is a one-time pad) and its own `ks_V`; without `ks_P` plaintext is information-theoretically hidden. |
| Record layer (recv) + deferred decryption | Buffers ciphertext; at close co-runs keystream 2PC and releases its recv keystream shares to the prover | Can't-learn: the verifier retains its own recv keystream shares and never reconstructs a full write key. |
| Commitment | Accepts commitment messages | Can't-learn: domain-separated hashes hide committed spans without their blinders, which stay with the prover. |
| Verification | Checks openings and keystream equations honestly | Can't-learn: keystream-share bytes are opened to the verifier **only at revealed offsets** (M7); redacted offsets' shares — and hence plaintext — stay with the prover. |

**Statement:** v0's redaction guarantee is *can't-learn* at every phase; no
phase relies on the verifier declining to look. What a curious verifier *does*
legitimately learn — the declared leakage budget, not a hole — is metadata:
transcript lengths, record boundaries and timing, which byte ranges were
committed, and which were revealed.

### Keystream-share holders, per direction (normative)

Retaining keystream shares to M7 (§7) raises a direction-specific question:
does the verifier ever hold enough to read a *redacted* byte? The answer must
be no in **both** directions, or §21.2 is violated. The invariant that makes
it no: **the verifier holds only its own additive share `ks_V`, never `ks_P`
and never the full keystream; the prover opens `ks_P` only at revealed
offsets.** A redacted byte is therefore always masked by the prover's unopened
share `ks_P` — `ct ⊕ ks_V = pt ⊕ ks_P` is not plaintext.

| Direction | How keystream is produced | Prover holds (M5→M7) | Verifier holds (M5→M7) | At M7 |
|---|---|---|---|---|
| **SENT** | 2PC keystream during the live session; `ct = pt ⊕ ks_P ⊕ ks_V` decoded to both | `pt`, `ks_P`, `ct` (so it independently knows the full keystream `pt ⊕ ct`) | `ct` and `ks_V` **only** — never `ks_P`, never the full keystream | prover opens `ks_P[i]` at revealed offsets; verifier checks `pt[i] ⊕ ks_P[i] ⊕ ks_V[i] == ct[i]`. Redacted offsets: `ks_P` unopened → masked. |
| **RECV** | deferred 2PC keystream at close; verifier releases its `ks_V` to the prover so the prover can decrypt | `pt` (after decrypt), `ks_P`, its copy of `ks_V`, `ct` | `ct` and `ks_V` **only** — never `ks_P` | identical discipline: prover opens `ks_P[i]` at revealed offsets; redacted offsets masked by unopened `ks_P`. |

The apparent asymmetry — on SENT the prover already knows the full keystream
(`pt ⊕ ct`), on RECV the verifier hands its `ks_V` to the prover — does **not**
give the verifier any extra power in either case: the verifier's view is
`ks_V` plus `ct`, i.e. `pt ⊕ ks_P`, in both directions. `ks_V`'s only role is
to give the verifier's revealed-offset check independence from the prover; it
never enables reading a redacted offset. **Outcome chosen: strict can't-learn
holds in both directions with no design change** — because keystream is
additively *shared* (the verifier holds a share, not the full keystream) and
`ks_P` is opened only at revealed offsets. The failure mode to guard against
is a variant where the verifier ends up with the full sent keystream (or with
`ks_P`) for any redacted offset — trapdoor #4, and the reason this table is
normative, not illustrative.

---

## 6. Dependency policy

Hand-roll the **notary/MPC protocol logic**: share conversion, the OT
extension, the garbled-circuit engine, joint handshake orchestration, the
record-layer share protocol, commitments. Do **not** hand-write cryptographic
primitives, and do **not** pull in any external MPC or ZK framework.

**Clarification (load-bearing):** "no MPC framework" means **no external MPC
dependency**. Hand-rolling our *own* semi-honest OT extension and garbled-
circuit engine is **in scope and required** — it is not a framework
dependency, it is the core of the system. Vendored **Bristol-fashion circuit
files** (AES-128, SHA-256) are **data, not a framework**: they are parsed at
build time, and shipping them is allowed and expected.

| ALLOWED (thin adapters / data) | DISALLOWED category | One-line reason |
|---|---|---|
| `sha2`, `blake3` (hashing) | Any **external** MPC framework (garbling, OT-extension, secret-sharing runtimes) | We hand-roll our own semi-honest engines; an external one prejudges the architecture. |
| `aes`, `aes-gcm`, `ctr`, `ghash` (cipher/AEAD primitives, for adapters + golden vectors) | Any ZK framework (SNARK/STARK/VOLE-ZK) | v0 has no ZK layer; pulling one in prejudges §14 and bloats the tree. |
| `p256`, `elliptic-curve` (P-256 arithmetic) | Any TLSN / notary library | Clean-room: reproducing behavior, not depending on the reference. |
| `hkdf`, `hmac` (PRF building blocks for adapters + vectors) | High-level "TLS-MPC" / "2PC-TLS" crates | Same. |
| `rand`, `rand_chacha` (RNG; ChaCha for seeded determinism) | A general TLS *stack* driven as the joint client | The joint client is not a normal client; we control the split key schedule. `rustls`/`webpki` used for cert-chain *validation primitives only*. |
| `subtle` (constant-time), `zeroize` (secret hygiene) | Homomorphic-encryption / Paillier libraries | Share conversion is OLE-from-OT, not Paillier — deliberately. |
| `serde` + `bincode` (wire serialization only) | | |
| `tokio`, `tokio-util` (async, framing) | | |
| `tracing`, `metrics` (observability) | | |
| `webpki` / `rustls` **cert-verification primitives only** | | Chain validation is solved; reimplementing X.509 path building is out of scope and dangerous. |
| **Vendored Bristol-fashion AES-128 / SHA-256 circuit files** (build-time parsed data) | Writing a circuit compiler; hand-laying gates | The circuits are standard, published data; generating or hand-laying them is error-prone waste. |
| `proptest`, `criterion`, `cargo-fuzz` target crates (test/bench) | | |

If a *future* malicious-security layer needs a ZK dependency, that is stated
only in §14 and pulled in only when that milestone begins.

---

## 7. Workspace architecture

A single Cargo workspace; dependency direction flows strictly upward: types →
adapters → protocol engines → role binaries. No cyclic deps.

| Crate | One responsibility | Key invariants |
|---|---|---|
| `nt-types` | Protocol message types, `SecurityMode`, session/phase enums, `CloseStatus`, `TranscriptManifest`, typed algebraic-domain newtypes, error taxonomy, wire envelope | No I/O, no crypto. Serializable types are the *only* things that cross the wire. Secret-bearing types live elsewhere. |
| `nt-transcript` | Direction-tagged transcript log, record index, byte-range addressing, redaction views, manifest derivation | A range either lies fully inside authenticated data or is rejected. Redacted view never materializes hidden bytes. |
| `nt-crypto` | Thin, audited wrappers over primitive crates: hashing, AES-CTR keystream, GHASH, P-256, HKDF/PRF pieces, commitments | Each wrapper is a leaf; no protocol logic. Constant-time where the primitive is. Secret types zeroize. |
| `nt-ot` | Hand-rolled base OT (Chou-Orlandi) + semi-honest OT extension (IKNP/KOS-style, consistency check omitted) | Produces the ~10⁵–10⁶ correlated OTs a session needs from 128 base OTs. Semi-honest-only (stated, not hidden). |
| `nt-mpc` | Hand-rolled semi-honest arithmetic share conversion (A2M/M2A over OLE-from-OT), GF(2^128) and P-256 share arithmetic | Pure algebra over an abstract channel; no TLS knowledge. Consumes `nt-ot`. |
| `nt-garble` | Hand-rolled semi-honest **half-gate garbled-circuit evaluator**: circuit loading (Bristol), garble/evaluate, decode, an `Evaluator` trait boundary | Boolean 2PC only. Consumes `nt-ot` for input OTs. The `Evaluator` trait is the seam a later authenticated-garbling backend implements (§14). |
| `nt-tls` | Minimal TLS 1.2 client state machine (§3 profile), record framing, handshake transcript hashing, cert-chain validation via `webpki`, `CloseStatus` tracking | Emits/consumes records; delegates key material to the split key schedule. Never holds a full session key. |
| `nt-prover` | Prover-side orchestration: setup, joint handshake, record co-run, commitment, interactive prove | Owns plaintext; drives `SecurityMode`. Typed phase state machine. |
| `nt-verifier` | Verifier-side orchestration: setup, handshake co-run, ciphertext co-authentication, interactive verify | Never receives plaintext or blinders for redacted ranges; never reconstructs a full write key. Typed phase state machine. |
| `nt-cli` | Dev/CLI tooling: run a prover or verifier, point at a fixture server, dump telemetry | No protocol logic; wiring only. |
| `nt-testutil` | Test fixtures: deterministic RNG seeding, an HTTP/1.1 fixture server, golden-vector loaders | Test-only; never a dependency of shipping crates. |

**Typed algebraic domains.** No generic `Share<T>` spanning fields. Distinct
newtypes: `P256ScalarShare`, `P256CoordShare`, `Gf128Share`, `BoolShare` /
wire labels, `TranscriptOffset`, `RecordSeq`. Feeding a GF(2^128) share into
P-256 math must not typecheck; mixing an offset and a record sequence must not
typecheck.

**State machines.** Prover and verifier each model their phases as a typed
state machine (`Setup → Handshake → Records → Committed → Proving → Done`),
transitions consuming `self` and returning the next state so invalid
transitions are unrepresentable. The record phase has an explicit
**start-traffic gate** (M5): no application-data record is released until
the client Finished is sent and the server Finished is verified. Message
decoding validates the envelope `phase` against the current state.

**Mode-branded outputs.** There is no generic `VerifiedTranscript`.
Verification output is branded with the security mode —
`SecurityModeBoundTranscript<SemiHonestV0>` — so v0 output cannot be passed
where malicious-secure output is expected. The brand is a type parameter, not
a runtime flag.

**The `SecurityMode` seam.** `SecurityMode` (`SemiHonestV0`; a reserved
`MaliciousProver` variant v0 never constructs) is threaded through the
orchestration layer. It is the **one** place extra indirection is justified:
the handshake, record-layer, and commitment orchestrators expose post-phase
hooks (no-ops in v0) where the §14 checks attach, and `nt-garble`'s
`Evaluator` trait is where an authenticated-garbling backend later slots in.
v0 does not stub the checks — the hooks are interface points called with
semi-honest implementations.

**Secret-bearing types.** Session keys, key shares, keystream shares,
blinders, and unrevealed plaintext live in dedicated types that:
- do **not** derive `Debug`/`Display` (manual `Debug` prints a redaction
  marker only),
- do **not** derive `Clone` or `serde` (justification required at any
  exception; none expected in v0),
- implement `Zeroize`/`ZeroizeOnDrop`,
- own their lifetime explicitly. **Key shares drop after deferred decryption;
  keystream shares are retained to M7** (they are what verification opens),
  subject to the per-direction holder discipline in §5 — the verifier retains
  only its own share `ks_V`, never `ks_P` or the full keystream; blinders drop
  after the proof.

No macros, `unsafe`, DSLs, or framework-style generics beyond a plain trait
per seam.

---

## 8. Implementation trapdoors

The places an agent is most likely to build a *plausible-looking fake*.
Called out before the milestones because each is a silent failure — the code
compiles, tests pass, and the security property is gone.

1. **Calling plain AES/HMAC on a reconstructed full key** outside test code.
   In production paths the key exists only as shares; a full key materializing
   anywhere is the bug.
2. **Treating ECDHE-P256/AES-128-GCM as a complete cipher-suite profile.** It
   is not — see the §3 table (EMS, SNI, ALPN, resumption, renegotiation, RSA
   *and* ECDSA auth all matter).
3. **Dropping key/keystream shares before M7 needs them.** Keystream shares
   are retained to verification; premature zeroization breaks the proof.
4. **Revealing a whole AES-CTR block when only one byte is disclosed.**
   Keystream is decoded per 16-byte block; opening the block leaks the other
   15 bytes' plaintext. Only per-offset keystream *shares* are opened.
5. **Treating transport EOF as proof of a complete response.** EOF is
   `TransportEof`, not completeness; see `CloseStatus` (§10).
6. **Letting bincode/serde encoding define commitment bytes.** Commitments use
   the canonical layout of M6; a serde re-encoding silently changes the
   committed value.
7. **Calling output "verified" without the semi-honest qualifier.** Output is
   `SecurityModeBoundTranscript<SemiHonestV0>`; dropping the brand oversells
   the guarantee.
8. **Using base OT without extension.** Base OT is ~1 exponentiation each;
   a session needs 10⁵–10⁶ OTs. Extension is mandatory, not an optimization.
9. **Deferring decryption of handshake/alert records** — including the server
   Finished. Those decrypt online or the handshake cannot complete.
10. **Evaluating boolean circuits with the arithmetic share-conversion
    machinery.** AES/SHA-256 go through `nt-garble`; share conversion cannot
    evaluate a boolean gate.

---

## 9. Protocol phases mapped to the spine

1. **Setup / preprocessing** — parties agree byte budgets `max_sent` /
   `max_recv` **and record-count budgets** `max_sent_records` /
   `max_recv_records` (§10 failure table; default `max(8, 1 per 4 KB of
   declared bytes)`, overridable). All correlated randomness — base OTs,
   extended OTs for share conversion and garbled-circuit inputs, OLE
   correlations, GHASH H-power material — is allocated before the server
   connection opens; per-record keystream/tag and GHASH H-power counts are
   sized from the **record** budgets, not byte sizes, because each TLS record
   needs its own allocation regardless of fill. Overshoot wastes preallocated
   material; undershoot (bytes *or* records) is a hard abort. *Lineage:
   pre-allocated correlated randomness sized from declared transcript and
   record bounds.*

2. **Three-party handshake** — prover and verifier each sample an independent
   P-256 ephemeral secret; the ClientKeyExchange carries the **sum** of their
   public keys; the server does ordinary ECDH and stays oblivious. The
   premaster secret is the **x-coordinate of the combined point, encoded as a
   fixed-length 32-byte octet string with leading zeros preserved** (per TLS);
   the two parties hold **arithmetic additive shares mod the P-256 prime** of
   it, produced by A2M/M2A share conversion over OLE-from-OT.

   **Arithmetic→boolean bridge (load-bearing).** The PRF is a boolean circuit
   (HMAC-SHA256); the PMS shares are arithmetic. The PMS is **reconstructed
   inside the boolean circuit** by an in-circuit mod-p adder over the two
   bit-decomposed, little-endian-encoded shares — there is no point where a
   party holds the PMS in the clear. From the reconstructed PMS the TLS 1.2
   PRF (Normal variant, all SHA-256 compressions in 2PC) derives the master
   secret (EMS: seed = handshake `session_hash`) and then the session keys and
   Finished verify-data, all as garbled-circuit outputs; neither party holds a
   complete write key. *Lineage: additive EC point-addition shares via A2M/M2A
   over OLE-from-OT; in-circuit mod-p PMS reconstruction; TLS 1.2 PRF in 2PC.*

3. **2PC record layer** — AES-128 evaluated in `nt-garble` as key-schedule +
   per-block circuits in CTR mode for keystream; keystream XOR into data is a
   cheap separate step. GHASH is **not** in-circuit: `H` is computed once
   (garbled), additively shared out across a **boolean→arithmetic bridge** (the
   mirror of the PMS bridge above; a silent-failure seam pinned in M5), and
   tag/polynomial work happens on GF(2^128) shares (odd powers via share
   conversion, even powers by local squaring). Ciphertext is decoded to both parties; plaintext stays private
   to the prover. **Handshake and alert records decrypt online** (the server
   Finished's verify-data must be checked before app data flows). **Only
   application-data records are deferred**: buffered during the session, their
   keystream computed jointly at close.

   **Client Finished sequencing.** The client Finished is itself an encrypted
   record: it is produced by the PRF (needs the shared keys), encrypted
   through the record layer in **public** mode (both parties see it — it is
   not application data), and flushed **before** any application-data record.
   The record-layer start-traffic gate enforces: client Finished sent →
   server Finished decrypted online and verified → application data released.

   **The deferred-decryption invariant (load-bearing).** At close, for the
   received direction the parties jointly run the deferred 2PC keystream
   evaluation over the buffered application-data records; each retains its
   additive keystream share, and the **verifier releases its recv keystream
   shares to the prover** so the prover can recover plaintext. This release is
   sound **only because** (1) the connection is closed (any terminal
   `CloseStatus`), so the server accepts no further records under this key, and
   (2) the verifier's ciphertext-and-tag log is already sealed, so the record
   set is fixed. A prover with full keystream can forge valid-looking records
   but has nowhere to put them. **If released any earlier**, the prover could
   encrypt requests the verifier never co-authorized and fabricate "received"
   records before the verifier logs them — co-authentication collapses. The
   verifier **never reconstructs a full write key** (releasing keystream
   shares is strictly weaker than releasing the key: it authorizes decryption
   of exactly the buffered records, nothing more). The state machines make the
   ordering unrepresentable: the recv-keystream-release message is only
   constructible from the post-close, log-sealed state. *Lineage: AES-CTR
   keystream via per-block garbled evaluation; GHASH via shared H-powers, odd
   powers by share conversion; deferred joint keystream at close.*

   **Reconciliation flag.** Earlier drafts spoke of "revealing the
   server-write key to the prover." v0 realizes deferral as a **keystream-
   share release**, not a raw-key release, so both parties retain keystream
   shares for verification without a re-run (this is what makes the M7 check
   have teeth and removes the M5/M7 contradiction). This is strictly more
   private than revealing the key and is a deliberate design choice, flagged
   here rather than left implicit.

4. **Commitment** — after close both parties derive a canonical
   `TranscriptManifest` (§10/M6); the prover commits to byte ranges as
   domain-separated, length-prefixed hashes bound to `manifest_hash` (M6),
   each span independent (no Merkle tree in v0). *Lineage: canonical manifest
   binding + domain-separated salted range commitments.*

5. **Verification (interactive)** — the verifier is convinced that (a) the
   session was a real TLS session with the claimed server (cert chain +
   handshake signature over the ephemeral key, EMS-bound), (b) revealed ranges
   are the true plaintext of the co-authenticated ciphertext (per-offset
   keystream-share opening; §10/M7), and (c) redacted ranges stay hidden.
   Output is `SecurityModeBoundTranscript<SemiHonestV0>`. *Lineage:
   interactive selective disclosure over co-authenticated ciphertext.*

---

## 10. Security & privacy requirements

**Roles / trust (v0).** Prover semi-honest, owns plaintext. Verifier
honest-but-curious, co-authenticates ciphertext, must not learn redacted
bytes. Neither holds a full session key during the live session.

**Transcript integrity & commitment.** Session integrity from TLS 1.2 AEAD
(tampering/reorder/replay above). Commitment integrity from collision-
resistant, domain-separated hashes bound to the manifest; each range
independently openable.

**Selective disclosure / redaction.** The verifier receives a partial
transcript of revealed ranges plus the keystream-share bytes and blinders
needed to open them; redacted bytes, their keystream shares, and their
blinders never leave the prover. A reveal must be a subset of a committed
range.

**Binding to session identity and ranges (the manifest).** Before
commitments both parties derive:

```
TranscriptManifest = {
  session_id, server_name, cert_chain_hash, server_key_exchange_hash,
  handshake_transcript_hash, cipher_suite, ems_negotiated,
  client_random, server_random, sent_len, recv_len,
  record_index_hash, close_status
}
```

Commitments and verification bind to `manifest_hash = H(canonical(manifest))`.
Range commitments use a **canonical, length-prefixed** encoding — never
bincode/serde output:

```
commitment = H( "nt-v0-range-commit" ‖ protocol_version ‖ manifest_hash ‖
                direction ‖ range_start ‖ range_end ‖ plaintext_bytes ‖ blinder )
```

The Merkle-compatibility note stands: a future tree hashes leaves derived from
this same canonical layout.

**Domain / session binding.** Every prover↔verifier frame carries the session
id and phase; the interactive proof binds to `manifest_hash`, so a proof
cannot be lifted onto another session.

**RNG.** Production randomness from the OS CSPRNG (`rand`); tests use seeded
`rand_chacha`. Distinguished at one injection point (an `Rng` passed into
constructors), never a global.

**Zeroization.** Key shares, session keys, keystream shares, blinders, and
unrevealed plaintext zeroize on drop; key shares drop after deferred
decryption, keystream shares after the proof.

**Constant-time.** Secret comparisons (tag checks, commitment openings) use
`subtle`. Share arithmetic avoids secret-dependent branches.

**Proof-channel authentication.** The verifier presents a pinned
certificate/public key; the prover validates it before the session. An
unauthenticated local-dev mode exists but is **compile-gated out of release
builds** (a cargo feature off by default in release).

**Failure semantics: abort vs. error.** Classified once, in `nt-types`:

| Failure | Class | Behavior | What it leaks |
|---|---|---|---|
| Byte-budget undershoot (`max_sent`/`max_recv`) | **Hard abort** | Unrecoverable; zeroize all shares | That a public declared bound was exceeded. |
| **Record-count-budget undershoot** (`max_sent_records`/`max_recv_records`) | **Hard abort** | Same class as byte undershoot | That a public record bound was exceeded. |
| **EMS not negotiated by server** | **Hard abort** | Refuse before app data | Server capability (public). |
| Record tag mismatch | **Hard abort** | Unrecoverable (tampered/corrupt link) | Nothing secret; the failing record index. |
| Certificate-chain / handshake-signature failure | **Hard abort** | Refuse before app data | Server identity material (public). |
| **A2M zero-factor** (multiplicative factor is zero during share conversion) | **Hard abort** | Unrecoverable | Phase/category only. |
| Phase-order violation / malformed frame | **Hard abort** | State machine refuses the transition | Phase + category only. |
| Transient I/O error | **Recoverable** | Bounded retries with backoff; abort on budget exhaustion | Retry counters in telemetry. |
| Commitment-opening mismatch, invalid disclosure range (verify) | **Verification failure, not protocol abort** | Proof rejected; state/logs intact for diagnosis | Which check failed (category), never the secret. |

Hard aborts are **fail-closed**: all shares, keystream shares, blinders, and
buffered plaintext zeroize before the error propagates. Error types carry
phase and category, never key material, blinders, or plaintext.

**Close/truncation semantics.** `CloseStatus`, recorded in session state and
the manifest:

```
CloseStatus = CleanClose            // close_notify observed
            | TransportEof          // TCP EOF, no close_notify
            | AppCompleteWithoutCloseNotify  // Content-Length satisfied or chunked terminator seen
            | TruncatedOrUnknown
```

The keystream-share release requires connection-closed (**any** terminal
status). Claims about response **completeness** require the corresponding
status (`CleanClose` or `AppCompleteWithoutCloseNotify`). **"Bytes were seen"
never implies "the response was complete."**

**Privacy-safe logging / never-cross-a-boundary lists.**
- **Never logged:** session keys, key shares, keystream shares, blinders,
  unrevealed plaintext, raw PMS or shares of it.
- **Never serialized / sent:** the above, plus the verifier's private
  handshake share except as defined protocol messages require.
- **Never crosses a process/network boundary:** unrevealed plaintext, its
  keystream shares, and its blinders (only revealed ranges + their openings
  do).
Error messages name phase and category, never secret values.

---

## 11. Logging & observability

Structured `tracing`; a stuck session must be diagnosable to the phase
without exposing secrets. One span per phase, nested under a session span.

**Required fields:** `role`, `session_id`, `peer_id`, `phase`,
`transcript_offset`/`range`, `msg_type`, `elapsed`, `retry_count`,
`net_state`, `commit_step`/`verify_step`, `error_category`.

**Metrics:** per-phase latency, peak memory, bandwidth (bytes per direction
per phase), transcript size, commitment size, and CPU hotspots — **SHA-256-
in-2PC compression count (the dominant compute cost), garbled-gate throughput,
OT-extension bytes**, share conversion, GHASH share work, preprocessing
bandwidth.

**Privacy-safe by default:** transcript content referenced by offset/length,
never value. A documented guide explains replaying a failed session from the
seeded RNG + frame log **without** secret material.

---

## 12. Progress tracking (PROGRESS.toml — normative)

A machine-readable `PROGRESS.toml` at the repo root is the implementing
agent's cursor. It records: the current milestone index, the current step
within it, per-milestone **Definition-of-Done** checkboxes, open blockers,
and the single next action. It is read at session start and rewritten on every
commit. **A milestone's DoD must be ticked in `PROGRESS.toml` before advancing
to the next.** Creating it is an M1 deliverable; keeping it accurate is a
standing requirement of every milestone.

---

## 13. Milestones

Eight milestones. Each leaves the repo compiling, tested, reviewable, with its
`PROGRESS.toml` DoD ticked. Each names the construction it reproduces.

### M1 — Types, transcript, manifest, tooling, PROGRESS.toml
- **Goal:** the type spine, transcript handling, and the repository's tooling
  skeleton.
- **Crates/modules:** `nt-types`, `nt-transcript`, `nt-testutil`; workspace +
  CI + `PROGRESS.toml`.
- **Scope:** wire envelope + codec; `SecurityMode`, phase enums, `CloseStatus`,
  `TranscriptManifest`, typed algebraic-domain newtypes, error taxonomy;
  transcript log with record index and `RangeSet` addressing; redaction view;
  the §14 tooling (rustfmt, CI, pre-commit, committed `Cargo.lock`);
  `PROGRESS.toml`.
- **DoD:** workspace builds clean under `-D warnings`; nightly `fmt --check`
  passes; property tests green; `PROGRESS.toml` present and accurate.
- **Invariants:** ranges outside authenticated data rejected; redaction view
  cannot materialize hidden bytes; envelope round-trips; newtype domains don't
  cross-typecheck.
- **Tests:** unit (serde round-trip, transcript slicing, range math); property
  (range union/subset, redaction boundaries); negative (malformed envelope,
  out-of-bounds ranges).
- **Acceptance:** transcript + envelope pass property tests; dep graph acyclic.
- **Risks:** transcript/manifest churn — mitigated by fixing both here.
- **Observability:** span/field vocabulary as constants.
- **Lineage:** direction-tagged transcript with byte-range addressing;
  canonical manifest type.
- **Seam:** `SecurityMode` and the mode-branded output type defined as
  interfaces; no behavior yet.

### M2 — Crypto adapters, share conversion, OT extension
- **Goal:** audited primitive wrappers, the semi-honest OT stack, and
  arithmetic share conversion.
- **Crates/modules:** `nt-crypto`, `nt-ot`, `nt-mpc`.
- **Scope:** hashing/PRF/AES-CTR/GHASH/P-256 wrappers with secret types +
  zeroization; **base OT (Chou-Orlandi) + semi-honest OT extension
  (IKNP/KOS-style, consistency check omitted)** producing bulk correlated OTs
  from 128 base OTs; OLE-from-OT (Gilboa bit-decomposition); A2M/M2A over an
  abstract channel; GF(2^128) and P-256 share arithmetic. Define the A2M
  zero-factor error path.
- **DoD:** OT extension produces ≥10⁶ correlated OTs in a bench; A2M∘M2A
  round-trips; GHASH golden-vector gate (below) green.
- **Invariants:** conversions semi-honest-correct; secret types don't derive
  `Debug`/`Clone`/`serde`; the OT extension is delta-correlated and batched.
- **Tests:** golden vectors per primitive (AES-CTR, GHASH, HKDF, P-256 scalar
  mult) **before** integration; property (A2M/M2A round-trip, homomorphism);
  negative (mismatched correlation counts, A2M zero factor).
- **Acceptance / gating precondition:** GF(2^128) share arithmetic reproduces
  GHASH values from the reference `aes-gcm` crate on golden vectors **before**
  any downstream milestone consumes this module.
- **Risks:** **odd-power GF(2^128) share conversion is the subtlest crypto in
  v0 and a bug is SILENT** — wrong tag, not a crash. GHASH's bit-reflected
  representation and endianness are the traps; hence the gate.
- **Observability:** correlations consumed vs. allocated; OT-extension bytes.
- **Lineage (semi-honest primitives; standard references, §24):** base OT =
  Chou-Orlandi; OT extension = **IKNP** semi-honest, using **KOS**'s
  construction but **omitting KOS's malicious correlation check** (deferred to
  §14); OLE-from-OT = **Gilboa** bit-decomposition; A2M/M2A over OLE-from-OT;
  GF(2^128) arithmetic with local squaring for even powers. v0 does **not** use
  LPN-style correlated OT (Ferret-core) — that is a future bandwidth
  optimization only (§16), kept off the M2 path to stay on the simpler,
  more-auditable IKNP/KOS lineage.
- **Explicitly not here:** no dual-PMS check, no ZK, no IT-MACs, no KOS
  consistency check, no LPN/Ferret COT (all §14 or §16).

### M3 — Garbled-circuit engine (boolean 2PC) — *the largest single component*
- **Goal:** a hand-rolled semi-honest half-gate garbled-circuit evaluator that
  runs AES-128 and SHA-256, with golden vectors gating all downstream use.
- **Crates/modules:** `nt-garble` (consumes `nt-ot`); Bristol circuit files.
- **Scope:** Bristol-fashion circuit loader; free-XOR + half-gate garbling;
  garble/evaluate/decode; input wiring via OT (`nt-ot`); the `Evaluator` trait
  boundary; vendored **AES-128 (~6.4k AND gates)** and **SHA-256 compression
  (~22.6k AND gates)** circuits.
- **DoD:** garbled AES-128 and SHA-256 outputs match plain `aes`/`sha2`
  references on golden vectors; `Evaluator` trait documented as the
  authenticated-garbling seam.
- **Invariants:** boolean 2PC only; garbler holds `Delta` and never leaks it;
  input labels via OT; decode reveals only designated outputs.
- **Tests:** golden vectors (garbled AES-128, garbled SHA-256 compression vs.
  plain reference) — **gating**: no milestone past M3 may consume the engine
  until these pass; property (random circuits over small gate sets); negative
  (malformed circuit file, wrong input width).
- **Acceptance:** AES-128 and SHA-256 evaluate correctly in 2PC against the
  reference; throughput benchmarked.
- **Risks:** this is the biggest, subtlest v0 build; half-gate/free-XOR label
  bookkeeping errors are silent. Golden vectors are the control.
- **Observability:** gates garbled/evaluated, bytes per circuit.
- **Lineage (standard references, §24):** semi-honest **half-gate** garbled
  circuits (Zahur-Rosulek-Evans) + **free-XOR** (Kolesnikov-Schneider);
  vendored Bristol AES-128 / SHA-256. A malicious backend (authenticated
  garbling, WRK-line) is §14, not here.
- **Seam:** the `Evaluator` trait is where a later authenticated-garbling
  (malicious) backend attaches as a second implementation (§14).

### M4 — Joint three-party handshake
- **Goal:** a real TLS 1.2 ECDHE-P256 handshake driven jointly, server
  oblivious, session keys existing only as shares.
- **Crates/modules:** `nt-tls`, `nt-mpc`, `nt-garble`, `nt-prover`/
  `nt-verifier`, `nt-crypto`.
- **Scope:** independent ephemeral secrets; summed ClientKeyExchange; PMS as
  arithmetic additive shares via M2; **in-circuit mod-p PMS reconstruction**
  (bit-decomposed, little-endian shares) feeding the Normal-variant TLS 1.2
  PRF in `nt-garble`; EMS (seed = `session_hash`) required; session keys +
  Finished verify-data as garbled outputs; cert-chain validation; handshake
  transcript hashing; PMS = 32-byte x-coordinate octet string, leading zeros
  preserved.
- **DoD:** a stock TLS 1.2 server accepts the joint handshake; PRF outputs
  match TLS 1.2 test vectors; EMS-absent server → hard abort.
- **Invariants:** neither party assembles a full write key; the server sees a
  standard handshake; the combined public key is a valid curve point; the PMS
  never exists in the clear on either side.
- **Tests:** integration (handshake to a stock server — the standard-TLS
  differential test); golden vectors (PRF vs. known TLS 1.2 vectors, EMS
  path); negative (bad cert → reject; EMS not offered → abort; wrong ephemeral
  share → clean failure).
- **Acceptance:** stock server accepts; session keys reconstructable only by
  combining both shares (test only).
- **Risks:** transcript-hash / EMS `session_hash` mismatches against real
  servers — mitigated by early stock-server testing.
- **Observability:** per-handshake-step span; SHA-256-compression count;
  round-trip counter.
- **Lineage:** additive EC point-addition shares via A2M/M2A over OLE-from-OT;
  in-circuit mod-p PMS reconstruction; TLS 1.2 PRF (EMS) in 2PC.
- **Seam:** post-handshake hook (empty) for the §14 dual-PMS equality check.

### M5 — 2PC record layer (deferred app-data decryption)
- **Goal:** co-run AES-128-GCM records so the verifier co-authenticates
  ciphertext without plaintext; decrypt handshake/alert online; defer app
  data; retain keystream shares.
- **Crates/modules:** `nt-tls` (record layer), `nt-mpc`, `nt-garble`,
  `nt-crypto`, `nt-prover`/`nt-verifier`.
- **Scope:** AES-CTR keystream via per-block garbled evaluation from the
  shared key; keystream XOR as a separate step; GHASH `H` garbled once and
  additively shared; tag via shared H-powers (odd via conversion, even by
  squaring); ciphertext decoded to both, plaintext private to prover; **client
  Finished encrypted in public mode and start-traffic gate**; **server
  Finished and alerts decrypted online**; **application-data records buffered
  and deferred**; at close the joint deferred keystream evaluation runs and the
  verifier releases its recv keystream shares to the prover. **Each party
  stores its own keystream share indexed by `{direction, record_seq,
  byte_offset}`.** GCM concrete pins (below). Record-count budgets enforced.
- **GHASH / GCM pins (also in the M2 golden-vector spec):** GF(2^128) uses the
  **bit-reflected** representation (reduction constant `R = 0x87` in reflected
  form — the endianness trap); tag = `E_k(J0) ⊕ GHASH`, where J0 uses counter
  1 and data counters start at 2; **explicit nonce = record sequence number
  (8 bytes, big-endian)**; **AAD = 13 bytes `seq ‖ type ‖ version ‖ length`**;
  the number of precomputed shared H-powers is sized from the record-count
  budget. Golden vectors must exercise each pin.
- **Boolean→arithmetic bridge for GHASH `H` (load-bearing, silent-failure
  seam).** `H = E_k(0)` is produced by `nt-garble` as **boolean** output bits,
  but all tag/polynomial work happens in the **GF(2^128) arithmetic share
  domain** of `nt-mpc`. Feeding one into the other is a representation handoff
  — the mirror image of M4's arith→boolean PMS bridge, and just as silent when
  wrong: the garbled-`H` output-bit order and the GF(2^128) share domain must
  agree on the **bit-reflected** GCM representation (the `R = 0x87` convention
  above), or every tag is wrong with no crash. M2 tests the share arithmetic
  and M3 tests garbled output, but **nothing tests the seam between them** —
  so a dedicated golden vector checks that a known key's garbled-`H` bits,
  once shared out and recombined in the GF(2^128) domain, reproduce the
  reference GHASH `H` (bit-reflection preserved across the handoff).
- **DoD:** end-to-end request/response with a stock server; deferred decrypt
  yields correct plaintext; verifier holds ciphertext + tags + its keystream
  shares, no full key; record-count-budget undershoot aborts.
- **Invariants:** verifier never obtains plaintext during the session; tag
  authenticates every record; keystream-share release is verifier→prover only,
  from the post-close log-sealed state (the §9 invariant; state machine makes
  earlier release unrepresentable); the verifier never reconstructs any full
  key; **keystream bytes at non-revealed offsets within an AES block are never
  opened.**
- **Tests:** golden vectors (GCM tag/keystream vs. `aes-gcm`, exercising every
  pin; **plus the boolean→arithmetic `H`-bridge vector** — garbled-`H` bits →
  GF(2^128) shares → recombined `H` matches the reference, bit-reflection
  preserved); integration (full session, deferred decrypt); property (tag over
  random record sizes; many small records vs. record budget); negative
  (tampered ciphertext → tag fails; reorder → auth fails; hidden `close_notify`
  in a private record → rejected).
- **Acceptance:** end-to-end to a stock server; verifier holds only
  ciphertext + tags + its keystream shares.
- **Risks:** GHASH share bookkeeping across records — the M2 silent-wrong-tag
  mode compounded; per-record golden vectors required before integration.
- **Observability:** bandwidth + GHASH-share-work + garbled-gate metrics;
  per-record span.
- **Lineage:** AES-CTR keystream via per-block garbled evaluation; GHASH via
  shared H-powers; deferred joint keystream at close.
- **Seam:** post-close hook (empty) for the §14 in-circuit tag verification and
  post-close re-proof.

### M6 — Commitments
- **Goal:** manifest-bound, domain-separated salted-hash byte-range
  commitments over the closed transcript.
- **Crates/modules:** `nt-transcript`, `nt-crypto`, `nt-prover`.
- **Scope:** canonical `TranscriptManifest` derivation on both sides;
  `manifest_hash`; per-span fresh blinders; the **canonical length-prefixed**
  commitment encoding of §10 (never bincode); independent commitments;
  commitment set + blinder store; the prover's byte-range commitment builder.
- **DoD:** both parties derive identical `manifest_hash`; commit/open
  round-trips; a mutated byte/blinder/manifest fails opening.
- **Invariants:** blinders fresh per span, never leave the prover; commitments
  hide short/low-entropy spans; committed ranges are subsets of authenticated
  data; commitment bytes come only from the canonical layout.
- **Tests:** unit (commit/open round-trip, manifest determinism); property
  (open matches iff bytes+blinder+manifest match; disjoint spans independent);
  negative (wrong blinder/bytes/manifest, overlapping ranges).
- **Acceptance:** commit-then-open succeeds for arbitrary range sets; any
  mutation fails.
- **Risks:** low, if the canonical encoding is the single source of committed
  bytes.
- **Observability:** commitment count/size metrics.
- **Lineage:** canonical manifest binding + domain-separated range commitments.
- **Seam:** commitment API + canonical leaf layout shaped so a future Merkle
  tree and the §14 commitment-to-ciphertext proof consume the same
  range/secret structures.

### M7 — Interactive verification
- **Goal:** the interactive prover→verifier proof that revealed ranges are the
  true plaintext of the co-authenticated ciphertext, for the claimed server,
  redacted ranges hidden.
- **Crates/modules:** `nt-prover`, `nt-verifier`, `nt-types`, `nt-transcript`.
- **Scope:** prover reveals selected ranges, their **keystream-share bytes**,
  and blinders; verifier checks (a) session identity (cert chain + handshake
  signature over the ephemeral key, EMS-bound, from M4 state + manifest), (b)
  revealed plaintext matches ciphertext via **retained keystream-share
  opening**: for each revealed offset `i` the prover opens its `ks_P[i]`, the
  verifier combines with its retained `ks_V[i]` and checks
  `pt[i] ⊕ ks_P[i] ⊕ ks_V[i] == ct[i]` (coordinates per §4.5), (c) redacted
  ranges absent; output `SecurityModeBoundTranscript<SemiHonestV0>`. The
  verifier already holds `ks_V` independently (retained from M5), so the check
  has teeth against an honestly-buggy prover. There is **no re-run of the 2PC
  keystream evaluation** — the shares are retained from M5. The verifier
  **never receives a full write key**. Binding against a prover that lies about
  its keystream share is the §14 commitment-to-ciphertext proof; this opening
  step is the `SecurityMode` dispatch point that proof later replaces.
- **DoD:** end-to-end prove/verify over M4–M6 output for a redaction example;
  negative cases rejected; output carries the semi-honest brand.
- **Invariants:** verifier accepts only ranges that open against commitments
  *and* match ciphertext at disclosed offsets; keystream-share bytes at
  redacted offsets never opened; redacted positions marked, never inferred.
- **Tests:** integration (full prove/verify); negative (bad commitment, wrong
  manifest/session binding, wrong keystream share, out-of-range disclosure,
  reordered/replayed/truncated proof messages under the **semi-honest**
  assumption — malicious versions marked deferred); property (any subset of
  committed ranges verifies).
- **Acceptance:** §23 acceptance passes end-to-end for reveal-some/hide-some.
- **Risks:** conflating the semi-honest keystream-share check with a malicious-
  secure binding proof — mitigated by the mode brand and §14 naming.
- **Observability:** per-verify-step span; verification-outcome metric.
- **Lineage:** interactive selective disclosure over co-authenticated
  ciphertext via retained keystream shares.

### M8 — End-to-end, stock-server interop, docs
- **Goal:** a runnable v0: CLI drives prover and verifier; interop against an
  independent stock TLS 1.2 server; full docs; benches; WAN + concurrency
  tests.
- **Crates/modules:** `nt-cli`, `nt-testutil`, all crates' docs.
- **Scope:** runnable prover/verifier binaries; the HTTP/1.1 fixture server;
  criterion benches; WAN-latency+loss harness; many-session concurrency test;
  the docs of §15.
- **DoD:** `nt-cli` completes a notarized session end-to-end **against at least
  one independent, stock, unmodified TLS 1.2 implementation** (not only the
  fixture); benches produce a §16 baseline.
- **Invariants:** default `cargo test` deterministic (seeded); networked/
  non-deterministic tests feature-gated and excluded by default.
- **Tests:** end-to-end (fixture, for determinism); **interop (stock server,
  the acceptance bar)**; concurrency (N sessions); WAN-simulated latency;
  benchmarks.
- **Acceptance:** stock-server interop passes; baseline recorded.
- **Risks:** flaky networked tests — mitigated by feature-gating; interop
  surprises — mitigated by M4/M5 having already tested against a stock server.
- **Observability:** full metric set emitted and sampled in the e2e run.
- **Lineage:** integration of all above.

No "build everything at once" milestone exists by construction.

---

## 14. Where malicious security plugs in later

This section **describes**; v0 pulls in none of these dependencies. Each seam
is where a future `SecurityMode::MaliciousProver` path attaches. The
construction lineage is a **QuickSilver**-style VOLE-ZK with IT-MACs
(QuickSilver, §24; one field element per AND gate; MACs `M = K + x·Δ` over
GF(2^128); a batched random-linear-combination check) — named for lineage
only. These are a **different lineage** from the v0 semi-honest primitives of
M2/M3; do not attach these papers to a v0 milestone.

| Seam | Future check | Construction | Rough cost | Interface host (v0 milestone) |
|---|---|---|---|---|
| Authenticated garbling backend | Malicious-secure boolean 2PC for handshake + record layer | Authenticated garbling behind the `nt-garble` `Evaluator` trait, as a second implementation | Replaces semi-honest garbling wholesale; a few× the gates + MAC traffic | **M3** — the `Evaluator` trait boundary. |
| KOS consistency check | Malicious-secure OT extension | Add the KOS correlation check dropped in v0 | One extra check pass over the extension batch | **M2** — the OT-extension interface. |
| Dual-PMS equality check | Detect inconsistent handshake key shares | Run share conversion twice; check `PMS₀ ⊕ PMS₁ = 0` in-circuit | One extra conversion + a small equality circuit | **M4** — the post-handshake hook. |
| Post-close re-proof + in-circuit tag verification | Re-prove the co-run honestly; authenticate received records from the verifier's side | Post-hoc VOLE-ZK re-execution; recompute J0/GHASH in ZK from shared key wires | One extra pass over the AES/GHASH circuits in ZK | **M5** — the post-close hook + record index. |
| Commitment-to-ciphertext binding | Prove committed plaintext is the true decryption | In-ZK AES-CTR consistency: revealed bytes ⊕ keystream = stored ciphertext | ~one AES-128 circuit per committed block in ZK | **M6** range/blinder structures + **M7** — the keystream-share-opening step is the dispatch point this replaces. |

**Paper lineage per seam (all §24):**
- **Authenticated-garbling backend** → the authenticated-garbling line
  (WRK — Wang-Ranellucci-Katz, and successors). **Not in the connector**;
  cited by standard reference, flagged not-yet-ingested.
- **Malicious OT-extension** → **KOS**'s consistency check (standard reference),
  and/or **Ferret**'s near-free malicious COT check (connector) if the extension
  later moves to the LPN path.
- **Post-close re-proof + in-circuit tag verification** → **QuickSilver** /
  **Wolverine** (connector). The per-record AES/GHASH re-proof re-executes the
  *same* circuit structure across records — a **batched disjunction** — so
  **Batchman/Robin** (connector) is the relevant batching technique, and
  **AntMan** (connector, IT-PAC, sublinear communication) the option for very
  large / SIMD-shaped re-proofs.
- **Commitment-to-ciphertext binding** → **QuickSilver** (connector).
- **Dual-PMS equality check** → a protocol-specific construction (run share
  conversion twice, equality-check in-circuit); no single originating paper.

**Cross-check (milestones vs. seams):** every deferred check lands in a slot an
earlier milestone defines — M2's OT-extension interface, M3's `Evaluator`
trait, M4's post-handshake hook, M5's post-close hook and record index, M6's
range/blinder structures, M7's keystream-share dispatch point. None needs a
slot an earlier milestone fails to provide; the shared §4.5 coordinates let the
M6/M7-hosted binding proof address the same bytes as M5's records.

Only when a malicious-security milestone begins would a VOLE-ZK dependency
enter the tree.

---

## 15. Documentation requirements

Docs live next to code. Required:
- `/docs`: this plan; a protocol spec (phases, messages, state machines, the
  §3 profile, the manifest); a roles-and-phases explainer; a glossary (PMS,
  share conversion, OLE, OT extension, garbled circuit, half-gate, GHASH
  powers, blinder, redaction, ephemeral key, EMS, manifest); test-vector docs
  (what each golden vector covers and its source — RFC/standard, not a
  reference repo).
- Crate-level docs stating each crate's one responsibility and invariants.
- Public-API docs with misuse warnings on secret-bearing types and on the
  `SecurityMode` seam ("v0 is semi-honest; do not present as malicious-
  secure").
- Diagrams: the full-session sequence (setup → handshake → records → commit →
  verify) and the record-layer share flow.
- A **security-assumptions** page: the v0 threat model, with a prominent
  pointer to §14 for what is *not* defended, and to §21's invalidating
  assumptions.

---

## 16. Performance requirements

**Measure before optimizing.** Establish M8 benches as a baseline; optimize
only against numbers.

Dimensions: loopback latency; WAN-simulated latency (delay + loss); prover/
verifier CPU; memory by transcript size; bandwidth overhead; commitment size;
concurrent sessions; large-transcript scaling.

Cost decomposition — **freight / couriers / factory**:
- **Freight (bandwidth):** preprocessing correlations dominate — base+extended
  OTs, OLE, garbled-circuit material. Measure bytes moved per declared
  byte/record budget.
- **Couriers (round trips):** handshake and request-send sit **inside the
  live-server window** and are latency-critical; count round trips there
  ruthlessly. Setup and post-close commitment/verification are **outside** the
  window.
- **Factory (local compute):** **SHA-256-in-2PC is the dominant compute cost
  — a full key derivation + verify-data is ~28 SHA-256 compressions ≈ 630k AND
  gates, ahead of share conversion.** Then AES-CTR block garbling, GF(2^128)
  squaring for even GHASH powers, hashing for commitments.

Instrument each hotspot: **SHA-256 compression count and garbled-gate
throughput first**, then share conversion (correlations/sec, latency), GHASH
share work (field ops/record), OT-extension and preprocessing bandwidth (bytes
vs. declared budgets). Flag in telemetry which phase is inside vs. outside the
live-server window.

The reduced/low-bandwidth PRF (roughly halving 2PC compressions by revealing
intermediate PRF hashes) is a **future flagged option with a stated privacy
cost**, not in v0 (§2, §20).

**Deferred bandwidth optimization — LPN correlated OT.** v0's OT extension is
IKNP/KOS (M2), whose preprocessing bandwidth is linear in the OT count. A
future optimization replaces it with **Ferret**-style LPN-based correlated OT
(§24, connector), which makes correlated-OT communication sublinear — the main
lever on the "freight" cost above. It is deliberately **out of v0** (kept off
the M2 path for auditability, §20); noted here only as the known bandwidth
lever. Ferret's separate near-free malicious COT check belongs to §14, not
here.

---

## 17. Testing strategy

Designed in per milestone, not bolted on.

- **Unit:** serialization, encoding, transcript slicing, commitments,
  redaction, state transitions.
- **Property (`proptest`):** transcript ranges, serde round-trips, commitment
  open-consistency, redaction boundaries, invalid-input rejection, A2M/M2A
  round-trip, manifest determinism.
- **Negative:** malformed proofs, bad commitments, wrong manifest/session
  binding, wrong keystream shares, invalid disclosure ranges. For reordered/
  replayed/truncated inputs, test correct behavior **under the semi-honest
  assumption**; mark malicious versions **deferred**.
- **Golden vectors (gating, before integration of each layer):** AES-CTR,
  GHASH (every GCM pin), HKDF/PRF (EMS path), P-256; **garbled AES-128 and
  garbled SHA-256 vs. plain references**; commitments.
- **Integration:** prover/verifier flows per phase.
- **End-to-end:** local deterministic session.
- **Differential — standard-TLS layer only:** the joint client produces a
  handshake and records a **stock, unmodified TLS 1.2 server** accepts.
  TLSN-artifact differential testing is **N/A for v0** — no portable artifact
  exists to diff.
- **Interop (acceptance bar, M8):** at least one independent stock TLS 1.2
  implementation, not only the fixture.
- **Fuzz (`cargo-fuzz`):** parsers, wire messages, transcript decoding,
  verification inputs.
- **Benchmarks (`criterion`):** latency, bandwidth, memory, transcript
  scaling, commitment/verification cost.
- **WAN-simulated / concurrency:** artificial latency + loss; many sessions.
- **Determinism:** seeded RNG by default; networked tests feature-gated,
  excluded from default runs.

**Privacy is not tested by these.** Golden vectors and property tests catch
wrong **output**, not **leakage**: a reused blinder, a non-oblivious OT, or an
over-revealing keystream share passes every vector. v0's privacy properties
(can't-learn redaction, share hiding) are established by **argument and
targeted code review**, not automated tests. Named review checklist (§18):
- blinder generation and lifetime (fresh per span, never sent for redacted
  spans),
- OT obliviousness (receiver choice bits never leak to sender),
- keystream-share opening (only revealed offsets; never a whole block; the
  verifier holds only `ks_V` per the §5 per-direction holder table, both
  directions),
- key-share vs. keystream-share release ordering (post-close only; no full key
  reconstructed by the verifier),
- logging/serialization boundary lists (§10).
Do **not** claim tested privacy.

---

## 18. Clean-room posture and hygiene

This plan is reference-informed but the implementation is **clean-room from an
independently written spec**. Binding rules for the implementing agent:
- **Allowed sources:** RFCs and standards (TLS 1.2 RFC 5246, EMS RFC 7627, GCM
  SP 800-38D, P-256 FIPS 186), academic papers (OT extension, half-gate
  garbling, OLE/share conversion), primitive-crate documentation, and this
  plan.
- **Disallowed:** copying code, APIs, tests, or fixture vectors from any
  TLSN/MPC reference repository; copying crate or module names from a reference
  unless generic (`prover`, `verifier`, `transcript` are generic; a reference's
  bespoke names are not).
- Every nontrivial protocol decision carries a citation or a derivation note in
  code or `/docs`.
- Golden vectors are generated from standards/primitive crates (`aes`, `sha2`,
  `aes-gcm`, `p256`), never lifted from a reference repo.

**Citation discipline (two places).**
- **The plan** cites a paper where a construction *originates* or where v0
  *deliberately diverges* from it — e.g. M2 cites KOS but records that v0 omits
  KOS's malicious correlation check. Citations live in the milestone lineage
  lines and in §14/§16, and are collected in **§24**.
- **The code** cites, in each module's top-level doc comment, the paper the
  module's idea came from: **paper short-name + what was taken + what was
  simplified** (e.g. `nt-ot`: "IKNP/KOS OT extension; took the correlated-OT
  construction; simplified by omitting KOS's consistency check — see §14").
- **Scoping rule (do not miscite):** the v0 semi-honest data path and the §14
  malicious-secure future are **different lineages**. Semi-honest-primitive
  papers (IKNP, KOS, Chou-Orlandi, Gilboa, half-gate, free-XOR) attach to
  M2/M3; the VOLE-ZK family (QuickSilver, Wolverine, AntMan, Batchman/Robin)
  and authenticated garbling attach to §14 **only**. Never attach a
  malicious-secure VOLE-ZK paper to a v0 milestone.

---

## 19. Tooling to create (fresh repository)

The repository is empty; this tooling is an **M1 deliverable**, not a
pre-existing fixture.

- **`rustfmt.toml`:** `imports_granularity = "Crate"`, `wrap_comments = true`.
  Formatting runs on **nightly** (`cargo +nightly fmt`) because
  `imports_granularity` is a nightly rustfmt feature.
- **CI (`.github/workflows/ci.yml`):** pin a `RUST_VERSION`; run
  `cargo clippy --all-features --all-targets --locked -- -D warnings`,
  `cargo +nightly fmt --check --all`, `cargo build --all-targets --locked`,
  and `cargo test --locked`. New crates must build clean under `-D warnings`
  and pass nightly `fmt --check`.
- **`pre-commit-check.sh`:** fmt + clippy + build + test, mirroring CI.
- **`Cargo.lock`:** committed; build and test with `--locked`.
- No markdown linter is assumed; if one is wanted, add it to CI explicitly.

Do not invent tooling beyond this shape.

---

## 20. Non-goals for v0

Explicitly out of scope (each deferred, not forgotten):
- Malicious-prover security (→ the configurable mode, §14).
- Malicious-secure hardening: authenticated garbling, KOS consistency check,
  Ferret's malicious COT check, dual-PMS check, in-circuit tag verification,
  DEAP-style dual execution (§14).
- LPN-based correlated OT (Ferret-core) as a bandwidth optimization — the M2
  OT extension stays on the IKNP/KOS path (§16).
- Portable notary-signed attestation and a presentation/verify split.
- HTTP-aware / JSON-field commitments (v0 is byte ranges).
- Online (non-deferred) decryption of application data.
- The reduced/low-bandwidth PRF variant (future flagged option, §16).
- Browser extension; mobile; production deployment; production key management.
- TLS versions other than 1.2; suites, curves, or profile parameters outside
  §3.
- Arbitrary web-app UX.
- Any external ZK/MPC framework dependency.
- Day-one parity with every reference feature.

Where scope is contested, the recommendation is the **narrow v0 that proves
the core architecture first**.

---

## 21. Assumptions that would invalidate the design if wrong

If any entry here is false, a stated guarantee fails.

1. **The semi-honest prover assumption holds in deployment.** Everything in
   §5's "defer" column depends on it; against an adversarial prover, v0's
   output proves nothing until §14.
2. **The verifier never obtains both shares of any write key, nor `ks_P` (nor
   the full keystream) at any redacted offset, in either direction.** The whole
   can't-learn redaction argument (§5, and its per-direction holder table)
   rests on this — including the sent direction, where the prover independently
   knows the full keystream but the verifier holds only `ks_V`. Any "let the
   verifier just decrypt and check" shortcut converts privacy into won't-look.
3. **The garbled-circuit engine is correct.** It now carries the PRF (M4) and
   the record layer (M5); a half-gate/free-XOR bug is silent (wrong keys or
   wrong keystream, not a crash). The M3 golden-vector gate is the control;
   removing it invalidates the correctness story.
4. **Keystream-share retention preserves reveal-once and nonce discipline.**
   The prover's keystream share is the one-time pad hiding plaintext; per-record
   GCM nonce uniqueness (explicit nonce = seq) plus opening each keystream-share
   byte at most once (M7) make it *one-time*. Reuse or double-open breaks TLS
   security and redaction at once.
5. **The GF(2^128) share arithmetic is bit-for-bit GHASH-correct** (bit-
   reflected representation, `R = 0x87`). A silent error (M2) yields wrong
   tags; the golden-vector gate is the control.
6. **The keystream-share release happens strictly after close + log-seal**
   (§9). Earlier release collapses co-authentication; the typed state machines
   are the enforcement, so a refactor that flattens them invalidates the
   design.
7. **Domain-separated commitments are hiding for short, low-entropy spans**
   (hash as PRF/random oracle, ≥16-byte blinder, canonical layout). Weaken any
   and commitments to auth tokens leak by dictionary attack.
8. **The combined ephemeral key is indistinguishable from a normal client's.**
   Mathematically true; the operational half — handshake timing/fingerprint
   don't make the joint client blockable — must be re-checked against real
   servers (M4/M8 stock-server tests).
9. **EMS is negotiable with target servers, and they keep accepting the §3
   profile.** EMS is mandatory (hard abort otherwise); if targets disable the
   profile, v0 has no subject matter, and TLS 1.3 is a design change (new key
   schedule and record layer), not a patch.

---

## 22. Plan assumptions

Everything guessed, stated plainly:
- **The target is a fresh, empty repository.** All crates, tooling, and CI are
  milestone deliverables; nothing pre-exists.
- **Crate names** (`nt-*`) are proposals; the implementing agent may rename,
  subject to the clean-room naming rule (§18).
- **`bincode` v2, length-delimited framing, hand-rolled TLS 1.2 client** are
  recommendations (§4), not mandates.
- **AND-gate counts** (AES-128 ~6.4k; SHA-256 ~22.6k/compression; key
  derivation ~630k) are standard Bristol/PRF figures for cost intuition.
- **The fixture and interop servers** are stock, unmodified TLS 1.2 servers
  supporting the §3 profile.
- **`webpki`/`rustls` primitives** are acceptable for cert-chain validation
  despite the hand-rolled client, because X.509 path building is out of scope
  to reimplement.
- The **semi-honest / honest-but-curious model** is fixed per §2; every "defer"
  in §5 depends on it.

---

## 23. Acceptance test for this plan

> **A reviewer familiar with notarized-TLS systems must be able to take any
> such feature and either find where in the milestones it lands, or find it
> explicitly in non-goals.**

Satisfied by construction:
- **In the milestones:** types/transcript/manifest → M1; crypto adapters,
  share conversion, OT extension → M2; boolean-2PC garbled-circuit engine →
  M3; three-party handshake, PMS shares, arith→bool bridge, EMS, PRF-in-2PC →
  M4; 2PC AES-GCM record layer, GHASH-via-shares, deferred app-data decryption,
  keystream retention, Finished sequencing, record-count budgets, close status
  → M5; manifest-bound domain-separated commitments → M6; interactive selective
  disclosure via keystream-share opening, session-identity binding → M7;
  end-to-end, stock-server interop, docs → M8.
- **In non-goals / deferrals:** malicious-prover security, authenticated
  garbling, KOS check, dual-PMS check, in-circuit tag verification, DEAP →
  §20 + §14; portable attestation and presentation/verify split → §20 + §14
  (interfaces preserved); HTTP/JSON-field commitments → §20; online app-data
  decryption → §20; reduced PRF variant → §20 + §16; Merkle-tree commitments,
  notary signing, browser extension, other TLS versions/suites/profile params →
  §20.

Any feature not in a milestone is deliberately in §20; any mechanism in a
milestone names the construction it reproduces (§13 lineage lines), making
"avoid obvious architectural mistakes" a checkable property.

---

## 24. References

Two lineages, kept separate (§18 scoping rule): **v0 semi-honest primitives**
(M2/M3) and the **§14 malicious-secure future**.

### v0 semi-honest primitives — standard references (not yet in the connector)

These are cited by standard reference pending ingestion; **do not fabricate
docIds for them.**
- **IKNP** — Ishai, Kilian, Nissim, Petrank, "Extending Oblivious Transfers
  Efficiently," CRYPTO 2003. *(M2 OT extension, semi-honest.)*
- **KOS** — Keller, Orsini, Scholl, "Actively Secure OT Extension with Optimal
  Overhead," CRYPTO 2015. *(M2 uses its construction; v0 omits its malicious
  correlation check — that check is a §14 seam.)*
- **Chou-Orlandi** — Chou, Orlandi, "The Simplest Protocol for Oblivious
  Transfer," LATINCRYPT 2015. *(M2 base OT.)*
- **Gilboa** — Gilboa, "Two Party RSA Key Generation," CRYPTO 1999. *(M2
  OLE-from-OT bit-decomposition.)*
- **half-gate** — Zahur, Rosulek, Evans, "Two Halves Make a Whole: Reducing
  Data Transfer in Garbled Circuits using Half Gates," EUROCRYPT 2015. *(M3.)*
- **free-XOR** — Kolesnikov, Schneider, "Improved Garbled Circuit: Free XOR
  Gates and Applications," ICALP 2008. *(M3.)*
- **authenticated garbling (WRK)** — Wang, Ranellucci, Katz, "Authenticated
  Garbling and Efficient Maliciously Secure Two-Party Computation," CCS 2017.
  *(§14 malicious garbling backend; not yet in the connector.)*

### §14 malicious-secure future — connector papers (with docIds)

Cite here and **only** here (never on a v0 milestone).
- **QuickSilver** — docId `1783051233072-cwhczx`. The stated §14 lineage: 1
  field element/AND gate, IT-MACs `M = K + x·Δ` over GF(2^128), batched RLC
  check. *(Post-close re-proof; commitment-to-ciphertext binding.)*
- **Wolverine** — docId `1783060460386-1b6hqh`. Subfield-VOLE authenticated
  triples; the scalable precursor. *(Post-close re-proof.)*
- **AntMan** — docId `1783060440324-wvzqfz`. IT-PAC, sublinear communication;
  the SIMD/large-circuit option for the re-proof.
- **Batchman/Robin** — docId `1783060400655-a7vfuh`. Batched disjunctions;
  cited because the per-record AES/GHASH re-proof re-executes one circuit
  structure across records — exactly a batched disjunction.
- **Ferret** — docId `1783060450360-xa54lv`. LPN-based correlated OT. Its
  **LPN-COT core** is a **future bandwidth optimization** (§16), *not* a v0
  primitive; its **near-free malicious COT check** is a §14 seam.

### Still processing — do not cite until ingested

Placeholder; ingestion pending, no docIds usable yet: `964.pdf`, `996.pdf`,
`popets-2025-0028.pdf`.
