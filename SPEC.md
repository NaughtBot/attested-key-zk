# Approval Proof V1 Spec

This library proves the following statement:

> There exists a hidden P-256 device public key `(dpk_x, dpk_y)` such that:
> 1. a trusted issuer public key signed `AttestationV1`,
> 2. `AttestationV1` contains `(dpk_x, dpk_y)` and the expected public policy fields,
> 3. `(dpk_x, dpk_y)` signed `ApprovalAssertionV1`, and
> 4. `ApprovalAssertionV1` binds the proof to the verifier and request context.

All integer encodings are fixed-width big-endian.

## Signatures

Both signatures are raw 64-byte `r || s` values:

- `attestation_sig[0..31]`: `r`
- `attestation_sig[32..63]`: `s`
- `approval_assertion_sig[0..31]`: `r`
- `approval_assertion_sig[32..63]`: `s`

Both signatures are over `SHA-256(message_bytes)`.

## AttestationV1

Length: 136 bytes

| Offset | Length | Field |
| --- | ---: | --- |
| 0 | 16 | domain = `AKZK-ATTEST-KEY1` |
| 16 | 32 | `app_id_hash` |
| 48 | 4 | `policy_version` |
| 52 | 1 | `key_class` |
| 53 | 3 | reserved = zero |
| 56 | 8 | `not_before` |
| 64 | 8 | `not_after` |
| 72 | 32 | `device_pk_x` |
| 104 | 32 | `device_pk_y` |

`key_class = 1` means “issuer attests this is a secure-hardware-backed P-256
key”.

## ApprovalAssertionV1

Length: 120 bytes

| Offset | Length | Field |
| --- | ---: | --- |
| 0 | 16 | domain = `AKZK-APPROVAL-V1` |
| 16 | 32 | `challenge_nonce` |
| 48 | 32 | `audience_hash` |
| 80 | 32 | `approval_hash` |
| 112 | 8 | `expires_at` |

## Field semantics

### `challenge_nonce`

A fresh, unpredictable 32-byte challenge chosen by the verifier. This is the main anti-replay value. A proof for one nonce is useless for another nonce.

### `audience_hash`

A 32-byte hash that identifies the verifier or relying party. Typical input is a stable verifier identifier such as a domain name, service identifier, or verifier public key. This prevents a proof produced for verifier A from being replayed to verifier B.

### `approval_hash`

Yes: this should be the hash of the verifier’s canonical challenge/request object.

Recommended input:

```text
approval_hash = SHA256(canonical_request_bytes)
```

The canonical request should contain everything the verifier wants the device to sign beyond the bare nonce and audience binding, for example:

- requested action
- relying-party-specific context
- channel binding
- expiry or issuance time
- statement text or payload hash

`challenge_nonce` and `audience_hash` stay separate even if they are also inside the canonical request, because they are the two most important binding fields and are useful to reason about independently.

## Public statement

The verifier sees:

- issuer public key `(issuer_pk_x, issuer_pk_y)`
- `app_id_hash`
- `policy_version`
- `now`
- `challenge_nonce`
- `audience_hash`
- `approval_hash`

The verifier does **not** see:

- `device_pk_x`
- `device_pk_y`
- the raw `AttestationV1`
- the raw `ApprovalAssertionV1`

## Time handling

- The proof enforces `not_before <= now <= not_after`.
- The proof enforces `now <= expires_at`.

`now` is supplied by the verifier as an 8-byte big-endian `uint64`.

## Statement wire format

The public statement is a fixed-width 204-byte struct passed across the C
ABI as `ApprovalProofV1Statement` (or its byte-oriented variant taken by
`run_approval_proof_v1_verifier_from_bytes`).

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 32 | `issuer_pk_x` |
| 32 | 32 | `issuer_pk_y` |
| 64 | 32 | `app_id_hash` |
| 96 | 4 | `policy_version` |
| 100 | 8 | `now` |
| 108 | 32 | `challenge_nonce` |
| 140 | 32 | `audience_hash` |
| 172 | 32 | `approval_hash` |

Total: 204 bytes. Offsets are asserted by `static_assert(offsetof(...))`
in `src/approval_proof_v1_zk.cc`; a struct reorder that preserved size but
shuffled fields would fail the build.

## ProverInput wire format

The prover takes a fixed-width 588-byte struct as `ApprovalProofV1ProverInput`
(or its byte-oriented variant taken by `run_approval_proof_v1_prover_from_bytes`).

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 204 | `statement` (see above) |
| 204 | 136 | `attestation` (see *AttestationV1*) |
| 340 | 64 | `attestation_sig` (raw `r || s`) |
| 404 | 120 | `approval_assertion` (see *ApprovalAssertionV1*) |
| 524 | 64 | `approval_assertion_sig` (raw `r || s`) |

Total: 588 bytes. Offsets are similarly enforced by `static_assert`.

## key_class and reserved bytes

`key_class = 1` (`kApprovalProofV1KeyClassSecureHardwareP256`) is the only
value the in-circuit assertion currently accepts. Future spec revisions
that admit other classes (e.g. attested software keys) must bump
`kProofVersion` and update the in-circuit assertion at the same time.

The 3 bytes at attestation offset 53–55 are reserved-zero. The in-circuit
assertion rejects any non-zero value, so existing proofs cannot smuggle
unexpected bits into a future revision that re-uses these bytes.

## policy_version

Encoded as a 4-byte big-endian `uint32`. Today only `policy_version = 1`
is in use; the in-circuit assertion compares the witnessed
`AttestationV1.policy_version` against the public-statement
`policy_version` byte-for-byte, so a proof issued for one version cannot
satisfy a verifier that expects a different version. Choosing a higher
number for a future, less-strict policy is the recommended pattern.

## Proof version (`kProofVersion`)

The library embeds `kProofVersion = 7` (`src/approval_proof_v1_zk.cc:60`)
into the Fiat-Shamir transcript at both the prover and verifier. Today
the value is *stored but never read* by the vendored longfellow-zk
verifier (`Transcript::version_` exists at
`third_party/longfellow-zk/lib/random/transcript.h:76-77` but no read
site is reachable from `verifier.verify()`), so a future bump of
`kProofVersion` will surface as a generic `VERIFICATION_FAILURE` rather
than a distinguishable version-mismatch error.

The value is wire-format-reserved: callers and verifiers must not expect
to interoperate across different `kProofVersion` values, even though the
mismatch is currently caught only via transcript divergence.

### When to bump `kProofVersion`

Any change that would make a proof produced by the previous code fail
verification under the new code (or vice versa) is a wire-format change
and MUST bump `kProofVersion`. The intent is that two implementations
that share a `kProofVersion` value are guaranteed to interoperate, and
two that disagree are guaranteed not to.

Bump `kProofVersion` for any of:

- A change to the Fiat-Shamir transcript domain separator — either the
  label bytes (`kTranscriptLabel`) or the absorbed label length
  (`kTranscriptLabelLen`).
- A change to in-circuit constants that alter the proof bytes: curve
  generator coordinates (`kRootX`/`kRootY`), the `key_class` enum value,
  attestation/approval domain tags, padding constants, or any other
  value baked into the witness or the circuit polynomial.
- A change to the order, types, or count of fields written to the
  transcript on either side.
- A change to the underlying ZK parameters
  (`kApprovalProofV1LigeroRate`, `kApprovalProofV1LigeroNreq`, hash
  function, field, or commitment scheme).
- A structural change to the witness layout (added/removed/reordered
  witness wires, changed bit-decomposition widths, etc.).

Do **not** bump `kProofVersion` for:

- Prover-only optimizations that produce byte-identical proof output.
- Comment, whitespace, or documentation changes.
- Refactors (rename, file move, helper extraction) whose net effect on
  the proof bytes and transcript trace is provably nil — confirm via the
  end-to-end prover→verifier round-trip in CI.

> **Historical note (L1).** Before launch, the `Transcript` constructor
> at both call sites was passing `length=7` for the 17-byte label
> `"approval_proof_v1"`, so only `"approval"` was absorbed. The fix
> (`kTranscriptLabel` / `kTranscriptLabelLen`, both used at prover and
> verifier) is a wire-format change that would normally require a
> `kProofVersion` bump under the rules above, but was landed before any
> proofs from the broken label were ever published, so no existing
> proofs need to verify. After the first public release, every change
> in the lists above is a hard bump.

## Ligero parameters

The proof system uses Ligero with the following parameters from
`include/attested_key_zk/approval_proof_v1_zk.h`:

| Constant | Value | Meaning |
| --- | ---: | --- |
| `kApprovalProofV1LigeroRate` | 7 | Reed-Solomon code expansion rate |
| `kApprovalProofV1LigeroNreq` | 132 | Number of column queries |

Both prover and verifier must agree on these parameters; they are
hard-coded into both call sites at
`src/approval_proof_v1_zk.cc:620, :689`. A separate audit of the soundness
implications of these specific values is *out of scope for this spec*
(see audit master plan, "Out of scope" section).

## Canonical circuit identity

The library exposes a 32-byte canonical id constant:

```c
extern const uint8_t kApprovalProofV1ExpectedCircuitId[32];
```

defined in `src/approval_proof_v1_zk.cc`. The four prove/verify C-ABI
entry points re-compute the id from the parsed circuit structure and
reject `circuit_bytes` whose digest does not match this constant; a
relying-party verifier therefore cannot be tricked into "verifying" a
proof against a substitute circuit (e.g. one with weakened time-window
assertions).

`approval_proof_v1_circuit_id(out_id, circuit_bytes, circuit_len)` is
exposed for callers that want to compute the digest themselves; it
returns the typed enum `ApprovalProofV1CircuitIdErrorCode` as of
remediation H1/V7.

A regression test (`canonical_circuit_id_matches_constant` in
`tests/approval_proof_v1_zk_test.cc`) recomputes the id at every CI run
and asserts equality with the constant, so a circuit change that alters
the digest fails the build before it ships.

## Transcript domain separation

The Fiat-Shamir transcript is initialized with the constant label
`kTranscriptLabel = "approval_proof_v1"` (17 bytes) at both the prover
and verifier construction sites in `src/approval_proof_v1_zk.cc`. The
label and its absorbed length are defined as a single named pair
(`kTranscriptLabel`, `kTranscriptLabelLen = sizeof(kTranscriptLabel) - 1`)
so a future literal/length drift cannot reintroduce the L1 bug.

Any change to the label bytes or length is a wire-format change and
MUST bump `kProofVersion`; see "When to bump `kProofVersion`" above.

## Input length caps

The C-ABI rejects oversized inputs before any parser runs:

| Constant | Value |
| --- | ---: |
| `kApprovalProofV1MaxCircuitBytes` | 64 MiB |
| `kApprovalProofV1MaxProofBytes` | 1 MiB |

`circuit_len > kApprovalProofV1MaxCircuitBytes` (or the analogous proof
cap) returns the `*_INPUT_TOO_LARGE` enumerator from the relevant entry
point, preventing reachable `abort()` paths inside the vendored
longfellow-zk parser from crashing the host process. Caps are sized
~3-4× the legitimate value of a freshly built circuit (~18 MiB) and proof
(~285 KiB).
