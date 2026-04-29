# Attested Key ZK

Proof/verify wrapper for a fixed-layout P-256 attested-key statement built on top of https://github.com/google/longfellow-zk

## Layout

- `third_party/longfellow-zk`: upstream git submodule
- `include/attested_key_zk/approval_proof_v1_zk.h`: public C API
- `src/approval_proof_v1_zk.cc`: fixed-layout circuit and proof wrapper
- `tests/approval_proof_v1_zk_test.cc`: end-to-end proof/verify tests
- `SPEC.md`: wire-format specification for `AttestationV1` and
  `ApprovalAssertionV1`

## Build

```bash
git submodule update --init --recursive
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The Makefile wraps the same flow:

```bash
make test-core
make test-go
make test-swift      # requires Swift and Apple artifact tooling
make test-wasm       # requires Emscripten, Node, and pnpm through corepack
```

## SwiftPM packaging

The repo-owned SwiftPM entrypoint is now the root [Package.swift](./Package.swift),
mirroring the `bbs-ffi` pattern:

- `make artifactbundle-apple`: build the Apple static libraries and package
  both `AttestedKeyZKApple.artifactbundle` and
  `AttestedKeyZKApple.xcframework`
- `make artifactbundle-android`: build the Android static libraries and package
  `AttestedKeyZKAndroid.artifactbundle`
- `make artifactbundle`: build both platform-specific bundles
- `make test-swift`: validate the artifact bundle layout, then run the Swift
  tests against the packaged binary target

The Apple XCFramework and Android artifact bundle are committed so clients can
consume `https://github.com/NaughtBot/attested-key-zk` directly as a Swift
package. The Apple artifact bundle remains a build/release staging format used
to assemble the XCFramework. When a platform bundle is rebuilt locally, the
Makefile can still emit a marked placeholder bundle for the opposite platform so
SwiftPM can resolve the package graph on Apple-only or Android-only hosts.
Running the real platform-specific prep target later replaces that placeholder
with a real bundle.

Swift consumers should depend on `attested-key-zk/` directly rather than the
nested `bindings/swift` folder, so the shared wrapper no longer needs local
`-L ../../build` linker flags and SwiftPM resolves the Apple or Android binary
target by platform instead of relying on one shared bundle path. Apple app
targets consume `AttestedKeyZKApple.xcframework`; Android SwiftPM builds
consume `AttestedKeyZKAndroid.artifactbundle`.

## API shape

The public API is intentionally small:

- `generate_approval_proof_v1_circuit()`
- `run_approval_proof_v1_prover()`
- `run_approval_proof_v1_verifier()`
- `approval_proof_v1_circuit_id()`

The prover accepts a public `ApprovalProofV1Statement` plus hidden
`AttestationV1`, `ApprovalAssertionV1`, and their raw `r||s` signatures.
The verifier only needs the circuit bytes, the public statement, and the zk
proof.

## Usage flow

1. Your attestation service validates Apple App Attest / Secure Enclave or Android Keystore evidence off-circuit.
2. The service issues `AttestationV1` over the device P-256 public key.
3. The verifier sends a challenge with:
   - `challenge_nonce`: freshness
   - `audience_hash`: audience / relying-party binding
   - `approval_hash`: hash of the canonical challenge object
4. The device signs `ApprovalAssertionV1` and calls
   `run_approval_proof_v1_prover(...)`.
5. The verifier calls `run_approval_proof_v1_verifier(...)`.

Minimal prover/verifier flow:

```c
uint8_t* circuit = NULL;
size_t circuit_len = 0;
generate_approval_proof_v1_circuit(&circuit, &circuit_len);

ApprovalProofV1ProverInput input = {0};
/* fill input.statement, input.attestation, input.attestation_sig,
   input.approval_assertion, input.approval_assertion_sig */

uint8_t* proof = NULL;
size_t proof_len = 0;
run_approval_proof_v1_prover(circuit, circuit_len, &input, &proof, &proof_len);

ApprovalProofV1VerifierErrorCode ok =
    run_approval_proof_v1_verifier(circuit, circuit_len, &input.statement,
                         proof, proof_len);
```

See [SPEC.md](SPEC.md) for the exact byte layout and field semantics.

## Bindings

Language bindings live under [bindings](./bindings):

- [bindings/go](./bindings/go)
- [bindings/swift](./bindings/swift)
- [bindings/wasm](./bindings/wasm)

The Go binding is validated against the local native build. The Swift wrapper
sources still live under `bindings/swift`, but repo-owned SwiftPM consumers
should use the root package and artifact bundle. The TypeScript binding is set
up for a browser + Node Emscripten build and requires `emcc` to be installed
before generating the WASM artifact.

## Releases

Tags matching `v*` run the release workflow. The workflow builds and attaches:

- Linux native archive with `libattested_key_zk.a` and public C headers
- macOS native archive with `libattested_key_zk.a` and public C headers
- Apple SwiftPM XCFramework for macOS, iOS devices, and iOS simulators
- Apple SwiftPM artifact bundle staging archive
- Android SwiftPM artifact bundle for `arm64-v8a` and `x86_64`
- Go binding source archive
- Swift binding source archive
- WASM distribution archive and npm package tarball for
  `@naughtbot/attested-key-zk-wasm`
- `SHA256SUMS` for the uploaded release assets

The workflow builds release archives from source and republishes the SwiftPM
SwiftPM artifacts as zip assets. The source-controlled Apple XCFramework and
Android artifact bundle are the package payload used by Git URL consumers;
transient build directories, release archives, and WASM output remain
uncommitted.
