# Bindings

This repository ships three wrapper layers on top of the core C API:

- `bindings/go`: Go package using `cgo`
- `bindings/swift`: Swift wrapper sources and tests for the repo-owned SwiftPM package
- `bindings/wasm`: TypeScript wrapper around a browser + Node Emscripten build

All three bindings use the same fixed-width binary encodings:

- `ApprovalProofV1Statement`: 204 bytes
- `ApprovalProofV1ProverInput`: 588 bytes

## Native prerequisite

Build the core library first:

```bash
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release
cmake --build build -j
```

That produces `build/libattested_key_zk.a`, which the Go binding links against
locally.

## Go

The Go module path is:

```text
github.com/naughtbot/attested-key-zk/bindings/go
```

```bash
cd bindings/go
go test ./...
```

## Swift

```bash
make test-spm-layout
swift test
```

The consumer-facing Swift package lives at the repository root. Build
`AttestedKeyZKApple.artifactbundle` first with `make artifactbundle-apple`
or build both platform-specific bundles with `make artifactbundle`.
The Makefile creates a placeholder opposite-platform bundle when needed so
SwiftPM can resolve the package on a host that only has one platform toolchain.

## TypeScript / WASM

The WASM binding targets both browsers and Node and requires Emscripten
(`emcc`) to be installed.

The crypto support is browser-safe:

- SHA-256 is implemented in the WASM support layer
- AES-256-ECB PRF is implemented in the WASM support layer
- randomness uses `globalThis.crypto.getRandomValues(...)` when available,
  with a Node fallback

```bash
cd bindings/wasm
./scripts/build-wasm.sh
corepack enable
pnpm install --frozen-lockfile
pnpm build
pnpm smoke
```
