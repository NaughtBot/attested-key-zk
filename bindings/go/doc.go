// Package attestedkeyzk provides a self-contained Go binding for the
// attested-key-zk approval proof circuit. It vendors all required C++ source
// (see PROVENANCE.md), so consumers need only `go get` plus a system C++17
// compiler and OpenSSL development headers — no separate library install or
// build step.
//
// Build requirements:
//
//   - CGO_ENABLED=1 (default).
//   - A C++17 compiler in PATH (clang++ or g++).
//   - libssl-dev (Linux) or openssl@3 via Homebrew (macOS arm64).
//
// Under CGO_ENABLED=0 the package compiles using stub implementations that
// return [ErrUnavailable] from every operation. This keeps pure-Go binaries
// (e.g. CGO_ENABLED=0 Docker builds) compilable while making the missing
// capability explicit at runtime.
package attestedkeyzk
