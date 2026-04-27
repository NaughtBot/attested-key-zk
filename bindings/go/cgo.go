//go:build cgo

package attestedkeyzk

/*
#cgo CPPFLAGS: -DOPENSSL_SUPPRESS_DEPRECATED=1
#cgo CPPFLAGS: -D_FORTIFY_SOURCE=2
#cgo CPPFLAGS: -D_GLIBCXX_ASSERTIONS
#cgo CPPFLAGS: -I${SRCDIR}/include
#cgo CPPFLAGS: -I${SRCDIR}/third_party/longfellow-zk/lib
#cgo CXXFLAGS: -std=c++17 -fPIC
#cgo CXXFLAGS: -fstack-protector-strong
#cgo CXXFLAGS: -fvisibility=hidden
#cgo darwin CPPFLAGS: -I/opt/homebrew/opt/openssl@3/include
#cgo darwin LDFLAGS:  -L/opt/homebrew/opt/openssl@3/lib -lcrypto
#cgo linux  LDFLAGS:  -lcrypto -lstdc++ -lm
#include "attested_key_zk/approval_proof_v1_zk.h"
*/
import "C"

// Hardening above is the subset of GAMMA-1 flags that pass cgo's CXXFLAGS
// allowlist (cmd/go/internal/work/security.go). Arch-specific flags
// (-fcf-protection=full, -mbranch-protection=standard, -fstack-clash-protection)
// were added to the allowlist in newer Go releases and are deliberately omitted
// here so the module remains buildable on the Go versions our consumers use.
// -Werror / -Wall / -Wextra are also omitted: they would fire on the vendored
// longfellow-zk sources that this module compiles alongside src/. The CMake
// build retains all of these via SYSTEM-include scoping; cgo has no equivalent.

import (
	"runtime"
	"unsafe"
)

func GenerateCircuit() ([]byte, error) {
	var circuitPtr *C.uint8_t
	var circuitLen C.size_t
	code := C.generate_approval_proof_v1_circuit(&circuitPtr, &circuitLen)
	if code != C.APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS {
		return nil, &StatusError{
			Domain:  "circuit",
			Code:    int(code),
			Message: C.GoString(C.approval_proof_v1_circuit_generation_error_string(code)),
		}
	}
	defer C.approval_proof_v1_free(unsafe.Pointer(circuitPtr))
	return C.GoBytes(unsafe.Pointer(circuitPtr), C.int(circuitLen)), nil
}

func Prove(circuit []byte, input ProverInput) ([]byte, error) {
	inputBytes := input.MarshalBinary()
	var proofPtr *C.uint8_t
	var proofLen C.size_t
	code := C.run_approval_proof_v1_prover_from_bytes(
		bytePtr(circuit), C.size_t(len(circuit)),
		bytePtr(inputBytes), C.size_t(len(inputBytes)),
		&proofPtr, &proofLen)
	runtime.KeepAlive(circuit)
	runtime.KeepAlive(inputBytes)
	if code != C.APPROVAL_PROOF_V1_PROVER_SUCCESS {
		return nil, &StatusError{
			Domain:  "prover",
			Code:    int(code),
			Message: C.GoString(C.approval_proof_v1_prover_error_string(code)),
		}
	}
	defer C.approval_proof_v1_free(unsafe.Pointer(proofPtr))
	return C.GoBytes(unsafe.Pointer(proofPtr), C.int(proofLen)), nil
}

func Verify(circuit []byte, statement Statement, proof []byte) error {
	statementBytes := statement.MarshalBinary()
	code := C.run_approval_proof_v1_verifier_from_bytes(
		bytePtr(circuit), C.size_t(len(circuit)),
		bytePtr(statementBytes), C.size_t(len(statementBytes)),
		bytePtr(proof), C.size_t(len(proof)))
	runtime.KeepAlive(circuit)
	runtime.KeepAlive(statementBytes)
	runtime.KeepAlive(proof)
	if code != C.APPROVAL_PROOF_V1_VERIFIER_SUCCESS {
		return &StatusError{
			Domain:  "verifier",
			Code:    int(code),
			Message: C.GoString(C.approval_proof_v1_verifier_error_string(code)),
		}
	}
	return nil
}

func CircuitID(circuit []byte) ([HashLength]byte, error) {
	var out [HashLength]byte
	code := C.approval_proof_v1_circuit_id(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		bytePtr(circuit), C.size_t(len(circuit)))
	runtime.KeepAlive(circuit)
	if code != C.APPROVAL_PROOF_V1_CIRCUIT_ID_SUCCESS {
		return out, &StatusError{
			Domain:  "circuit_id",
			Code:    int(code),
			Message: C.GoString(C.approval_proof_v1_circuit_id_error_string(code)),
		}
	}
	return out, nil
}

func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
