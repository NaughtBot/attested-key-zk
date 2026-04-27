package attestedkeyzk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestProveAndVerify(t *testing.T) {
	input := makeInput(t)
	circuit, err := GenerateCircuit()
	if err != nil {
		t.Fatalf("GenerateCircuit: %v", err)
	}
	proof, err := Prove(circuit, input)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if err := Verify(circuit, input.Statement, proof); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestRejectMismatchedNonce(t *testing.T) {
	input := makeInput(t)
	circuit, err := GenerateCircuit()
	if err != nil {
		t.Fatalf("GenerateCircuit: %v", err)
	}
	proof, err := Prove(circuit, input)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	wrong := input.Statement
	wrong.ChallengeNonce[0] ^= 0xff
	if err := Verify(circuit, wrong, proof); err == nil {
		t.Fatal("Verify should fail for mismatched nonce")
	}
}

func TestProverRejectsZeroSignatureScalar(t *testing.T) {
	input := makeInput(t)
	for i := 0; i < 32; i++ {
		input.AttestationSig[i] = 0 // r = 0
	}
	circuit, err := GenerateCircuit()
	if err != nil {
		t.Fatalf("GenerateCircuit: %v", err)
	}
	_, err = Prove(circuit, input)
	if err == nil {
		t.Fatal("Prove should reject r=0 attestation signature")
	}
	se, ok := err.(*StatusError)
	if !ok {
		t.Fatalf("expected *StatusError, got %T: %v", err, err)
	}
	// APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE = 9
	if se.Code != 9 {
		t.Fatalf("expected MALFORMED_SIGNATURE (9), got code %d (%s)", se.Code, se.Message)
	}
}

func TestProverRejectsOffCurveIssuerPK(t *testing.T) {
	input := makeInput(t)
	for i := 0; i < 32; i++ {
		input.Statement.IssuerPublicKeyX[i] = 0
		input.Statement.IssuerPublicKeyY[i] = 0
	}
	input.Statement.IssuerPublicKeyX[31] = 1
	input.Statement.IssuerPublicKeyY[31] = 1 // (1, 1) is not on P-256
	circuit, err := GenerateCircuit()
	if err != nil {
		t.Fatalf("GenerateCircuit: %v", err)
	}
	_, err = Prove(circuit, input)
	if err == nil {
		t.Fatal("Prove should reject off-curve issuer public key")
	}
	se, ok := err.(*StatusError)
	if !ok {
		t.Fatalf("expected *StatusError, got %T: %v", err, err)
	}
	if se.Code != 9 { // MALFORMED_SIGNATURE
		t.Fatalf("expected MALFORMED_SIGNATURE (9), got code %d (%s)", se.Code, se.Message)
	}
}

func TestVerifierRejectsOversizedCircuitBytes(t *testing.T) {
	input := makeInput(t)
	circuit, err := GenerateCircuit()
	if err != nil {
		t.Fatalf("GenerateCircuit: %v", err)
	}
	proof, err := Prove(circuit, input)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	// Construct an oversized buffer; the cap check rejects before any read,
	// so we don't actually need 65 MiB of data.
	huge := make([]byte, MaxCircuitBytes+1)
	copy(huge, circuit)
	err = Verify(huge, input.Statement, proof)
	if err == nil {
		t.Fatal("Verify should reject oversized circuit_bytes")
	}
	se, ok := err.(*StatusError)
	if !ok {
		t.Fatalf("expected *StatusError, got %T: %v", err, err)
	}
	// APPROVAL_PROOF_V1_VERIFIER_INPUT_TOO_LARGE = 7
	if se.Code != 7 {
		t.Fatalf("expected INPUT_TOO_LARGE (7), got code %d (%s)", se.Code, se.Message)
	}
}

func TestCircuitIDReturnsTypedError(t *testing.T) {
	// Empty buffer triggers INVALID_INPUT, exercising the typed enum return
	// from the V7 change.
	if _, err := CircuitID([]byte{}); err == nil {
		t.Fatal("CircuitID should fail on empty input")
	} else if se, ok := err.(*StatusError); !ok {
		t.Fatalf("expected *StatusError, got %T", err)
	} else if se.Domain != "circuit_id" {
		t.Fatalf("expected domain=circuit_id, got %q", se.Domain)
	}
}

func makeInput(t *testing.T) ProverInput {
	t.Helper()

	serviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("service keygen: %v", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device keygen: %v", err)
	}

	var input ProverInput
	input.Statement.IssuerPublicKeyX, input.Statement.IssuerPublicKeyY = publicKeyXY(serviceKey)
	fillIncreasing(input.Statement.AppIDHash[:], 0xa0)
	fillIncreasing(input.Statement.ChallengeNonce[:], 0x10)
	fillIncreasing(input.Statement.AudienceHash[:], 0x20)
	fillIncreasing(input.Statement.ApprovalHash[:], 0x30)
	input.Statement.PolicyVersion[3] = 1
	input.Statement.Now = Uint64BE(1000)

	deviceX, deviceY := publicKeyXY(deviceKey)
	input.Attestation = BuildAttestation(input.Statement, deviceX, deviceY, Uint64BE(900), Uint64BE(2000))
	input.ApprovalAssertion = BuildApprovalAssertion(input.Statement, Uint64BE(1500))
	input.AttestationSig = rawSignature(t, serviceKey, input.Attestation[:])
	input.ApprovalAssertionSig = rawSignature(t, deviceKey, input.ApprovalAssertion[:])
	return input
}

func publicKeyXY(key *ecdsa.PrivateKey) ([P256CoordLength]byte, [P256CoordLength]byte) {
	var x, y [P256CoordLength]byte
	writeFixed32(x[:], key.PublicKey.X)
	writeFixed32(y[:], key.PublicKey.Y)
	return x, y
}

func rawSignature(t *testing.T, key *ecdsa.PrivateKey, msg []byte) [SignatureLength]byte {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	var sig [SignatureLength]byte
	writeFixed32(sig[0:32], r)
	writeFixed32(sig[32:64], s)
	return sig
}

func writeFixed32(dst []byte, n *big.Int) {
	for i := range dst {
		dst[i] = 0
	}
	src := n.Bytes()
	copy(dst[len(dst)-len(src):], src)
}

func fillIncreasing(dst []byte, start byte) {
	for i := range dst {
		dst[i] = start + byte(i)
	}
}
