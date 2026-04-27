package attestedkeyzk

import (
	"encoding/binary"
)

const (
	HashLength              = 32
	P256CoordLength         = 32
	SignatureLength         = 64
	PolicyVersionLength     = 4
	TimeLength              = 8
	DomainLength            = 16
	AttestationLength       = 136
	ApprovalAssertionLength = 120
	StatementLength         = 204
	ProverInputLength       = 588
	// MaxCircuitBytes / MaxProofBytes mirror kApprovalProofV1Max{Circuit,Proof}Bytes
	// in the public C header. Inputs above these caps are rejected at the
	// C-ABI boundary with INPUT_TOO_LARGE, before any parser runs.
	MaxCircuitBytes = 64 * 1024 * 1024
	MaxProofBytes   = 1 * 1024 * 1024
)

var (
	AttestationDomain       = [DomainLength]byte{'A', 'K', 'Z', 'K', '-', 'A', 'T', 'T', 'E', 'S', 'T', '-', 'K', 'E', 'Y', '1'}
	ApprovalAssertionDomain = [DomainLength]byte{'A', 'K', 'Z', 'K', '-', 'A', 'P', 'P', 'R', 'O', 'V', 'A', 'L', '-', 'V', '1'}
)

type Statement struct {
	IssuerPublicKeyX [P256CoordLength]byte
	IssuerPublicKeyY [P256CoordLength]byte
	AppIDHash        [HashLength]byte
	PolicyVersion    [PolicyVersionLength]byte
	Now              [TimeLength]byte
	ChallengeNonce   [HashLength]byte
	AudienceHash     [HashLength]byte
	ApprovalHash     [HashLength]byte
}

type ProverInput struct {
	Statement            Statement
	Attestation          [AttestationLength]byte
	AttestationSig       [SignatureLength]byte
	ApprovalAssertion    [ApprovalAssertionLength]byte
	ApprovalAssertionSig [SignatureLength]byte
}

type StatusError struct {
	Domain  string
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return e.Domain + ": " + e.Message
}

func Uint64BE(v uint64) [TimeLength]byte {
	var out [TimeLength]byte
	binary.BigEndian.PutUint64(out[:], v)
	return out
}

func BuildAttestation(statement Statement, devicePublicKeyX, devicePublicKeyY [P256CoordLength]byte, notBefore, notAfter [TimeLength]byte) [AttestationLength]byte {
	var out [AttestationLength]byte
	copy(out[0:16], AttestationDomain[:])
	copy(out[16:48], statement.AppIDHash[:])
	copy(out[48:52], statement.PolicyVersion[:])
	out[52] = 1
	copy(out[56:64], notBefore[:])
	copy(out[64:72], notAfter[:])
	copy(out[72:104], devicePublicKeyX[:])
	copy(out[104:136], devicePublicKeyY[:])
	return out
}

func BuildApprovalAssertion(statement Statement, expiresAt [TimeLength]byte) [ApprovalAssertionLength]byte {
	var out [ApprovalAssertionLength]byte
	copy(out[0:16], ApprovalAssertionDomain[:])
	copy(out[16:48], statement.ChallengeNonce[:])
	copy(out[48:80], statement.AudienceHash[:])
	copy(out[80:112], statement.ApprovalHash[:])
	copy(out[112:120], expiresAt[:])
	return out
}

func (s Statement) MarshalBinary() []byte {
	out := make([]byte, StatementLength)
	copy(out[0:32], s.IssuerPublicKeyX[:])
	copy(out[32:64], s.IssuerPublicKeyY[:])
	copy(out[64:96], s.AppIDHash[:])
	copy(out[96:100], s.PolicyVersion[:])
	copy(out[100:108], s.Now[:])
	copy(out[108:140], s.ChallengeNonce[:])
	copy(out[140:172], s.AudienceHash[:])
	copy(out[172:204], s.ApprovalHash[:])
	return out
}

func (p ProverInput) MarshalBinary() []byte {
	out := make([]byte, ProverInputLength)
	copy(out[0:StatementLength], p.Statement.MarshalBinary())
	copy(out[StatementLength:StatementLength+AttestationLength], p.Attestation[:])
	copy(out[StatementLength+AttestationLength:StatementLength+AttestationLength+SignatureLength], p.AttestationSig[:])
	copy(out[StatementLength+AttestationLength+SignatureLength:StatementLength+AttestationLength+SignatureLength+ApprovalAssertionLength], p.ApprovalAssertion[:])
	copy(out[StatementLength+AttestationLength+SignatureLength+ApprovalAssertionLength:], p.ApprovalAssertionSig[:])
	return out
}
