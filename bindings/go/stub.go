//go:build !cgo

package attestedkeyzk

import "errors"

var ErrUnavailable = errors.New("attested-key-zk: built without cgo (CGO_ENABLED=0)")

func GenerateCircuit() ([]byte, error) {
	return nil, ErrUnavailable
}

func Prove(circuit []byte, input ProverInput) ([]byte, error) {
	return nil, ErrUnavailable
}

func Verify(circuit []byte, statement Statement, proof []byte) error {
	return ErrUnavailable
}

func CircuitID(circuit []byte) ([HashLength]byte, error) {
	return [HashLength]byte{}, ErrUnavailable
}
