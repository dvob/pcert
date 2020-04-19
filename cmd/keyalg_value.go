package cmd

import (
	"crypto/x509"
	"fmt"

	"github.com/dsbrng25b/pcert"
)

type keyAlgorithmValue struct {
	value *x509.PublicKeyAlgorithm
}

func newKeyAlgorithmValue(keyAlgorithm *x509.PublicKeyAlgorithm) *keyAlgorithmValue {
	return &keyAlgorithmValue{
		value: keyAlgorithm,
	}
}

func (sa *keyAlgorithmValue) Type() string {
	return "PublicKeyAlgorithm"
}

func (sa *keyAlgorithmValue) String() string {
	return fmt.Sprintf("%s", sa.value.String())
}

func (sa *keyAlgorithmValue) Set(keyAlgName string) error {
	var alg x509.PublicKeyAlgorithm
	for _, keyAlg := range pcert.PublicKeyAlgorithms {
		if keyAlg.String() == keyAlgName {
			alg = keyAlg
			break
		}
	}
	if alg == x509.UnknownPublicKeyAlgorithm {
		return fmt.Errorf("unknown public key algorithm: %s", keyAlgName)
	}
	*sa.value = alg
	return nil
}
