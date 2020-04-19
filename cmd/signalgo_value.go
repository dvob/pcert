package cmd

import (
	"crypto/x509"
	"fmt"

	"github.com/dsbrng25b/pcert"
)

type signAlgValue struct {
	value *x509.SignatureAlgorithm
}

func newSignAlgValue(signAlg *x509.SignatureAlgorithm) *signAlgValue {
	return &signAlgValue{
		value: signAlg,
	}
}

func (sa *signAlgValue) Type() string {
	return "algorithm"
}

func (sa *signAlgValue) String() string {
	return fmt.Sprintf("%s", sa.value.String())
}

func (sa *signAlgValue) Set(signAlgName string) error {
	var alg x509.SignatureAlgorithm
	for _, signAlg := range pcert.SignatureAlgorithms {
		if signAlg.String() == signAlgName {
			alg = signAlg
			break
		}
	}
	if alg == x509.UnknownSignatureAlgorithm {
		return fmt.Errorf("unknown signature algorithm: %s", signAlgName)
	}
	*sa.value = alg
	return nil
}
