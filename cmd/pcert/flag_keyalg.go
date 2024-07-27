package main

import (
	"crypto/x509"
	"fmt"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

type keyAlgorithmValue struct {
	value *x509.PublicKeyAlgorithm
}

func newKeyAlgorithmValue(keyAlgorithm *x509.PublicKeyAlgorithm) *keyAlgorithmValue {
	return &keyAlgorithmValue{
		value: keyAlgorithm,
	}
}

func (ka *keyAlgorithmValue) Type() string {
	return "PublicKeyAlgorithm"
}

func (ka *keyAlgorithmValue) String() string {
	return ka.value.String()
}

func (ka *keyAlgorithmValue) Set(keyAlgName string) error {
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
	*ka.value = alg
	return nil
}

func keyAlgorithmCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	out := []string{}
	for _, s := range pcert.PublicKeyAlgorithms {
		out = append(out, s.String())
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
