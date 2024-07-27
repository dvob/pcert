package main

import (
	"crypto/x509"
	"fmt"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
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
	return sa.value.String()
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

func signAlgorithmCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	out := []string{}
	for _, s := range pcert.SignatureAlgorithms {
		out = append(out, s.String())
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
