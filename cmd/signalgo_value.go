package cmd

import (
	"crypto/x509"
	"fmt"
	"strconv"
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
	alg := getSignatureAlgorithmByName(signAlgName)
	if alg == x509.UnknownSignatureAlgorithm {
		return fmt.Errorf("unknown signature algorithm: %s", signAlgName)
	}
	*sa.value = alg
	return nil
}

func getSignatureAlgorithmByName(name string) x509.SignatureAlgorithm {
	for i, alg := range GetSignatureAlgorithms() {
		if alg == name {
			return x509.SignatureAlgorithm(i)
		}
	}
	return x509.UnknownSignatureAlgorithm
}

func GetSignatureAlgorithms() []string {
	maxAlgs := 100
	algs := []string{}
	for i := 0; i < maxAlgs; i++ {
		indexStr := strconv.Itoa(i)
		algStr := x509.SignatureAlgorithm(i).String()
		if algStr == indexStr {
			fmt.Println("jump out")
			break
		}
		algs = append(algs, algStr)
	}
	return algs
}
