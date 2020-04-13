package cmd

import (
	"crypto/x509"
	"fmt"
)

type extKeyUsageValue struct {
	value *[]x509.ExtKeyUsage
}

func newExtKeyUsageValue(eku *[]x509.ExtKeyUsage) *extKeyUsageValue {
	return &extKeyUsageValue{
		value: eku,
	}
}

func (eku *extKeyUsageValue) Type() string {
	return "usage"
}

func (eku *extKeyUsageValue) String() string {
	return fmt.Sprintf("%s", *eku.value)
}

func (eku *extKeyUsageValue) Set(usage string) error {
	x509ExtUsage, ok := ExtKeyUsage[usage]
	if !ok {
		return fmt.Errorf("unknown usage: %s", usage)
	}
	*eku.value = append(*eku.value, x509ExtUsage)
	return nil
}
