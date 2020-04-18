package cmd

import (
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/dsbrng25b/pcert"
)

type keyUsageValue struct {
	value *x509.KeyUsage
}

func newKeyUsageValue(ku *x509.KeyUsage) *keyUsageValue {
	return &keyUsageValue{
		value: ku,
	}
}

func (ku *keyUsageValue) Type() string {
	return "usage"
}

func (ku *keyUsageValue) String() string {
	return strconv.Itoa(int(*ku.value))
}

func (ku *keyUsageValue) Set(usage string) error {
	x509Usage, ok := pcert.KeyUsages[usage]
	if !ok {
		return fmt.Errorf("unknown usage: %s", usage)
	}
	*ku.value |= x509Usage
	return nil
}
