package cmd

import (
	"crypto/x509"
	"fmt"
	"strings"

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
	return pcert.KeyUsageToString(*ku.value)
}

func (ku *keyUsageValue) Set(usageStr string) error {
	var newUsages x509.KeyUsage
	for _, u := range strings.Split(usageStr, ",") {
		x509KeyUsage, ok := pcert.KeyUsages[u]
		if !ok {
			return fmt.Errorf("unknown usage: %s", u)
		}
		newUsages |= x509KeyUsage
	}
	*ku.value |= newUsages
	return nil
}
