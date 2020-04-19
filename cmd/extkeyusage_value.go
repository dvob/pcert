package cmd

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/dsbrng25b/pcert"
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
	return pcert.ExtKeyUsageToString(*eku.value)
}

func (eku *extKeyUsageValue) Set(usageStr string) error {
	usages := []x509.ExtKeyUsage{}
	for _, u := range strings.Split(usageStr, ",") {
		x509ExtUsage, ok := pcert.ExtKeyUsages[u]
		if !ok {
			return fmt.Errorf("unknown usage: %s", u)
		}
		usages = append(usages, x509ExtUsage)
	}
	*eku.value = append(*eku.value, usages...)
	return nil
}
