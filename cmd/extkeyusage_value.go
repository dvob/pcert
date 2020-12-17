package cmd

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
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

func extKeyUsageCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	out := []string{}
	for u := range pcert.ExtKeyUsages {
		out = append(out, u)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
