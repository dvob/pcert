package pcert

import (
	"crypto/x509"
	"sort"
	"strings"
)

//go:generate go run keyusage_gen.go

func KeyUsageToString(bitmask x509.KeyUsage) string {
	usages := []string{}
	for str, usage := range KeyUsages {
		if usage&bitmask == usage {
			usages = append(usages, str)
		}
	}
	sort.Strings(usages)
	return strings.Join(usages, ",")
}

func ExtKeyUsageToString(ku []x509.ExtKeyUsage) string {
	usages := []string{}
	for str, usage := range ExtKeyUsages {
		for _, existingUsage := range ku {
			if usage == existingUsage {
				usages = append(usages, str)
			}
		}
	}
	sort.Strings(usages)
	return strings.Join(usages, ",")
}
