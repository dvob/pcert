package pcert

import (
	"crypto/x509"
	"sort"
	"strings"
)

//go:generate go run x509_lists_gen.go

// KeyUsageToString returns a string representation of a x509.KeyUsage bitmask
func KeyUsageToStringSlice(bitmask x509.KeyUsage) []string {
	usages := []string{}
	for str, usage := range KeyUsages {
		if usage&bitmask == usage {
			usages = append(usages, str)
		}
	}
	sort.Strings(usages)
	return usages
}

func KeyUsageToString(bitmask x509.KeyUsage) string {
	return strings.Join(KeyUsageToStringSlice(bitmask), ", ")
}

// ExtKeyUsageToString returns a string representation of a []x509.ExtKeyUsage slice
func ExtKeyUsageToString(ku []x509.ExtKeyUsage) string {
	usages := []string{}
	for str, usage := range ExtKeyUsages {
		for _, existingUsage := range ku {
			if usage == existingUsage {
				usages = append(usages, str)
				break
			}
		}
	}
	sort.Strings(usages)
	return strings.Join(usages, ",")
}
