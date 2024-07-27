package main

import (
	"fmt"
	"net"
	"time"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func registerCertFlags(cmd *cobra.Command, certOpts *pcert.CertificateOptions) {
	bindCertFlags(cmd.Flags(), certOpts)

	_ = cmd.RegisterFlagCompletionFunc("sign-alg", signAlgorithmCompletionFunc)

	_ = cmd.RegisterFlagCompletionFunc("key-usage", keyUsageCompletionFunc)
	_ = cmd.RegisterFlagCompletionFunc("ext-key-usage", extKeyUsageCompletionFunc)
}

func bindCertFlags(fs *pflag.FlagSet, co *pcert.CertificateOptions) {
	// SAN
	fs.StringSliceVar(&co.DNSNames, "dns", []string{}, "DNS subject alternative name.")
	fs.StringSliceVar(&co.EmailAddresses, "email", []string{}, "Email subject alternative name.")
	fs.IPSliceVar(&co.IPAddresses, "ip", []net.IP{}, "IP subject alternative name.")
	fs.Var(newURISliceValue(&co.URIs), "uri", "URI subject alternative name.")

	// signature algorithm
	fs.Var(newSignAlgValue(&co.SignatureAlgorithm), "sign-alg", "Signature Algorithm. See 'pcert list' for available algorithms.")

	// validity duration
	fs.Var(newTimeValue(&co.NotBefore), "not-before", fmt.Sprintf("Not valid before time in RFC3339 format (e.g. '%s').", time.Now().UTC().Format(time.RFC3339)))
	fs.Var(newTimeValue(&co.NotAfter), "not-after", fmt.Sprintf("Not valid after time in RFC3339 format (e.g. '%s').", time.Now().Add(time.Hour*24*60).UTC().Format(time.RFC3339)))
	fs.Var(newDurationValue(&co.Expiry), "expiry", "Validity period of the certificate. If --not-after is set this option has no effect.")

	// subject
	fs.Var(newSubjectValue(&co.Subject), "subject", "Subject in the form '/C=CH/O=My Org/OU=My Team'.")
	bindSubjectFlags(fs, &co.Subject)

	// basic constraints
	fs.BoolVar(&co.BasicConstraintsValid, "basic-constraints", co.BasicConstraintsValid, "Add basic constraints extension.")
	fs.BoolVar(&co.IsCA, "is-ca", co.IsCA, "Mark certificate as CA in the basic constraints. Only takes effect if --basic-constraints is true.")
	fs.Var(newMaxPathLengthValue(co.MaxPathLen), "max-path-length", "Sets the max path length in the basic constraints.")

	// key usage
	fs.Var(newKeyUsageValue(&co.KeyUsage), "key-usage", "Set the key usage. See 'pcert list' for available key usages.")
	fs.Var(newExtKeyUsageValue(&co.ExtKeyUsage), "ext-key-usage", "Set the extended key usage. See 'pcert list' for available extended key usages.")
}
