package main

import (
	"crypto/x509"
	"net"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func registerRequestFlags(cmd *cobra.Command, csr *x509.CertificateRequest) {
	bindRequestFlags(cmd.Flags(), csr)

	_ = cmd.RegisterFlagCompletionFunc("sign-alg", signAlgorithmCompletionFunc)
}

func bindRequestFlags(fs *pflag.FlagSet, csr *x509.CertificateRequest) {
	fs.StringSliceVar(&csr.DNSNames, "dns", []string{}, "DNS subject alternative name.")
	fs.StringSliceVar(&csr.EmailAddresses, "email", []string{}, "Email subject alternative name.")
	fs.IPSliceVar(&csr.IPAddresses, "ip", []net.IP{}, "IP subject alternative name.")
	fs.Var(newURISliceValue(&csr.URIs), "uri", "URI subject alternative name.")
	fs.Var(newSignAlgValue(&csr.SignatureAlgorithm), "sign-alg", "Signature Algorithm. See 'pcert list' for available algorithms.")
	fs.Var(newSubjectValue(&csr.Subject), "subject", "Subject in the form '/C=CH/O=My Org/OU=My Team'.")
}
