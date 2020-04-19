package cmd

import (
	"crypto/x509"
	"net"

	"github.com/dsbrng25b/pcert"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func BindCertificateFlags(fs *pflag.FlagSet, cert *x509.Certificate, prefix string) {
	fs.StringSliceVar(&cert.DNSNames, prefix+"dns", []string{}, "DNS subject alternative name")
	fs.StringSliceVar(&cert.EmailAddresses, prefix+"email", []string{}, "Email subject alternative name")
	fs.IPSliceVar(&cert.IPAddresses, prefix+"ip", []net.IP{}, "IP subject alternative name")
	fs.Var(newURISliceValue(&cert.URIs), prefix+"uri", "URI subject alternative name")
	fs.Var(newSignAlgValue(&cert.SignatureAlgorithm), prefix+"sign-alg", "Signature Algorithm")
	fs.Var(newTimeValue(&cert.NotBefore), prefix+"not-before", "Not valid before time in RFC3339 format")
	fs.Var(newTimeValue(&cert.NotAfter), prefix+"not-after", "Not valid after time in RFC3339 format")
	fs.Var(newSubjectValue(&cert.Subject), prefix+"subject", "Subject in the form '/C=CH/O=My Org/OU=My Team'")

	fs.BoolVar(&cert.BasicConstraintsValid, prefix+"basic-constraints", cert.BasicConstraintsValid, "Add basic constraints extension")
	fs.BoolVar(&cert.IsCA, prefix+"is-ca", cert.IsCA, "Mark certificate as CA in the basic constraints. Only takes effect if --basic-constraints is true")
	fs.Var(newMaxPathLengthValue(cert), prefix+"max-path-length", "Sets the max path length in the basic constraints.")

	fs.Var(newKeyUsageValue(&cert.KeyUsage), prefix+"key-usage", "Set the key usage")
	fs.Var(newExtKeyUsageValue(&cert.ExtKeyUsage), prefix+"ext-key-usage", "Set the extended key usage")
}

func BindKeyFlags(fs *pflag.FlagSet, keyConfig *pcert.KeyConfig, prefix string) {
	fs.StringVar(&keyConfig.Algorithm, prefix+"key-alg", keyConfig.Algorithm, "Key Algorithm")
	fs.IntVar(&keyConfig.Size, prefix+"key-size", keyConfig.Size, "Key Size")
}

func RegisterCompletionFuncs(cmd *cobra.Command) {
	cmd.RegisterFlagCompletionFunc("key-usage", keyUsageCompletionFunc)
	cmd.RegisterFlagCompletionFunc("ext-key-usage", extKeyUsageCompletionFunc)
}
