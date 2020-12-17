package cmd

import (
	"crypto/x509"
	"net"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// BindCertificateRequestFlags binds flags to a x509.CertificateRequest
func BindCertificateRequestFlags(fs *pflag.FlagSet, csr *x509.CertificateRequest) {
	fs.StringSliceVar(&csr.DNSNames, "dns", []string{}, "DNS subject alternative name")
	fs.StringSliceVar(&csr.EmailAddresses, "email", []string{}, "Email subject alternative name")
	fs.IPSliceVar(&csr.IPAddresses, "ip", []net.IP{}, "IP subject alternative name")
	fs.Var(newURISliceValue(&csr.URIs), "uri", "URI subject alternative name")
	fs.Var(newSignAlgValue(&csr.SignatureAlgorithm), "sign-alg", "Signature Algorithm")
	fs.Var(newSubjectValue(&csr.Subject), "subject", "Subject in the form '/C=CH/O=My Org/OU=My Team'")
}

// BindCertificateFlags binds flags to a x509.Certificate
func BindCertificateFlags(fs *pflag.FlagSet, cert *x509.Certificate) {
	fs.StringSliceVar(&cert.DNSNames, "dns", []string{}, "DNS subject alternative name")
	fs.StringSliceVar(&cert.EmailAddresses, "email", []string{}, "Email subject alternative name")
	fs.IPSliceVar(&cert.IPAddresses, "ip", []net.IP{}, "IP subject alternative name")
	fs.Var(newURISliceValue(&cert.URIs), "uri", "URI subject alternative name")
	fs.Var(newSignAlgValue(&cert.SignatureAlgorithm), "sign-alg", "Signature Algorithm")
	fs.Var(newTimeValue(&cert.NotBefore), "not-before", "Not valid before time in RFC3339 format")
	fs.Var(newTimeValue(&cert.NotAfter), "not-after", "Not valid after time in RFC3339 format")
	fs.Var(newSubjectValue(&cert.Subject), "subject", "Subject in the form '/C=CH/O=My Org/OU=My Team'")

	fs.BoolVar(&cert.BasicConstraintsValid, "basic-constraints", cert.BasicConstraintsValid, "Add basic constraints extension")
	fs.BoolVar(&cert.IsCA, "is-ca", cert.IsCA, "Mark certificate as CA in the basic constraints. Only takes effect if --basic-constraints is true")
	fs.Var(newMaxPathLengthValue(cert), "max-path-length", "Sets the max path length in the basic constraints.")

	fs.Var(newKeyUsageValue(&cert.KeyUsage), "key-usage", "Set the key usage")
	fs.Var(newExtKeyUsageValue(&cert.ExtKeyUsage), "ext-key-usage", "Set the extended key usage")
}

// BindKeyFlags binds flags to a pcert.KeyOptions
func BindKeyFlags(fs *pflag.FlagSet, keyOptions *pcert.KeyOptions) {
	fs.Var(newKeyAlgorithmValue(&keyOptions.Algorithm), "key-alg", "Public Key Algorithm")
	fs.IntVar(&keyOptions.Size, "key-size", keyOptions.Size, "Key Size. This defaults to 256 for ECDSA and to 2048 for RSA.")
}

// RegisterCertificateCompletionFuncs can be used after with BindCertificateFlags to enable shell completion for certain flags
func RegisterCertificateCompletionFuncs(cmd *cobra.Command) {
	_ = cmd.RegisterFlagCompletionFunc("key-usage", keyUsageCompletionFunc)
	_ = cmd.RegisterFlagCompletionFunc("ext-key-usage", extKeyUsageCompletionFunc)
	_ = cmd.RegisterFlagCompletionFunc("sign-alg", signAlgorithmCompletionFunc)
}

// RegisterCertificateRequestCompletionFuncs can be used after BindCertificateRequestFlags to enable shell completion for certain flags
func RegisterCertificateRequestCompletionFuncs(cmd *cobra.Command) {
	_ = cmd.RegisterFlagCompletionFunc("sign-alg", signAlgorithmCompletionFunc)
}

// RegisterKeyCompletionFuncs can be used after with BindKeyFlags to enable shell completion for certain flags
func RegisterKeyCompletionFuncs(cmd *cobra.Command) {
	_ = cmd.RegisterFlagCompletionFunc("key-alg", keyAlgorithmCompletionFunc)
}
