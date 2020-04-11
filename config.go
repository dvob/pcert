package tlsutil

import (
	"crypto/x509"
	"net"

	"github.com/spf13/pflag"
)

func BindFlags(fs *pflag.FlagSet, cert *x509.Certificate, prefix string) {
	fs.StringSliceVar(&cert.DNSNames, prefix+"dns", []string{}, "DNS subject alternative name")
	fs.StringSliceVar(&cert.EmailAddresses, prefix+"email", []string{}, "Email subject alternative name")
	fs.IPSliceVar(&cert.IPAddresses, prefix+"ip", []net.IP{}, "IP subject alternative name")
	//fs.StringSliceVar(&cfg.URIs, prefix+"uri", []string{}, "URI subject alternative name")
}
