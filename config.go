package tlsutil

import (
	"net"

	"github.com/spf13/pflag"
)

func BindFlags(fs *pflag.FlagSet, cfg *Config, prefix string) {
	fs.StringSliceVar(&cfg.DNSNames, prefix+"dns", []string{}, "DNS subject alternative name")
	fs.StringSliceVar(&cfg.EmailAddresses, prefix+"email", []string{}, "Email subject alternative name")
	fs.IPSliceVar(&cfg.IPAddresses, prefix+"ip", []net.IP{}, "IP subject alternative name")
	//fs.StringSliceVar(&cfg.URIs, prefix+"uri", []string{}, "URI subject alternative name")
}
