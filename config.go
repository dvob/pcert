package tlsutil

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/spf13/pflag"
)

func BindFlags(fs *pflag.FlagSet, cert *x509.Certificate, prefix string) {
	fs.StringSliceVar(&cert.DNSNames, prefix+"dns", []string{}, "DNS subject alternative name")
	fs.StringSliceVar(&cert.EmailAddresses, prefix+"email", []string{}, "Email subject alternative name")
	fs.IPSliceVar(&cert.IPAddresses, prefix+"ip", []net.IP{}, "IP subject alternative name")
	fs.Var(&uriSliceValue{&cert.URIs}, prefix+"uri", "URI subject alternative name")
}

type uriSliceValue struct {
	urls *[]*url.URL
}

func (us *uriSliceValue) Type() string {
	return "uris"
}

func (us *uriSliceValue) String() string {
	//TODO
	return fmt.Sprintf("%s", *us.urls)
}

func (us *uriSliceValue) Set(urlRawStr string) error {
	//TODO
	urlStrList := strings.Split(urlRawStr, ",")
	var urls []*url.URL
	for _, urlStr := range urlStrList {
		u, err := url.Parse(urlStr)
		if err != nil {
			return fmt.Errorf("from Set: %w", err)
		}
		urls = append(urls, u)
	}

	*us.urls = append(*us.urls, urls...)
	return nil
}
