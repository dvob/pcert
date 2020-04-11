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
	fs.Var(newURISliceValue(&cert.URIs), prefix+"uri", "URI subject alternative name")
}

type uriSliceValue struct {
	urls    *[]*url.URL
	changed bool
}

func newURISliceValue(urls *[]*url.URL) *uriSliceValue {
	return &uriSliceValue{
		urls: urls,
	}
}

func (us *uriSliceValue) Type() string {
	return "uris"
}

func (us *uriSliceValue) String() string {
	return fmt.Sprintf("%s", *us.urls)
}

func (us *uriSliceValue) Set(urlRawStr string) error {
	urlStrList := strings.Split(urlRawStr, ",")
	var urls []*url.URL
	for _, urlStr := range urlStrList {
		u, err := url.Parse(urlStr)
		if err != nil {
			return err
		}
		urls = append(urls, u)
	}

	// overwrite the defaults/initial value on first Set
	if us.changed {
		*us.urls = append(*us.urls, urls...)
	} else {
		*us.urls = urls
		us.changed = true
	}

	return nil
}
