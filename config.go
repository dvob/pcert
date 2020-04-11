package tlsutil

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

func BindFlags(fs *pflag.FlagSet, cert *x509.Certificate, prefix string) {
	fs.StringSliceVar(&cert.DNSNames, prefix+"dns", []string{}, "DNS subject alternative name")
	fs.StringSliceVar(&cert.EmailAddresses, prefix+"email", []string{}, "Email subject alternative name")
	fs.IPSliceVar(&cert.IPAddresses, prefix+"ip", []net.IP{}, "IP subject alternative name")
	fs.Var(newURISliceValue(&cert.URIs), prefix+"uri", "URI subject alternative name")
	fs.Var(newSignAlgValue(&cert.SignatureAlgorithm), prefix+"sign-alg", "Signature Algorithm")
	fs.Var(newTimeValue(&cert.NotBefore), prefix+"not-before", "Not valid before time in RFC3339 format")
	fs.Var(newTimeValue(&cert.NotAfter), prefix+"not-after", "Not valid after time in RFC3339 format")
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

type signAlgValue struct {
	value *x509.SignatureAlgorithm
}

func newSignAlgValue(signAlg *x509.SignatureAlgorithm) *signAlgValue {
	return &signAlgValue{
		value: signAlg,
	}
}

func (sa *signAlgValue) Type() string {
	return "algorithm"
}

func (sa *signAlgValue) String() string {
	return fmt.Sprintf("%s", sa.value.String())
}

func (sa *signAlgValue) Set(signAlgName string) error {
	alg := getSignatureAlgorithmByName(signAlgName)
	if alg == x509.UnknownSignatureAlgorithm {
		return fmt.Errorf("unknown signature algorithm: %s", signAlgName)
	}
	*sa.value = alg
	return nil
}

func getSignatureAlgorithmByName(name string) x509.SignatureAlgorithm {
	for i, alg := range getSignatureAlgorithms() {
		if alg == name {
			return x509.SignatureAlgorithm(i)
		}
	}
	return x509.UnknownSignatureAlgorithm
}

func getSignatureAlgorithms() []string {
	maxAlgs := 100
	algs := []string{}
	for i := 0; i < maxAlgs; i++ {
		indexStr := strconv.Itoa(i)
		algStr := x509.SignatureAlgorithm(i).String()
		if algStr == indexStr {
			fmt.Println("jump out")
			break
		}
		algs = append(algs, algStr)
	}
	return algs
}

type timeValue struct {
	value *time.Time
}

func newTimeValue(t *time.Time) *timeValue {
	return &timeValue{
		value: t,
	}
}

func (t *timeValue) Type() string {
	return "time"
}

func (t *timeValue) String() string {
	if t.value.IsZero() {
		return ""
	}
	return t.value.Format(time.RFC3339)
}

func (t *timeValue) Set(timeStr string) error {
	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return err
	}
	*t.value = parsedTime
	return nil
}
