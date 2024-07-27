package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/spf13/pflag"
)

const (
	defaultDuration = time.Hour * 24 * 365
)

func NewCertificate(opts *CertificateOptions) *x509.Certificate {
	if opts == nil {
		opts = &CertificateOptions{}
	}
	cert := &x509.Certificate{
		SignatureAlgorithm:          opts.SignatureAlgorithm,
		SerialNumber:                opts.SerialNumber,
		Subject:                     opts.Subject,
		NotBefore:                   opts.NotBefore,
		NotAfter:                    opts.NotAfter,
		KeyUsage:                    opts.KeyUsage,
		ExtraExtensions:             opts.ExtraExtensions,
		ExtKeyUsage:                 opts.ExtKeyUsage,
		UnknownExtKeyUsage:          opts.UnknownExtKeyUsage,
		BasicConstraintsValid:       opts.BasicConstraintsValid,
		IsCA:                        opts.IsCA,
		SubjectKeyId:                opts.SubjectKeyId,
		AuthorityKeyId:              opts.AuthorityKeyId,
		OCSPServer:                  opts.OCSPServer,
		IssuingCertificateURL:       opts.IssuingCertificateURL,
		DNSNames:                    opts.DNSNames,
		EmailAddresses:              opts.EmailAddresses,
		IPAddresses:                 opts.IPAddresses,
		URIs:                        opts.URIs,
		PermittedDNSDomainsCritical: opts.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         opts.PermittedDNSDomains,
		ExcludedDNSDomains:          opts.ExcludedDNSDomains,
		PermittedIPRanges:           opts.PermittedIPRanges,
		ExcludedIPRanges:            opts.ExcludedIPRanges,
		PermittedEmailAddresses:     opts.PermittedEmailAddresses,
		ExcludedEmailAddresses:      opts.ExcludedEmailAddresses,
		PermittedURIDomains:         opts.PermittedURIDomains,
		ExcludedURIDomains:          opts.ExcludedURIDomains,
		CRLDistributionPoints:       opts.CRLDistributionPoints,
		PolicyIdentifiers:           opts.PolicyIdentifiers,
		Policies:                    opts.Policies,
	}

	if opts.MaxPathLen != nil {
		cert.MaxPathLen = *opts.MaxPathLen
		cert.MaxPathLenZero = true
	}

	if cert.NotBefore.IsZero() {
		cert.NotBefore = time.Now()
	}
	if cert.NotAfter.IsZero() {
		if opts.Expiry == 0 {
			cert.NotAfter = cert.NotBefore.Add(defaultDuration)
		} else {
			cert.NotAfter = cert.NotBefore.Add(opts.Expiry)
		}
	}

	if cert.SerialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		randomSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			panic("failed to obtain randomness:" + err.Error())
		}
		cert.SerialNumber = randomSerialNumber
	}
	return cert
}

// CertificateOptions represents all options which can be set using
// CreateCertificate (see Go docs of it). Further it offers Expiry to set a
// validity duration instead of absolute times.
type CertificateOptions struct {
	SignatureAlgorithm x509.SignatureAlgorithm

	SerialNumber *big.Int
	Subject      pkix.Name

	NotBefore, NotAfter time.Time // Validity bounds.
	Expiry              time.Duration

	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage // Sequence of extended key usages.

	ExtraExtensions    []pkix.Extension
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	BasicConstraintsValid bool
	IsCA                  bool
	// if nil MaxPathLen = 0, MaxPathLenZero = false
	// else: MaxPathLen = *this, MaxPathLenZero = true
	MaxPathLen *int

	// if CA defaults to sha something something
	SubjectKeyId []byte
	// gets defaulted to parent.SubjectKeyID
	AuthorityKeyId []byte

	OCSPServer            []string
	IssuingCertificateURL []string

	// SAN
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	// Name constraints
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	PolicyIdentifiers []asn1.ObjectIdentifier
	Policies          []x509.OID
}

func (co *CertificateOptions) BindFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&co.DNSNames, "dns", []string{}, "DNS subject alternative name.")
	fs.StringSliceVar(&co.EmailAddresses, "email", []string{}, "Email subject alternative name.")
	fs.IPSliceVar(&co.IPAddresses, "ip", []net.IP{}, "IP subject alternative name.")
	fs.Var(newURISliceValue(&co.URIs), "uri", "URI subject alternative name.")
	fs.Var(newSignAlgValue(&co.SignatureAlgorithm), "sign-alg", "Signature Algorithm. See 'pcert list' for available algorithms.")
	fs.Var(newTimeValue(&co.NotBefore), "not-before", fmt.Sprintf("Not valid before time in RFC3339 format (e.g. '%s').", time.Now().UTC().Format(time.RFC3339)))
	fs.Var(newTimeValue(&co.NotAfter), "not-after", fmt.Sprintf("Not valid after time in RFC3339 format (e.g. '%s').", time.Now().Add(time.Hour*24*60).UTC().Format(time.RFC3339)))
	fs.Var(newSubjectValue(&co.Subject), "subject", "Subject in the form '/C=CH/O=My Org/OU=My Team'.")

	//fs.BoolVar(&co.BasicConstraintsValid, "basic-constraints", cert.BasicConstraintsValid, "Add basic constraints extension.")
	//fs.BoolVar(&co.IsCA, "is-ca", cert.IsCA, "Mark certificate as CA in the basic constraints. Only takes effect if --basic-constraints is true.")
	//fs.Var(newMaxPathLengthValue(co), "max-path-length", "Sets the max path length in the basic constraints.")

	fs.Var(newKeyUsageValue(&co.KeyUsage), "key-usage", "Set the key usage. See 'pcert list' for available key usages.")
	fs.Var(newExtKeyUsageValue(&co.ExtKeyUsage), "ext-key-usage", "Set the extended key usage. See 'pcert list' for available extended key usages.")
}
