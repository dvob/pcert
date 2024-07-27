package pcert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"time"
)

const (
	// DefaultValidityPeriod is the validity period used for certificates which have not set NotAfter explicitly
	DefaultValidityPeriod = time.Hour * 24 * 365
)

// Create creates a x509.Certificate and a key with the default key options. See CreateWithKeyOptions for more details.
func CreateCertificate(cert, signCert *x509.Certificate, signKey crypto.PrivateKey) (certDER []byte, privateKey crypto.PrivateKey, err error) {
	return CreateWithKeyOptions(cert, KeyOptions{}, signCert, signKey)
}

// CreateCertificateWithKeyOptions creates a key and certificate. The certificate is signed
// used signCert and signKey. If signCert or signKey are nil, a self-signed
// certificate will be created. The certificate and the key are returned PEM encoded.
func CreateWithKeyOptions(cert *x509.Certificate, keyOptions KeyOptions, signCert *x509.Certificate, signKey crypto.PrivateKey) (certDER []byte, privateKey crypto.PrivateKey, err error) {
	priv, pub, err := GenerateKey(keyOptions)
	if err != nil {
		return nil, nil, err
	}

	// If signCert and signKey are missing we self sign the certificate
	if signCert == nil && signKey == nil {
		signCert = cert
		signKey = priv
	}

	if signCert == nil {
		return nil, nil, fmt.Errorf("signing certificate cannot be nil")
	}
	if signKey == nil {
		return nil, nil, fmt.Errorf("signing key cannot be nil")
	}

	certDER, err = x509.CreateCertificate(rand.Reader, cert, signCert, pub, signKey)
	if err != nil {
		return nil, nil, err
	}
	return certDER, priv, err
}

// Request creates a CSR and a key. The key is created with the default key
// options. See RequestWithKeyOptions for more details.
func CreateRequest(csr *x509.CertificateRequest) (csrPEM []byte, privateKey crypto.PrivateKey, err error) {
	return CreateRequestWithKeyOptions(csr, KeyOptions{})
}

// RequestWithKeyOptions creates a CSR and a key based on key options.  The key is
// created with the default key options.
func CreateRequestWithKeyOptions(csr *x509.CertificateRequest, keyOptions KeyOptions) (csrPEM []byte, privateKey crypto.PrivateKey, err error) {
	priv, _, err := GenerateKey(keyOptions)
	if err != nil {
		return
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
	if err != nil {
		return
	}

	return csrDER, priv, nil
}

// SignCSR applies the settings from csr and return the signed certificate
func CreateCertificateWithCSR(csr *x509.CertificateRequest, cert, signCert *x509.Certificate, signKey any) (certDER []byte, err error) {
	// TODO: settings from cert should take precedence
	applyCSR(csr, cert)

	return x509.CreateCertificate(rand.Reader, cert, signCert, csr.PublicKey, signKey)
}

// apply values of CSR to certificate
func applyCSR(csr *x509.CertificateRequest, cert *x509.Certificate) {
	cert.Signature = csr.Signature
	cert.SignatureAlgorithm = csr.SignatureAlgorithm
	cert.PublicKeyAlgorithm = csr.PublicKeyAlgorithm
	cert.PublicKey = csr.PublicKey

	emptySubject := pkix.Name{}
	if reflect.DeepEqual(cert.Subject, emptySubject) {
		cert.Subject = csr.Subject
	}

	if cert.DNSNames == nil {
		cert.DNSNames = csr.DNSNames
	}

	if cert.EmailAddresses == nil {
		cert.EmailAddresses = csr.EmailAddresses
	}

	if cert.IPAddresses == nil {
		cert.IPAddresses = csr.IPAddresses
	}

	if cert.URIs == nil {
		cert.URIs = csr.URIs
	}
}

// GenerateSerial produces an RFC 5280 conformant serial number to be used
// in a certificate. The serial number will be a positive integer, no more
// than 20 octets in length, generated using the provided random source.
//
// Code from: https://go-review.googlesource.com/c/go/+/479120/3/src/crypto/x509/x509.go#2485
func generateSerial() (*big.Int, error) {
	randBytes := make([]byte, 20)
	for i := 0; i < 10; i++ {
		// get 20 random bytes
		_, err := io.ReadFull(rand.Reader, randBytes)
		if err != nil {
			return nil, err
		}
		// clear the top bit (to prevent the number being negative)
		randBytes[0] &= 0x7f
		// convert to big.Int
		serial := new(big.Int).SetBytes(randBytes)
		// check that the serial is not zero
		if serial.Sign() == 0 {
			continue
		}
		return serial, nil
	}
	return nil, errors.New("x509: failed to generate serial number because the random source returns only zeros")
}

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

	if opts.MaxPathLen == nil {
		cert.MaxPathLen = -1
		cert.MaxPathLenZero = false
	} else if *opts.MaxPathLen == 0 {
		cert.MaxPathLen = 0
		cert.MaxPathLenZero = true
	} else {
		cert.MaxPathLen = *opts.MaxPathLen
		cert.MaxPathLenZero = false
	}

	if cert.NotBefore.IsZero() {
		cert.NotBefore = time.Now()
	}
	if cert.NotAfter.IsZero() {
		if opts.Expiry == 0 {
			cert.NotAfter = cert.NotBefore.Add(DefaultValidityPeriod)
		} else {
			cert.NotAfter = cert.NotBefore.Add(opts.Expiry)
		}
	}

	if cert.SerialNumber == nil {
		var err error
		cert.SerialNumber, err = generateSerial()
		if err != nil {
			// reading randomness failed
			panic(err.Error())
		}
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
