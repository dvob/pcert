package pcert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"time"
)

const (
	// DefaultValidityPeriod is the validity period used for certificates which have not set NotAfter explicitly
	DefaultValidityPeriod = time.Hour * 24 * 365
)

// CreateCertificate creates a x509.Certificate and a key with the default key
// options. See CreateCertificateWithKeyOptions for more details.
func CreateCertificate(cert, signCert *x509.Certificate, signKey crypto.PrivateKey) (certDER []byte, privateKey crypto.PrivateKey, err error) {
	return CreateCertificateWithKeyOptions(cert, KeyOptions{}, signCert, signKey)
}

// CreateCertificateWithKeyOptions creates a key and certificate. The
// certificate is signed used signCert and signKey. If signCert or signKey are
// nil, a self-signed certificate will be created. The certificate and the key
// are returned PEM encoded.
func CreateCertificateWithKeyOptions(cert *x509.Certificate, keyOptions KeyOptions, signCert *x509.Certificate, signKey crypto.PrivateKey) (certDER []byte, privateKey crypto.PrivateKey, err error) {
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

// CreateRequest creates a CSR and a key. The key is created with the default key
// options. See CreateRequestWithKeyOptions for more details.
func CreateRequest(csr *x509.CertificateRequest) (csrPEM []byte, privateKey crypto.PrivateKey, err error) {
	return CreateRequestWithKeyOptions(csr, KeyOptions{})
}

// CreateRequestWithKeyOptions creates a CSR and a key based on key options.  The key is
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

// CreateCertificateWithCSR applies the settings from csr and return the signed certificate
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

// NewCertificate returns a *x509.Certificate with settings set based on
// CertificateOptions. Further it sets certain defaults if they were not set explicitly:
// - Expiration one year from now
// - Random serial number
func NewCertificate(opts *CertificateOptions) *x509.Certificate {
	if opts == nil {
		opts = &CertificateOptions{}
	}

	if opts.NotBefore.IsZero() {
		opts.NotBefore = time.Now()
	}
	if opts.NotAfter.IsZero() {
		if opts.Expiry == 0 {
			opts.NotAfter = opts.NotBefore.Add(DefaultValidityPeriod)
		} else {
			opts.NotAfter = opts.NotBefore.Add(opts.Expiry)
		}
	}

	if opts.ProfileCA {
		SetCAProfile(&opts.Certificate)
	}
	if opts.ProfileServer {
		SetServerProfile(&opts.Certificate)
	}
	if opts.ProfileClient {
		SetClientProfile(&opts.Certificate)
	}

	if opts.SerialNumber == nil {
		var err error
		opts.SerialNumber, err = generateSerial()
		if err != nil {
			// reading randomness failed
			panic(err.Error())
		}
	}
	return &opts.Certificate
}

// CertificateOptions represents all options which can be set using
// CreateCertificate (see Go docs of it). Further it offers Expiry to set a
// validity duration instead of absolute times.
type CertificateOptions struct {
	Expiry        time.Duration
	ProfileServer bool
	ProfileClient bool
	ProfileCA     bool

	x509.Certificate
}
