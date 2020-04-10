package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

var defaultValidityPeriod = time.Hour * 24 * 365

type Config struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
	NotBefore      time.Time
	NotAfter       time.Time
}

// create self signed certificate (e.g. CA)
func Create(name string, cfg *Config) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}

	keyPEM = KeyToPEM(keyDER)

	cert, err := certTemplate(name, cfg)
	if err != nil {
		return
	}

	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return
	}

	certPEM = CertificateToPEM(der)

	return
}

// create CSR
func Request(name string, cfg *Config) (csrPEM []byte, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}

	keyPEM = KeyToPEM(keyDER)

	cert, err := certTemplate(name, cfg)
	if err != nil {
		return
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, certToCSR(cert), key)
	if err != nil {
		return
	}

	csrPEM = CSRToPEM(der)

	return
}

// sign a CSR
func Sign(csr *x509.CertificateRequest, cfg *Config, caCert *x509.Certificate, caKey interface{}) (certPEM []byte, err error) {
	// name will be set from csr
	cert, err := certTemplate("", cfg)
	if err != nil {
		return nil, err
	}

	applyCSR(csr, cert)

	der, err := x509.CreateCertificate(rand.Reader, cert, caCert, cert.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return CertificateToPEM(der), nil
}

// apply values of CSR to certificate
func applyCSR(csr *x509.CertificateRequest, cert *x509.Certificate) {
	cert.Signature = csr.Signature
	cert.SignatureAlgorithm = csr.SignatureAlgorithm
	cert.PublicKeyAlgorithm = csr.PublicKeyAlgorithm
	cert.PublicKey = csr.PublicKey
	cert.Subject = csr.Subject
	cert.DNSNames = csr.DNSNames
	cert.EmailAddresses = csr.EmailAddresses
	cert.IPAddresses = csr.IPAddresses
	cert.URIs = csr.URIs
	cert.ExtraExtensions = csr.ExtraExtensions
}

func certToCSR(cert *x509.Certificate) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		SignatureAlgorithm: cert.SignatureAlgorithm,
		Subject:            cert.Subject,
		DNSNames:           cert.DNSNames,
		EmailAddresses:     cert.EmailAddresses,
		IPAddresses:        cert.IPAddresses,
		URIs:               cert.URIs,
		ExtraExtensions:    cert.ExtraExtensions,
	}
}

func certTemplate(name string, cfg *Config) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	if cfg.NotBefore.IsZero() {
		cfg.NotBefore = time.Now()
	}

	if cfg.NotAfter.IsZero() {
		cfg.NotAfter = time.Now().Add(defaultValidityPeriod)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: name},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             cfg.NotBefore,
		NotAfter:              cfg.NotAfter,
		BasicConstraintsValid: true,
		IPAddresses:           cfg.IPAddresses,
		DNSNames:              cfg.DNSNames,
		EmailAddresses:        cfg.EmailAddresses,
		URIs:                  cfg.URIs,
	}
	return &tmpl, nil
}
