package pcert

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

const (
	DefaultKeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
)

// NewCertificate returns a new certificate which have the CommonName set to name
func NewCertificate(name string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: name,
		},
	}
}

// NewClientCertificate returns a new certificate. The CommonName is set to name
// and typical client certificate settings are set (see SetClientProfile function).
func NewClientCertificate(name string) *x509.Certificate {
	cert := NewCertificate(name)
	SetClientProfile(cert)
	return cert
}

// NewServerCertificate returns a new certificate. The CommonName is set to name
// and typical server certificate settings are set (see SetServerProfile function).
func NewServerCertificate(name string) *x509.Certificate {
	cert := NewCertificate(name)
	SetServerProfile(cert)
	return cert
}

// NewCACertificate returns a new certificate. The CommonName is set to name and
// typical CA certificate settings are set (see SetCAProfile function).
func NewCACertificate(name string) *x509.Certificate {
	cert := NewCertificate(name)
	SetCAProfile(cert)
	return cert
}

// SetServerProfile sets typical characteristics of a server certificate.
func SetServerProfile(cert *x509.Certificate) {
	present := false
	for _, dns := range cert.DNSNames {
		if dns == cert.Subject.CommonName {
			present = true
			break
		}
	}

	if !present {
		cert.DNSNames = append(cert.DNSNames, cert.Subject.CommonName)
	}

	addExtKeyUsage(cert, x509.ExtKeyUsageServerAuth)
	addExtKeyUsage(cert, x509.ExtKeyUsageClientAuth)
	cert.BasicConstraintsValid = true
	cert.IsCA = false
	cert.KeyUsage |= DefaultKeyUsage
}

// SetCAProfile sets typical characteristics of a CA certificate.
func SetCAProfile(cert *x509.Certificate) {
	cert.ExtKeyUsage = nil
	cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert.BasicConstraintsValid = true
	cert.IsCA = true
}

// SetClientProfile sets typical characteristics of a client certificate.
func SetClientProfile(cert *x509.Certificate) {
	addExtKeyUsage(cert, x509.ExtKeyUsageClientAuth)
	cert.BasicConstraintsValid = true
	cert.IsCA = false
	cert.KeyUsage |= DefaultKeyUsage
}

func addExtKeyUsage(cert *x509.Certificate, newUsage x509.ExtKeyUsage) {
	for _, eku := range cert.ExtKeyUsage {
		if eku == newUsage {
			return
		}
	}
	cert.ExtKeyUsage = append(cert.ExtKeyUsage, newUsage)
}
