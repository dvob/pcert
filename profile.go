package pcert

import (
	"crypto/x509"
)

const (
	DefaultKeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
)

func SetServerProfile(cert *x509.Certificate) {
	addExtKeyUsage(cert, x509.ExtKeyUsageServerAuth)
	cert.KeyUsage |= DefaultKeyUsage
}

func SetCAProfile(cert *x509.Certificate) {
	cert.ExtKeyUsage = nil
	cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert.BasicConstraintsValid = true
	cert.IsCA = true
}

func SetClientProfile(cert *x509.Certificate) {
	addExtKeyUsage(cert, x509.ExtKeyUsageClientAuth)
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
