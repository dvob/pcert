package pcert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

// create self signed certificate (e.g. CA)
func Create(name string, template *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}

	keyPEM = KeyToPEM(keyDER)

	cert, err := DefaultWithName(name, template)
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
func Request(name string, template *x509.Certificate) (csrPEM []byte, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}

	keyPEM = KeyToPEM(keyDER)

	cert, err := DefaultWithName(name, template)
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
func Sign(csr *x509.CertificateRequest, template *x509.Certificate, signCert *x509.Certificate, signKey interface{}) (certPEM []byte, err error) {
	// name will be set from csr
	cert, err := DefaultWithName("", template)
	if err != nil {
		return nil, err
	}

	applyCSR(csr, cert)

	der, err := x509.CreateCertificate(rand.Reader, cert, signCert, cert.PublicKey, signKey)
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
