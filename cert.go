package pcert

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
)

// create self signed certificate (e.g. CA)
func Create(cert, signCert *x509.Certificate, keyConfig KeyConfig, signKey crypto.PrivateKey) (certPEM, keyPEM []byte, err error) {
	priv, pub, err := GenerateKey(keyConfig)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}

	keyPEM = KeyToPEM(keyDER)

	err = Default(cert)
	if err != nil {
		return
	}

	cert.SubjectKeyId, err = getSubjectKeyId(pub)
	if err != nil {
		err = fmt.Errorf("failed to calculate subject key id: %w", err)
		return
	}

	var der []byte
	// If either signCert or signKey is missing we self sign the certificate
	if signCert == nil || signKey == nil {
		cert.AuthorityKeyId = cert.SubjectKeyId
		der, err = x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	} else {
		der, err = x509.CreateCertificate(rand.Reader, cert, signCert, pub, signKey)
	}

	if err != nil {
		return
	}

	certPEM = CertificateToPEM(der)

	return
}

// create CSR
func Request(cert *x509.Certificate, keyConfig KeyConfig) (csrPEM []byte, keyPEM []byte, err error) {
	priv, _, err := GenerateKey(keyConfig)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}

	keyPEM = KeyToPEM(keyDER)

	der, err := x509.CreateCertificateRequest(rand.Reader, toCSR(cert), priv)
	if err != nil {
		return
	}

	csrPEM = CSRToPEM(der)

	return
}

// sign a CSR
func Sign(csr *x509.CertificateRequest, cert *x509.Certificate, signCert *x509.Certificate, signKey interface{}) (certPEM []byte, err error) {
	// name will be set from csr
	err = Default(cert)
	if err != nil {
		return nil, err
	}

	applyCSR(csr, cert)

	cert.SubjectKeyId, err = getSubjectKeyId(cert.PublicKey)
	if err != nil {
		err = fmt.Errorf("failed to calculate subject key id: %w", err)
		return
	}

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

func toCSR(cert *x509.Certificate) *x509.CertificateRequest {
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

func getSubjectKeyId(pub crypto.PublicKey) ([]byte, error) {
	encodedPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(encodedPub)
	return pubHash[:], nil
}
