package pcert

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"math/big"
	"time"
)

const (
	DefaultValidityPeriod = time.Hour * 24 * 365
)

func Create(cert *x509.Certificate, signCert *x509.Certificate, signKey crypto.PrivateKey) (certPEM, keyPEM []byte, err error) {
	return CreateWithKeyConfig(cert, NewDefaultKeyConfig(), signCert, signKey)
}

func CreateWithKeyConfig(cert *x509.Certificate, keyConfig KeyConfig, signCert *x509.Certificate, signKey crypto.PrivateKey) (certPEM, keyPEM []byte, err error) {
	priv, pub, err := GenerateKey(keyConfig)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}

	keyPEM = keyToPEM(keyDER)

	// If either signCert or signKey is missing we self sign the certificate
	if signCert == nil || signKey == nil {
		certPEM, err = Sign(cert, pub, cert, priv)
	} else {
		certPEM, err = Sign(cert, pub, signCert, signKey)
	}
	return
}

func Sign(cert *x509.Certificate, publicKey interface{}, signCert *x509.Certificate, signKey interface{}) (certPEM []byte, err error) {
	if cert.SubjectKeyId == nil {
		subjectKeyId, err := getSubjectKeyId(publicKey)
		if err != nil {
			return nil, err
		}
		cert.SubjectKeyId = subjectKeyId
	}
	if cert.AuthorityKeyId == nil {
		cert.AuthorityKeyId = signCert.SubjectKeyId
	}

	if cert.NotBefore.IsZero() {
		cert.NotBefore = time.Now()
	}

	if cert.NotAfter.IsZero() {
		cert.NotAfter = cert.NotBefore.Add(DefaultValidityPeriod)
	}

	if cert.SerialNumber == nil {
		serialNumber, err := getRandomSerialNumber()
		if err != nil {
			return nil, err
		}
		cert.SerialNumber = serialNumber
	}

	der, err := x509.CreateCertificate(rand.Reader, cert, signCert, publicKey, signKey)
	if err != nil {
		return nil, err
	}

	return certificateToPEM(der), nil
}

func Request(cert *x509.Certificate) (csrPEM []byte, keyPEM []byte, err error) {
	return RequestWithKeyOption(cert, NewDefaultKeyConfig())
}

// create CSR
func RequestWithKeyOption(cert *x509.Certificate, keyConfig KeyConfig) (csrPEM []byte, keyPEM []byte, err error) {
	priv, _, err := GenerateKey(keyConfig)
	if err != nil {
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}

	keyPEM = keyToPEM(keyDER)

	der, err := x509.CreateCertificateRequest(rand.Reader, toCSR(cert), priv)
	if err != nil {
		return
	}

	csrPEM = csrToPEM(der)

	return
}

// SignCSR applies the settings from csr and return the signed certificate
func SignCSR(csr *x509.CertificateRequest, cert *x509.Certificate, signCert *x509.Certificate, signKey interface{}) (certPEM []byte, err error) {
	// TODO: settings from cert should take precedence
	applyCSR(csr, cert)

	return Sign(cert, csr.PublicKey, signCert, signKey)
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

func getRandomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}
