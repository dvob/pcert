package pcert

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
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

// Create creates a x509.Certificate and a key with the default key options. See CreateWithKeyOptions for more details.
func Create(cert, signCert *x509.Certificate, signKey crypto.PrivateKey) (certPEM, keyPEM []byte, err error) {
	return CreateWithKeyOptions(cert, KeyOptions{}, signCert, signKey)
}

// CreateWithKeyOptions creates a key and certificate. The certificate is signed
// used signCert and signKey. If signCert or signKey are nil, a self-signed
// certificate will be created. The certificate and the key are returned PEM encoded.
func CreateWithKeyOptions(cert *x509.Certificate, keyOptions KeyOptions, signCert *x509.Certificate, signKey crypto.PrivateKey) (certPEM, keyPEM []byte, err error) {
	priv, pub, err := GenerateKey(keyOptions)
	if err != nil {
		return
	}

	keyPEM, err = EncodeKey(priv)
	if err != nil {
		return
	}

	// If signCert and signKey are missing we self sign the certificate
	if signCert == nil && signKey == nil {
		certPEM, err = Sign(cert, pub, cert, priv)
	} else if signCert != nil && signKey != nil {
		certPEM, err = Sign(cert, pub, signCert, signKey)
	} else {
		if signCert == nil {
			return nil, nil, fmt.Errorf("certificate for signing missing")
		}
		return nil, nil, fmt.Errorf("private key for signing missing")
	}
	return certPEM, keyPEM, err
}

// Sign set some defaults on a certificate and signs it with the  signCert and
// the signKey. The following defaults are set they are not set explicitly in the
// certificate:
//
//   - SubjectKeyId is generated based on the publicKey
//   - The AuthorityKeyId is set based on the SubjectKeyId of the signCert
//   - NotBefore is set to time.Now()
//   - NotAfter is set to NotBefore + DefaultValidityPeriod
//   - SerialNumber is set to a randomly generated serial number
//
// The created certificate is returned PEM encoded.
func Sign(cert *x509.Certificate, publicKey any, signCert *x509.Certificate, signKey any) (certPEM []byte, err error) {
	if cert.SubjectKeyId == nil {
		subjectKeyID, err := getSubjectKeyID(publicKey)
		if err != nil {
			return nil, err
		}
		cert.SubjectKeyId = subjectKeyID
	}
	if cert.AuthorityKeyId == nil {
		// TODO: is probably already done in Go
		cert.AuthorityKeyId = signCert.SubjectKeyId
	}

	if cert.NotBefore.IsZero() {
		cert.NotBefore = time.Now()
	}

	if cert.NotAfter.IsZero() {
		cert.NotAfter = cert.NotBefore.Add(DefaultValidityPeriod)
	}

	if cert.SerialNumber == nil {
		serialNumber, err := generateSerial(rand.Reader)
		if err != nil {
			return nil, err
		}
		cert.SerialNumber = serialNumber
	}

	der, err := x509.CreateCertificate(rand.Reader, cert, signCert, publicKey, signKey)
	if err != nil {
		return nil, err
	}

	return Encode(der), nil
}

// Request creates a CSR and a key. The key is created with the default key
// options. See RequestWithKeyOptions for more details.
func Request(csr *x509.CertificateRequest) (csrPEM, keyPEM []byte, err error) {
	return RequestWithKeyOptions(csr, KeyOptions{})
}

// RequestWithKeyOptions creates a CSR and a key based on key options.  The key is
// created with the default key options.
func RequestWithKeyOptions(csr *x509.CertificateRequest, keyOptions KeyOptions) (csrPEM, keyPEM []byte, err error) {
	priv, _, err := GenerateKey(keyOptions)
	if err != nil {
		return
	}

	keyPEM, err = EncodeKey(priv)
	if err != nil {
		return
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
	if err != nil {
		return
	}

	csrPEM = EncodeCSR(der)

	return
}

// SignCSR applies the settings from csr and return the signed certificate
func SignCSR(csr *x509.CertificateRequest, cert, signCert *x509.Certificate, signKey any) (certPEM []byte, err error) {
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

func getSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	encodedPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(encodedPub)
	return pubHash[:], nil
}

// GenerateSerial produces an RFC 5280 conformant serial number to be used
// in a certificate. The serial number will be a positive integer, no more
// than 20 octets in length, generated using the provided random source.
//
// Code from: https://go-review.googlesource.com/c/go/+/479120/3/src/crypto/x509/x509.go#2485
func generateSerial(rand io.Reader) (*big.Int, error) {
	randBytes := make([]byte, 20)
	for i := 0; i < 10; i++ {
		// get 20 random bytes
		_, err := io.ReadFull(rand, randBytes)
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
