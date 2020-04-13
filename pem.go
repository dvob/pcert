package pcert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

const (
	certificateBlockType        = "CERTIFICATE"
	certificateRequestBlockType = "CERTIFICATE REQUEST"
	privateKeyBlockType         = "PRIVATE KEY"
)

// FromFile reads a *x509.Certificate from a PEM encoded file.
func FromFile(f string) (*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return FromPEM(pem)
}

// KeyFromFile reads a *crypto.PrivateKey from a PEM encoded file.
func KeyFromFile(f string) (interface{}, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return KeyFromPEM(pem)
}

// CSRFromFile reads a *x509.CertificateRequest from a PEM encoded file.
func CSRFromFile(f string) (*x509.CertificateRequest, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return CSRFromPEM(pem)
}

// FromPEM returns a *x509.Certificate from PEM encoded data.
func FromPEM(pem []byte) (*x509.Certificate, error) {
	der, err := fromPEM(certificateBlockType, pem)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// KeyFromPEM returns a *crypto.PrivateKey from PEM encoded data.
func KeyFromPEM(pem []byte) (key interface{}, err error) {
	der, err := fromPEM(privateKeyBlockType, pem)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(der)
}

// CSRFromPEM returns a *x509.CertificateRequest from PEM encoded data.
func CSRFromPEM(pem []byte) (*x509.CertificateRequest, error) {
	der, err := fromPEM(certificateRequestBlockType, pem)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

func toPEM(blockType string, bytes []byte) []byte {

	block := &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	}

	return pem.EncodeToMemory(block)
}

func certificateToPEM(derBytes []byte) []byte {
	return toPEM(certificateBlockType, derBytes)
}

func csrToPEM(derBytes []byte) []byte {
	return toPEM(certificateRequestBlockType, derBytes)
}

func keyToPEM(derBytes []byte) []byte {
	return toPEM(privateKeyBlockType, derBytes)
}

func fromPEM(blockType string, bytes []byte) ([]byte, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("no pem data found")
	}

	if block.Type != blockType {
		return nil, fmt.Errorf("pem block is not of type '%s'", blockType)
	}

	return block.Bytes, nil
}
