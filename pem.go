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

func KeyFromPEM(pem []byte) (key interface{}, err error) {
	der, err := fromPEM(privateKeyBlockType, pem)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(der)
}

func CSRFromPEM(pem []byte) (*x509.CertificateRequest, error) {
	der, err := fromPEM(certificateRequestBlockType, pem)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

func CertificateFromPEM(pem []byte) (*x509.Certificate, error) {
	der, err := fromPEM(certificateBlockType, pem)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func FromFile(f string) (*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return CertificateFromPEM(pem)
}

func KeyFromFile(f string) (interface{}, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return KeyFromPEM(pem)
}

func CSRFromFile(f string) (*x509.CertificateRequest, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return CSRFromPEM(pem)
}
