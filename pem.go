package pcert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

const (
	certificateBlock        = "CERTIFICATE"
	certificateRequestBlock = "CERTIFICATE REQUEST"
	privateKeyBlock         = "PRIVATE KEY"
)

// Load reads a *x509.Certificate from a PEM encoded file.
func Load(f string) (*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}

	return Parse(pem)
}

// LoadKey reads a *crypto.PrivateKey from a PEM encoded file.
func LoadKey(f string) (interface{}, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}

	return ParseKey(pem)
}

// LoadCSR reads a *x509.CertificateRequest from a PEM encoded file.
func LoadCSR(f string) (*x509.CertificateRequest, error) {
	pem, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}

	return ParseCSR(pem)
}

// Parse returns a *x509.Certificate from PEM encoded data.
func Parse(pem []byte) (*x509.Certificate, error) {
	der, err := parsePEM(pem)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// ParseKey returns a *crypto.PrivateKey from PEM encoded data.
func ParseKey(pem []byte) (key interface{}, err error) {
	der, err := parsePEM(pem)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS8PrivateKey(der)
}

// ParseCSR returns a *x509.CertificateRequest from PEM encoded data.
func ParseCSR(pem []byte) (*x509.CertificateRequest, error) {
	der, err := parsePEM(pem)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(der)
}

func parsePEM(bytes []byte) ([]byte, error) {
	block, _ := pem.Decode(bytes)

	if block == nil {
		return nil, fmt.Errorf("no pem data found")
	}

	return block.Bytes, nil
}

// Encode encodes DER encoded certificate into PEM encoding
func Encode(derBytes []byte) []byte {
	return encode(certificateBlock, derBytes)
}

// EncodeKey encodes a *crypto.PrivateKey into PEM encoding by using x509.MarshalPKCS8PrivateKey
func EncodeKey(priv interface{}) ([]byte, error) {
	pkcs8der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return encode(privateKeyBlock, pkcs8der), nil
}

// EncodeCSR encodes DER encoded CSR into PEM encoding
func EncodeCSR(derBytes []byte) []byte {
	return encode(certificateRequestBlock, derBytes)
}

func encode(blockType string, bytes []byte) []byte {
	block := &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	}

	return pem.EncodeToMemory(block)
}
