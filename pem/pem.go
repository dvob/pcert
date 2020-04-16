package pem

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

const (
	CERTIFICATE_TYPE         = "CERTIFICATE"
	CERTIFICATE_REQUEST_TYPE = "CERTIFICATE REQUEST"
	PRIVATE_KEY_TYPE         = "PRIVATE KEY"
)

// Read reads a *x509.Certificate from a PEM encoded file.
func Load(f string) (*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(f)

	if err != nil {
		return nil, err
	}

	return Parse(pem)
}

// ReadKey reads a *crypto.PrivateKey from a PEM encoded file.
func LoadKey(f string) (interface{}, error) {
	pem, err := ioutil.ReadFile(f)

	if err != nil {
		return nil, err
	}

	return ParseKey(pem)
}

// ReadCSR reads a *x509.CertificateRequest from a PEM encoded file.
func LoadCSR(f string) (*x509.CertificateRequest, error) {
	pem, err := ioutil.ReadFile(f)

	if err != nil {
		return nil, err
	}

	return ParseCSR(pem)
}

// Parse returns a *x509.Certificate from PEM encoded data.
func Parse(pem []byte) (*x509.Certificate, error) {
	der, err := parseType(CERTIFICATE_TYPE, pem)

	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// ParseKey returns a *crypto.PrivateKey from PEM encoded data.
func ParseKey(pem []byte) (key interface{}, err error) {
	der, err := parseType(PRIVATE_KEY_TYPE, pem)

	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS8PrivateKey(der)
}

// ParseCSR returns a *x509.CertificateRequest from PEM encoded data.
func ParseCSR(pem []byte) (*x509.CertificateRequest, error) {
	der, err := parseType(CERTIFICATE_REQUEST_TYPE, pem)

	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(der)
}

func parseType(blockType string, bytes []byte) ([]byte, error) {
	block, _ := pem.Decode(bytes)

	if block == nil {
		return nil, fmt.Errorf("no pem data found")
	}

	if block.Type != blockType {
		return nil, fmt.Errorf("pem block is not of type '%s'", blockType)
	}

	return block.Bytes, nil
}

// Encode encodes DER encoded certificate into PEM encoding
func Encode(derBytes []byte) []byte {
	return encode(CERTIFICATE_TYPE, derBytes)
}

// EncodeKey encodes a *crypto.PrivateKey into PEM encoding by using x509.MarshalPKCS8PrivateKey
func EncodeKey(priv interface{}) ([]byte, error) {
	pkcs8der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return encode(PRIVATE_KEY_TYPE, pkcs8der), nil
}

// EncodeCSR encodes DER encoded CSR into PEM encoding
func EncodeCSR(derBytes []byte) []byte {
	return encode(CERTIFICATE_REQUEST_TYPE, derBytes)
}

func encode(blockType string, bytes []byte) []byte {
	block := &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	}

	return pem.EncodeToMemory(block)
}
