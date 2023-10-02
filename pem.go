package pcert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	certificateBlock        = "CERTIFICATE"
	certificateRequestBlock = "CERTIFICATE REQUEST"
	privateKeyBlock         = "PRIVATE KEY"
	ecPrivateKeyBlock       = "EC PRIVATE KEY"
)

// Load reads a *x509.Certificate from a PEM encoded file.
func Load(f string) (*x509.Certificate, error) {
	pem, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}

	return Parse(pem)
}

// LoadKey reads a *crypto.PrivateKey from a PEM encoded file.
func LoadKey(f string) (any, error) {
	pem, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}

	return ParseKey(pem)
}

// LoadCSR reads a *x509.CertificateRequest from a PEM encoded file.
func LoadCSR(f string) (*x509.CertificateRequest, error) {
	pem, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}

	return ParseCSR(pem)
}

// Parse returns a *x509.Certificate from PEM encoded data.
func Parse(pem []byte) (*x509.Certificate, error) {
	block, err := parsePEM(pem)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(block.Bytes)
}

// ParseAll returns a list of x509.Certificates from a list of concatenated PEM
// encoded certificates.
func ParseAll(data []byte) ([]*x509.Certificate, error) {
	var (
		certs []*x509.Certificate
		block *pem.Block
	)
	for {
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ParseKey returns a *crypto.PrivateKey from PEM encoded data.
func ParseKey(pem []byte) (key any, err error) {
	block, err := parsePEM(pem)
	if err != nil {
		return nil, err
	}

	if block.Type == ecPrivateKeyBlock {
		return x509.ParseECPrivateKey(block.Bytes)
	}

	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// ParseCSR returns a *x509.CertificateRequest from PEM encoded data.
func ParseCSR(pem []byte) (*x509.CertificateRequest, error) {
	block, err := parsePEM(pem)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(block.Bytes)
}

func parsePEM(bytes []byte) (*pem.Block, error) {
	block, _ := pem.Decode(bytes)

	if block == nil {
		return nil, fmt.Errorf("no pem data found")
	}

	return block, nil
}

// Encode encodes DER encoded certificate into PEM encoding
func Encode(derBytes []byte) []byte {
	return encode(certificateBlock, derBytes)
}

// EncodeKey encodes a *crypto.PrivateKey into PEM encoding by using x509.MarshalPKCS8PrivateKey
func EncodeKey(priv any) ([]byte, error) {
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
