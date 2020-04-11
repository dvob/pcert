package pcert

import (
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

const (
	DefaultValidityPeriod     = time.Hour * 24 * 90
	DefaultSignatureAlgorithm = x509.SHA256WithRSA
)

func DefaultWithName(name string, template *x509.Certificate) (*x509.Certificate, error) {
	template.Subject = pkix.Name{CommonName: name}
	Default(template)
	return template, nil
}

func Default(c *x509.Certificate) {
	defaultSerialNumber(c)

	if c.NotBefore.IsZero() {
		c.NotBefore = time.Now()
	}

	if c.NotAfter.IsZero() {
		c.NotAfter = time.Now().Add(DefaultValidityPeriod)
	}

	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		c.SignatureAlgorithm = DefaultSignatureAlgorithm
	}
}

func defaultSerialNumber(c *x509.Certificate) {
	if c.SerialNumber != nil {
		return
	}
	maxuint64 := ^uint64(0)
	maxint64 := int64(maxuint64 >> 1)
	c.SerialNumber = big.NewInt(rand.Int63n(maxint64))
}

func defaultSecureSerialNumber(c *x509.Certificate) error {
	if c.SerialNumber != nil {
		return nil
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cryptorand.Int(cryptorand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}
	c.SerialNumber = serialNumber
	return nil
}
