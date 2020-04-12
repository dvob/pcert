package pcert

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

const (
	DefaultValidityPeriod = time.Hour * 24 * 365
	DefaultKeyUsage       = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
)

var (
	defaultExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
)

func Default(template *x509.Certificate) error {
	defaultTime(template)
	defaultKeyUsage(template)
	err := defaultSerialNumber(template)
	return err
}

func defaultCA(c *x509.Certificate) {
	c.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	c.IsCA = true
	c.BasicConstraintsValid = true
}

func defaultKeyUsage(c *x509.Certificate) {
	if c.KeyUsage != 0 {
		return
	}
	c.KeyUsage = DefaultKeyUsage

	if len(c.ExtKeyUsage) == 0 {
		c.ExtKeyUsage = defaultExtKeyUsage
	}
}

func defaultTime(c *x509.Certificate) {
	if c.NotBefore.IsZero() {
		c.NotBefore = time.Now()
	}

	if c.NotAfter.IsZero() {
		c.NotAfter = time.Now().Add(DefaultValidityPeriod)
	}
}

func defaultSerialNumber(c *x509.Certificate) error {
	if c.SerialNumber != nil {
		return nil
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}
	c.SerialNumber = serialNumber
	return nil
}
