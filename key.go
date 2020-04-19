package pcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// KeyConfig specifies a key algorithm and a size
type KeyConfig struct {
	Algorithm x509.PublicKeyAlgorithm
	Size      int
}

// PublicKeyAlgorithms which are supported to create x509 certificates
var PublicKeyAlgorithms = []x509.PublicKeyAlgorithm{
	x509.RSA,
	x509.ECDSA,
	x509.Ed25519,
}

// GenerateKey returns a private and a public key based on the config.
// If no PublicKeyAlgorithm is set in the config ECDSA is used. If no key size
// is set in the config 256 bit is used for ECDSA and 2048 for RSA.
func GenerateKey(config KeyConfig) (crypto.PrivateKey, crypto.PublicKey, error) {
	if config.Algorithm == x509.UnknownPublicKeyAlgorithm {
		config.Algorithm = x509.ECDSA
	}

	if config.Size == 0 {
		if config.Algorithm == x509.RSA {
			config.Size = 2048
		} else if config.Algorithm == x509.ECDSA {
			config.Size = 256
		}
	}

	switch config.Algorithm {
	case x509.RSA:
		priv, err := rsa.GenerateKey(rand.Reader, config.Size)
		if err != nil {
			return nil, nil, err
		}
		pub := priv.Public()
		return priv, pub, err
	case x509.ECDSA:
		var curve elliptic.Curve
		switch config.Size {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub := priv.Public()
		return priv, pub, nil
	case x509.Ed25519:
		return ed25519.GenerateKey(rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unknown key algorithm: %s", config.Algorithm)
	}
}
