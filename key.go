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

var (
	defaultAlgorithm    = x509.ECDSA
	defaultRSAKeySize   = 2048
	defaultECDSAKeySize = 256
)

// KeyOptions specifies a key algorithm and a size
type KeyOptions struct {
	Algorithm x509.PublicKeyAlgorithm
	Size      int
}

// PublicKeyAlgorithms which are supported to create x509 certificates
var PublicKeyAlgorithms = []x509.PublicKeyAlgorithm{
	x509.RSA,
	x509.ECDSA,
	x509.Ed25519,
}

// GenerateKey returns a private and a public key based on the options.
// If no PublicKeyAlgorithm is set in the options ECDSA is used. If no key size
// is set in the options 256 bit is used for ECDSA and 2048 bit for RSA.
// For ECDSA the following sizes are valid: 224, 256, 384 and 521.
// For the x509.Ed25519 algorithm the size in the KeyOptions is ignored.
func GenerateKey(opts KeyOptions) (crypto.PrivateKey, crypto.PublicKey, error) {
	if opts.Algorithm == x509.UnknownPublicKeyAlgorithm {
		opts.Algorithm = defaultAlgorithm
	}

	if opts.Size == 0 {
		if opts.Algorithm == x509.RSA {
			opts.Size = defaultRSAKeySize
		} else if opts.Algorithm == x509.ECDSA {
			opts.Size = defaultECDSAKeySize
		}
	}

	switch opts.Algorithm {
	case x509.RSA:
		priv, err := rsa.GenerateKey(rand.Reader, opts.Size)
		if err != nil {
			return nil, nil, err
		}

		pub := priv.Public()
		return priv, pub, err

	case x509.ECDSA:
		var curve elliptic.Curve

		switch opts.Size {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("invalid size for ecdsa")
		}

		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		pub := priv.Public()
		return priv, pub, nil

	case x509.Ed25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, pub, err

	default:
		return nil, nil, fmt.Errorf("unknown key algorithm: %s", opts.Algorithm)

	}
}
