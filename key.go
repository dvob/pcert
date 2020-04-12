package pcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

type KeyConfig struct {
	Algorithm string
	Size      int
}

func NewDefaultKeyConfig() KeyConfig {
	return KeyConfig{"ecdsa", 256}
}

func GenerateKey(config KeyConfig) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch config.Algorithm {
	case "rsa":
		priv, err := rsa.GenerateKey(rand.Reader, config.Size)
		if err != nil {
			return nil, nil, err
		}
		pub := priv.Public()
		return priv, pub, err
	case "ecdsa":
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
	case "ed25519":
		return ed25519.GenerateKey(rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unknown key algorithm: %s", config.Algorithm)
	}
}
