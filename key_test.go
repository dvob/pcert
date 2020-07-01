package pcert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
)

func TestGenerateKey_default(t *testing.T) {
	priv, pub, err := GenerateKey(KeyOptions{})
	if err != nil {
		t.Fatal("failed to create key", err)
	}

	_, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("private key is not of type ecdsa.PrivateKey")
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Error("public key is not of type ecdsa.PublicKey")
	}

	want := elliptic.P256().Params().Name
	got := ecdsaPub.Params().Name
	if got != want {
		t.Errorf("curve not set to default curve: got=%s want=%s", got, want)
	}
}

func TestGenerateKey_ecdsaInvalid(t *testing.T) {
	_, _, err := GenerateKey(KeyOptions{x509.ECDSA, 123})
	if err == nil {
		t.Fatal("generate key did not fail with invalid key size")
	}

	if !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("error string does not contain invalid size: '%s'", err.Error())
	}
}

func TestGenerateKey_ecdsa(t *testing.T) {
	tests := []struct {
		size         int
		expectedName string
	}{
		{0, elliptic.P256().Params().Name},
		{224, elliptic.P224().Params().Name},
		{256, elliptic.P256().Params().Name},
		{384, elliptic.P384().Params().Name},
		{521, elliptic.P521().Params().Name},
	}
	for _, test := range tests {
		priv, pub, err := GenerateKey(KeyOptions{x509.ECDSA, test.size})
		if err != nil {
			t.Error("failed to create key", err)
			continue
		}
		_, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			t.Error("private key is not of type ecdsa.PrivateKey")
		}

		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Error("public key is not of type ecdsa.PublicKey")
		}

		want := test.expectedName
		got := ecdsaPub.Params().Name
		if got != want {
			t.Errorf("curve not set to default curve: got=%s want=%s", got, want)
		}

	}
}

func TestGenerateKey_rsa(t *testing.T) {
	tests := []struct {
		inputSize       int
		expectedKeySize int
	}{
		{0, defaultRSAKeySize},
		{1024, 1024},
		{4096, 4096},
	}

	for _, test := range tests {
		priv, pub, err := GenerateKey(KeyOptions{x509.RSA, test.inputSize})
		if err != nil {
			t.Error("failed to create key", err)
			continue
		}

		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			t.Error("private key is not of type rsa.PrivateKey")
		}

		_, ok = pub.(*rsa.PublicKey)
		if !ok {
			t.Error("public key is not of type rsa.PublicKey")
		}

		got := rsaPriv.N.BitLen()
		want := test.expectedKeySize

		if got != want {
			t.Errorf("wrong key size: got=%d want=%d", got, want)
		}
	}
}

func TestGenerateKey_ed25519(t *testing.T) {
	priv, pub, err := GenerateKey(KeyOptions{x509.Ed25519, 0})
	if err != nil {
		t.Fatal("failed to create key", err)
	}

	_, ok := priv.(ed25519.PrivateKey)
	if !ok {
		t.Error("private key is not of type ed25519.PrivateKey")
	}

	_, ok = pub.(ed25519.PublicKey)
	if !ok {
		t.Error("public key is not of type ed25519.PublicKey")
	}
}
