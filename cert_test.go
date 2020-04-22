package pcert

import (
	"crypto/x509"
	"testing"
)

func TestCreate_selfSigned(t *testing.T) {
	crt := &x509.Certificate{}
	crtPEM, keyPEM, err := Create(crt, nil, nil)
	if err != nil {
		t.Errorf("failed to create self signed certificate: %w", err)
		return
	}

	_, err = Parse(crtPEM)
	if err != nil {
		t.Errorf("failed to parse cert PEM: %w", err)
		return
	}

	_, err = ParseKey(keyPEM)
	if err != nil {
		t.Errorf("failed to parse key PEM: %w", err)
		return
	}
}
