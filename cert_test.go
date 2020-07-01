package pcert

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

func createAndParse(name string, signCert *x509.Certificate, signKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	crt := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: name,
		},
	}

	certPEM, keyPEM, err := Create(crt, signCert, signKey)
	if err != nil {
		return nil, nil, err
	}

	crt, err = Parse(certPEM)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := ParseKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}

	return crt, privKey, nil
}

func TestCreate_selfSigned(t *testing.T) {
	crt, _, err := createAndParse("My Server", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if crt.Issuer.CommonName != crt.Subject.CommonName {
		t.Errorf("issuer and subject common name are not equal: subject=%s issuer=%s", crt.Subject.CommonName, crt.Issuer.CommonName)
	}
}

func TestCreate_signed(t *testing.T) {
	caName := "My CA"
	serverName := "My Server"

	caCrt, caPrivKey, err := createAndParse(caName, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	crt, _, err := createAndParse(serverName, caCrt, caPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	if crt.Issuer.CommonName != caCrt.Subject.CommonName {
		t.Errorf("certificate has wrong issuer: got=%s want=%s", caCrt.Subject.CommonName, crt.Issuer.CommonName)
	}
}

func TestCreate_missing_key(t *testing.T) {
	caName := "My CA"
	serverName := "My Server"

	caCrt, _, err := createAndParse(caName, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = createAndParse(serverName, caCrt, nil)

	if err == nil {
		t.Fatal("no error returned")
	}

	if !strings.Contains(err.Error(), "key for signing missing") {
		t.Fatalf("error does not contain string 'key for signing missing': %s", err.Error())
	}
}

func TestCreate_missing_certificate(t *testing.T) {
	caName := "My CA"
	serverName := "My Server"

	_, caPrivKey, err := createAndParse(caName, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = createAndParse(serverName, nil, caPrivKey)

	if err == nil {
		t.Fatal("no error returned")
	}

	if !strings.Contains(err.Error(), "certificate for signing missing") {
		t.Fatalf("error does not contain string 'certificate for signing missing': %s", err.Error())
	}
}
