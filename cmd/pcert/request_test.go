package main

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/dvob/pcert"
)

func runRequestAndLoad(name string, args []string, env map[string]string) (*x509.CertificateRequest, error) {
	defer os.Remove(name + ".csr")
	defer os.Remove(name + ".key")
	fullArgs := []string{"request", name}
	fullArgs = append(fullArgs, args...)
	err := runCmd(fullArgs, env)
	if err != nil {
		return nil, err
	}

	csr, err := pcert.LoadCSR(name + ".csr")
	return csr, err
}

func Test_request(t *testing.T) {
	name := "csr1"
	csr, err := runRequestAndLoad(name, []string{}, nil)
	if err != nil {
		t.Error(err)
		return
	}

	if csr.Subject.CommonName != name {
		t.Errorf("common name no set correctly: got: %s, want: %s", csr.Subject.CommonName, name)
	}
}
