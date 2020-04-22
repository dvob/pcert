package main

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/dsbrng25b/pcert"
)

func runCmd(args []string) error {
	cmd := newRootCmd()
	cmd.SetArgs(args)
	return cmd.Execute()
}

func runCreateAndLoad(name string, args []string) (*x509.Certificate, error) {
	defer os.Remove(name + ".crt")
	defer os.Remove(name + ".key")
	fullArgs := []string{"create", name}
	fullArgs = append(fullArgs, args...)
	err := runCmd(fullArgs)
	if err != nil {
		return nil, err
	}

	cert, err := pcert.Load(name + ".crt")
	return cert, err
}

func Test_create(t *testing.T) {
	name := "foo1"
	cert, err := runCreateAndLoad("foo1", []string{})
	if err != nil {
		t.Error(err)
		return
	}

	if cert.Subject.CommonName != name {
		t.Errorf("common name no set correctly: got: %s, want: %s", cert.Subject.CommonName, name)
	}
}

func Test_create_subject(t *testing.T) {
	cn := "myCommonName"
	cert, err := runCreateAndLoad("foo2", []string{
		"--subject",
		"CN=" + cn,
	})
	if err != nil {
		t.Error(err)
		return
	}

	if cert.Subject.CommonName != cn {
		t.Errorf("common name no set correctly: got: %s, want: %s", cert.Subject.CommonName, cn)
	}
}

func Test_create_output_parameter(t *testing.T) {
	name := "foo2"
	certFile := "mycert_foo2"
	keyFile := "mykey_foo2"
	defer os.Remove(certFile)
	defer os.Remove(keyFile)
	err := runCmd([]string{
		"create",
		name,
		"--cert",
		certFile,
		"--key",
		keyFile,
	})
	if err != nil {
		t.Error(err)
		return
	}

	_, err = pcert.Load(certFile)
	if err != nil {
		t.Errorf("could not load certificate: %w", err)
	}

	_, err = pcert.LoadKey(keyFile)
	if err != nil {
		t.Errorf("could not load key: %w", err)
	}
}
