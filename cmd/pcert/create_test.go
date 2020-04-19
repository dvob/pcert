package main

import (
	"os"
	"testing"

	"github.com/dsbrng25b/pcert"
)

func runCmd(args []string) error {
	cmd := newRootCmd()
	cmd.SetArgs(args)
	return cmd.Execute()
}

func Test_create(t *testing.T) {
	name := "foo1"
	defer os.Remove(name + ".crt")
	defer os.Remove(name + ".key")
	err := runCmd([]string{"create", name})
	if err != nil {
		t.Error(err)
		return
	}

	cert, err := pcert.Load(name + ".crt")
	if err != nil {
		t.Errorf("could not load certificate: %w", err)
	}

	_, err = pcert.LoadKey(name + ".key")
	if err != nil {
		t.Errorf("could not load key: %w", err)
	}

	if cert.Subject.CommonName != name {
		t.Errorf("common name no set correctly: got: %s, want: %s", cert.Subject.CommonName, name)
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
