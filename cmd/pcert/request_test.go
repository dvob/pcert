package main

import (
	"testing"

	"github.com/dvob/pcert"
)

func Test_request(t *testing.T) {
	name := "foo"
	stdout, stderr, err := runCmd([]string{
		"request",
		"--subject",
		"/CN=" + name,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	if stderr.Len() != 0 {
		t.Fatalf("stderr not empty '%s'", stderr.String())
	}

	csr, err := pcert.ParseCSR(stdout.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if csr.Subject.CommonName != name {
		t.Errorf("common name no set correctly: got: %s, want: %s", csr.Subject.CommonName, name)
	}
}
