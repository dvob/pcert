package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/dvob/pcert"
)

func runCmd(args []string, stdin io.Reader, env map[string]string) (*bytes.Buffer, *bytes.Buffer, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}

	code := run(args, stdin, stdout, stderr, func(key string) (string, bool) {
		if env == nil {
			return "", false
		}
		val, ok := env[key]
		return val, ok
	})

	if code != 0 {
		return stdout, stderr, fmt.Errorf("execution failed. stderr='%s'", stderr.String())
	}

	return stdout, stderr, nil
}

func runAndLoad(args []string, env map[string]string) (*x509.Certificate, error) {
	stdout, stderr, err := runCmd(args, nil, env)
	if err != nil {
		return nil, err
	}

	if stderr.Len() != 0 {
		return nil, fmt.Errorf("stderr not empty '%s'", stderr.String())
	}

	cert, err := pcert.Parse(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not read certificate from standard output: %s. stdout='%s'", err, stdout.String())
	}

	return cert, err
}

func Test_create(t *testing.T) {
	name := "foo1"
	cert, err := runAndLoad([]string{"create", "--subject", "/CN=" + name}, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	if cert.Subject.CommonName != name {
		t.Fatalf("common name no set correctly: got: %s, want: %s", cert.Subject.CommonName, name)
	}
}

func Test_create_subject_multiple(t *testing.T) {
	subject := pkix.Name{
		CommonName:         "Bla bla bla",
		Country:            []string{"CH"},
		Locality:           []string{"Bern"},
		Organization:       []string{"Snakeoil Ltd."},
		OrganizationalUnit: []string{"Group 1", "Group 2"},
	}
	cert, err := runAndLoad([]string{
		"create",
		"--subject",
		"CN=Bla bla bla/C=CH/L=Bern",
		"--subject",
		"O=Snakeoil Ltd.",
		"--subject",
		"OU=Group 1/OU=Group 2",
	}, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	if subject.String() != cert.Subject.String() {
		t.Fatalf("subject no set correctly:\n got: %s\nwant: %s", cert.Subject, subject)
	}
}

func Test_create_subject_combined_with_environment(t *testing.T) {
	env := map[string]string{
		envVarPrefix + "SUBJECT": "CN=this should be over written/C=CH/L=Bern/O=Snakeoil Ltd.",
	}
	subject := pkix.Name{
		CommonName:         "Bla bla bla",
		Country:            []string{"CH"},
		Locality:           []string{"Bern"},
		Organization:       []string{"Snakeoil Ltd."},
		OrganizationalUnit: []string{"Group 1", "Group 2"},
	}
	cert, err := runAndLoad([]string{
		"create",
		"--subject",
		"CN=Bla bla bla",
		"--subject",
		"OU=Group 1/OU=Group 2",
	}, env)
	if err != nil {
		t.Fatal(err)
		return
	}

	if subject.String() != cert.Subject.String() {
		t.Fatalf("subject no set correctly:\n got: %s\nwant: %s", cert.Subject, subject)
	}
}

func Test_create_not_before(t *testing.T) {
	notBefore := time.Date(2020, 10, 27, 12, 0, 0, 0, time.FixedZone("UTC+1", 60*60))
	cert, err := runAndLoad([]string{
		"create",
		"--not-before",
		"2020-10-27T12:00:00+01:00",
	}, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	if !cert.NotBefore.Equal(notBefore) {
		t.Fatalf("not before not set correctly: got: %s, want: %s", cert.NotBefore, notBefore)
	}

	notAfter := notBefore.Add(pcert.DefaultValidityPeriod)
	if !cert.NotAfter.Equal(notAfter) {
		t.Fatalf("not after not set correctly: got: %s, want: %s", cert.NotAfter, notAfter)
	}
}

func Test_create_not_before_and_not_after(t *testing.T) {
	notBefore := time.Date(2020, 12, 30, 12, 0, 0, 0, time.FixedZone("UTC+1", 60*60))
	notAfter := time.Date(2022, 12, 30, 12, 0, 0, 0, time.FixedZone("UTC+1", 60*60))
	cert, err := runAndLoad([]string{
		"create",
		"--not-before",
		"2020-12-30T12:00:00+01:00",
		"--not-after",
		"2022-12-30T12:00:00+01:00",
	}, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	if !cert.NotBefore.Equal(notBefore) {
		t.Errorf("not before not set correctly: got: %s, want: %s", cert.NotBefore, notBefore)
	}

	if !cert.NotAfter.Equal(notAfter) {
		t.Errorf("not after not set correctly: got: %s, want: %s", cert.NotAfter, notAfter)
	}
}

func Test_create_with_expiry(t *testing.T) {
	now := time.Now().Round(time.Minute)
	cert, err := runAndLoad([]string{
		"create",
		"--expiry",
		"3y",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	actualNotBefore := cert.NotBefore.Round(time.Minute)
	if !actualNotBefore.Equal(now) {
		t.Errorf("not before not set correctly: got: %s, want: %s", actualNotBefore, now)
	}

	expectedNotAfter := now.Add(time.Hour * 24 * 365 * 3)
	actualNotAfter := cert.NotAfter.Round(time.Minute)
	if !actualNotAfter.Equal(expectedNotAfter) {
		t.Errorf("not after not set correctly: got: %s, want: %s", actualNotAfter, expectedNotAfter)
	}
}

func Test_create_not_before_with_expiry(t *testing.T) {
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	cert, err := runAndLoad([]string{
		"create",
		"--not-before",
		"2020-01-01T00:00:00Z",
		"--expiry",
		"90d",
	}, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	if !cert.NotBefore.Equal(notBefore) {
		t.Errorf("not before not set correctly: got: %s, want: %s", cert.NotBefore, notBefore)
	}

	expectedNotAfter := notBefore.Add(time.Hour * 24 * 90)
	if !cert.NotAfter.Equal(expectedNotAfter) {
		t.Errorf("not after not set correctly: got: %s, want: %s", cert.NotAfter, expectedNotAfter)
	}
}

func Test_create_output_parameter(t *testing.T) {
	defer os.Remove("tls.crt")
	defer os.Remove("tls.key")
	_, _, err := runCmd([]string{
		"create",
		"tls.crt",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	_, err = pcert.Load("tls.crt")
	if err != nil {
		t.Errorf("could not load certificate: %s", err)
	}

	_, err = pcert.LoadKey("tls.key")
	if err != nil {
		t.Errorf("could not load key: %s", err)
	}
}
