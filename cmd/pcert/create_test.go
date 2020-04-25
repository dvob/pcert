package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"

	"github.com/dsbrng25b/pcert"
)

func runCmd(args []string, env map[string]string) error {
	os.Clearenv()
	for k, v := range env {
		os.Setenv(k, v)
	}
	cmd := newRootCmd()
	cmd.SetArgs(args)
	return cmd.Execute()
}

func runCreateAndLoad(name string, args []string, env map[string]string) (*x509.Certificate, error) {
	defer os.Remove(name + ".crt")
	defer os.Remove(name + ".key")
	fullArgs := []string{"create", name}
	fullArgs = append(fullArgs, args...)
	err := runCmd(fullArgs, env)
	if err != nil {
		return nil, err
	}

	cert, err := pcert.Load(name + ".crt")
	return cert, err
}

func Test_create(t *testing.T) {
	name := "foo1"
	cert, err := runCreateAndLoad("foo1", []string{}, nil)
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
	}, nil)
	if err != nil {
		t.Error(err)
		return
	}

	if cert.Subject.CommonName != cn {
		t.Errorf("common name no set correctly: got: %s, want: %s", cert.Subject.CommonName, cn)
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
	cert, err := runCreateAndLoad("subject2", []string{
		"--subject",
		"CN=Bla bla bla/C=CH/L=Bern",
		"--subject",
		"O=Snakeoil Ltd.",
		"--subject",
		"OU=Group 1/OU=Group 2",
	}, nil)

	if err != nil {
		t.Error(err)
		return
	}

	if subject.String() != cert.Subject.String() {
		t.Errorf("subject no set correctly:\n got: %s\nwant: %s", cert.Subject, subject)
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
	cert, err := runCreateAndLoad("subject3", []string{
		"--subject",
		"CN=Bla bla bla",
		"--subject",
		"OU=Group 1/OU=Group 2",
	}, env)

	if err != nil {
		t.Error(err)
		return
	}

	if subject.String() != cert.Subject.String() {
		t.Errorf("subject no set correctly:\n got: %s\nwant: %s", cert.Subject, subject)
	}
}

func Test_create_not_before(t *testing.T) {
	notBefore := time.Date(2020, 10, 27, 12, 0, 0, 0, time.FixedZone("UTC+1", 60*60))
	cert, err := runCreateAndLoad("foo3", []string{
		"--not-before",
		"2020-10-27T12:00:00+01:00",
	}, nil)
	if err != nil {
		t.Error(err)
		return
	}

	if !cert.NotBefore.Equal(notBefore) {
		t.Errorf("not before not set correctly: got: %s, want: %s", cert.NotBefore, notBefore)
	}

	notAfter := notBefore.Add(pcert.DefaultValidityPeriod)
	if !cert.NotAfter.Equal(notAfter) {
		t.Errorf("not after not set correctly: got: %s, want: %s", cert.NotAfter, notAfter)
	}
}

func Test_create_not_before_and_not_after(t *testing.T) {
	notBefore := time.Date(2020, 12, 30, 12, 0, 0, 0, time.FixedZone("UTC+1", 60*60))
	notAfter := time.Date(2022, 12, 30, 12, 0, 0, 0, time.FixedZone("UTC+1", 60*60))
	cert, err := runCreateAndLoad("foo4", []string{
		"--not-before",
		"2020-12-30T12:00:00+01:00",
		"--not-after",
		"2022-12-30T12:00:00+01:00",
	}, nil)
	if err != nil {
		t.Error(err)
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
	cert, err := runCreateAndLoad("foo4", []string{
		"--expiry",
		"3y",
	}, nil)
	if err != nil {
		t.Error(err)
		return
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
	cert, err := runCreateAndLoad("foo4", []string{
		"--not-before",
		"2020-01-01T00:00:00Z",
		"--expiry",
		"90d",
	}, nil)
	if err != nil {
		t.Error(err)
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
	}, nil)
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
