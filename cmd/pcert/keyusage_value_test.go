package main

import (
	"crypto/x509"
	"testing"
)

func Test_keyUsageValueSet(t *testing.T) {
	var usage x509.KeyUsage

	value := newKeyUsageValue(&usage)

	err := value.Set("CRLSign")
	if err != nil {
		t.Errorf("failed to set CRLSign: %s", err)
		return
	}

	if usage != x509.KeyUsageCRLSign {
		t.Errorf("crl sign not set: got: %d, want: %d", value, x509.KeyUsageCRLSign)
		return
	}
}

func Test_keyUsageValueSet_multiple(t *testing.T) {
	var usage x509.KeyUsage

	value := newKeyUsageValue(&usage)

	err := value.Set("CRLSign,CertSign")
	if err != nil {
		t.Errorf("failed to set CRLSign,CertSign: %s", err)
		return
	}

	want := x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	if usage != want {
		t.Errorf("crl sign not set: got: %d, want: %d", usage, want)
		return
	}
}

func Test_keyUsageValueSet_multiple_separate(t *testing.T) {
	var usage x509.KeyUsage

	value := newKeyUsageValue(&usage)

	err := value.Set("CRLSign")
	if err != nil {
		t.Errorf("failed to set CRLSign: %s", err)
		return
	}
	err = value.Set("CertSign")
	if err != nil {
		t.Errorf("failed to set CertSign: %s", err)
		return
	}

	want := x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	if usage != want {
		t.Errorf("crl sign not set: got: %d, want: %d", usage, want)
		return
	}
}
