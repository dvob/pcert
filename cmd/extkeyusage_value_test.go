package cmd

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/dsbrng25b/pcert"
)

func Test_extKeyUsageValueSet(t *testing.T) {
	var usage []x509.ExtKeyUsage

	value := newExtKeyUsageValue(&usage)

	err := value.Set("ClientAuth")
	if err != nil {
		t.Errorf("failed to set ext key usage: %w", err)
		return
	}

	want := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if !reflect.DeepEqual(usage, want) {
		t.Errorf("crl sign not set: got: %v, want: %s", pcert.ExtKeyUsageToString(usage), pcert.ExtKeyUsageToString(want))
		return
	}

}

func Test_extKeyUsageValueSet_multiple(t *testing.T) {
	var usage []x509.ExtKeyUsage

	value := newExtKeyUsageValue(&usage)

	err := value.Set("ClientAuth,ServerAuth")
	if err != nil {
		t.Errorf("failed to set ext key usage: %w", err)
		return
	}

	want := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if !reflect.DeepEqual(usage, want) {
		t.Errorf("crl sign not set: got: %v, want: %s", pcert.ExtKeyUsageToString(usage), pcert.ExtKeyUsageToString(want))
		return
	}

}

func Test_extKeyUsageValueSet_multiple_separate(t *testing.T) {
	var usage []x509.ExtKeyUsage

	value := newExtKeyUsageValue(&usage)

	err := value.Set("ClientAuth")
	if err != nil {
		t.Errorf("failed to set ext key usage: %w", err)
		return
	}

	err = value.Set("ServerAuth")
	if err != nil {
		t.Errorf("failed to set ext key usage: %w", err)
		return
	}

	want := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if !reflect.DeepEqual(usage, want) {
		t.Errorf("crl sign not set: got: %v, want: %s", pcert.ExtKeyUsageToString(usage), pcert.ExtKeyUsageToString(want))
		return
	}

}
