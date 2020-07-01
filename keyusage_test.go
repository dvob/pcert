package pcert

import (
	"crypto/x509"
	"testing"
)

func TestKeyUsageToString(t *testing.T) {
	tests := []struct {
		keyUsage x509.KeyUsage
		expected string
	}{
		{x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageDecipherOnly, "CertSign,DecipherOnly,KeyEncipherment"},
		{x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment, "DataEncipherment,DigitalSignature"},
		{x509.KeyUsage(0), ""},
	}

	for _, test := range tests {
		got := KeyUsageToString(test.keyUsage)
		want := test.expected
		if got != want {
			t.Errorf("got=%s want=%s", got, want)
		}
	}
}

func TestExtKeyUsageToString(t *testing.T) {
	tests := []struct {
		keyUsage []x509.ExtKeyUsage
		expected string
	}{
		{[]x509.ExtKeyUsage{
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		}, "MicrosoftCommercialCodeSigning,MicrosoftServerGatedCrypto"},
		{[]x509.ExtKeyUsage{
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		}, "MicrosoftCommercialCodeSigning,MicrosoftServerGatedCrypto"},
		{[]x509.ExtKeyUsage{
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		}, "MicrosoftCommercialCodeSigning,MicrosoftServerGatedCrypto"},
	}

	for _, test := range tests {
		got := ExtKeyUsageToString(test.keyUsage)
		want := test.expected
		if got != want {
			t.Errorf("got=%s want=%s", got, want)
		}
	}
}
