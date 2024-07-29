package main

import (
	"crypto/x509"
	"strconv"
)

type maxPathLengthValue struct {
	cert *x509.Certificate
}

func newMaxPathLengthValue(cert *x509.Certificate) *maxPathLengthValue {
	return &maxPathLengthValue{
		cert: cert,
	}
}

func (m *maxPathLengthValue) Type() string {
	return "int|-"
}

func (m *maxPathLengthValue) String() string {
	if m.cert.MaxPathLen == 0 && m.cert.MaxPathLenZero {
		return "0"
	}
	if m.cert.MaxPathLen < 0 {
		return "-"
	}
	return strconv.Itoa(m.cert.MaxPathLen)
}

func (m *maxPathLengthValue) Set(length string) error {
	if length == "-" {
		m.cert.MaxPathLen = -1
		m.cert.MaxPathLenZero = false
	}

	value, err := strconv.Atoi(length)
	if err != nil {
		return err
	}
	if value == 0 {
		m.cert.MaxPathLenZero = true
	} else {
		m.cert.MaxPathLenZero = false
	}
	m.cert.MaxPathLen = value
	return nil
}
