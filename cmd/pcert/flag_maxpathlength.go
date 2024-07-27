package main

import (
	"crypto/x509"
	"strconv"
)

type maxPathLengthValue struct {
	cert *x509.Certificate
}

func newMaxPathLengthValue(c *x509.Certificate) *maxPathLengthValue {
	return &maxPathLengthValue{
		cert: c,
	}
}

func (m *maxPathLengthValue) Type() string {
	return "int|none"
}

func (m *maxPathLengthValue) String() string {
	if m.cert.MaxPathLen < 0 {
		return "none"
	}
	if m.cert.MaxPathLen == 0 && !m.cert.MaxPathLenZero {
		return "none"
	}
	return strconv.Itoa(m.cert.MaxPathLen)
}

func (m *maxPathLengthValue) Set(length string) error {
	var err error
	if length == "none" {
		m.cert.MaxPathLen = -1
		return nil
	}

	m.cert.MaxPathLen, err = strconv.Atoi(length)
	return err
}
