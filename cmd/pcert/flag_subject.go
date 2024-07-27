package main

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

type subjectValue struct {
	value *pkix.Name
}

func newSubjectValue(subject *pkix.Name) *subjectValue {
	return &subjectValue{
		value: subject,
	}
}

func (s *subjectValue) Type() string {
	return "subject"
}

func (s *subjectValue) String() string {
	return s.value.String()
}

func (s *subjectValue) Set(subject string) error {
	return parseSubjectInto(subject, s.value)
}

func parseSubjectInto(subject string, target *pkix.Name) error {
	for _, part := range strings.Split(subject, "/") {
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return fmt.Errorf("failed to parse subject. could not split '%s'", part)
		}

		// https://datatracker.ietf.org/doc/html/rfc4519#section-2
		switch key {
		case "C":
			target.Country = append(target.Country, value)
		case "O":
			target.Organization = append(target.Organization, value)
		case "OU":
			target.OrganizationalUnit = append(target.OrganizationalUnit, value)
		case "L":
			target.Locality = append(target.Locality, value)
		case "P":
			target.Province = append(target.Province, value)
		case "STREET":
			target.StreetAddress = append(target.StreetAddress, value)
		case "POSTALCODE":
			target.PostalCode = append(target.PostalCode, value)
		case "SERIALNUMBER":
			target.SerialNumber = value
		case "CN":
			target.CommonName = value
		default:
			return fmt.Errorf("unknown field '%s'", key)
		}
	}
	return nil
}
