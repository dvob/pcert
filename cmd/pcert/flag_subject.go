package main

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

func bindSubjectFlags(fs *pflag.FlagSet, subject *pkix.Name) {
	fs.StringSliceVar(&subject.Country, "subject-country", subject.Country, "Subject country (C)")
	fs.StringSliceVar(&subject.Organization, "subject-org", subject.Organization, "Subject organization (O)")
	fs.StringSliceVar(&subject.OrganizationalUnit, "subject-ou", subject.OrganizationalUnit, "Subject organizational unit (OU)")
	fs.StringSliceVar(&subject.Locality, "subject-locality", subject.Locality, "Subject locality (L)")
	fs.StringSliceVar(&subject.Province, "subject-province", subject.Province, "Subject province (P)")
	fs.StringSliceVar(&subject.StreetAddress, "subject-street-address", subject.StreetAddress, "Subject street address (STREET)")
	fs.StringSliceVar(&subject.PostalCode, "subject-postal-code", subject.PostalCode, "Subject postal code (POSTALCODE)")
	fs.StringVar(&subject.SerialNumber, "subject-serial-number", subject.SerialNumber, "Subject serial number (SERIALNUMBER)")
	fs.StringVar(&subject.CommonName, "subject-common-name", subject.CommonName, "Subject common name (CN)")
	fs.StringVarP(&subject.CommonName, "name", "n", subject.CommonName, "Subject common name (CN). alias for --subject-common-name")
}

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
