package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

func newShowCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "show [FILE]",
		Short: "Reads PEM encoded certificates and show information.",
		Long: `Reads PEM encoded certificates and shows information like issuer, subject,
validity used algorithms etc. If no file is provided PEM certificate is read
from STDIN.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var file string
			if len(args) == 0 {
				file = "-"
			} else {
				file = args[0]
			}

			var input io.Reader

			if file == "-" {
				input = os.Stdin
			} else {
				file, err := os.Open(file)
				if err != nil {
					return err
				}
				input = file
			}

			inputBytes, err := io.ReadAll(input)
			if err != nil {
				return err
			}

			certs, err := pcert.ParseAll(inputBytes)
			if err != nil {
				return err
			}

			if len(certs) == 0 {
				return fmt.Errorf("no PEM encoded certificates found in input")
			}

			var printer func(cert *x509.Certificate)
			switch format {
			case "text":
				printer = printText
			case "json":
				printer = printJSON
			case "pem":
				printer = printPEM
			}

			for _, cert := range certs {
				printer(cert)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Format in which to print the certificate information. Valid formats are text, json and pem.")
	return cmd
}

func encodeSerial(s *big.Int) string {
	return hex.EncodeToString(s.Bytes())
}

func printPEM(c *x509.Certificate) {
	pem := pcert.Encode(c.Raw)
	fmt.Printf("%s", pem)
}

func printText(c *x509.Certificate) {
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "subject:    %s\n", c.Subject.String())
	fmt.Fprintf(sb, "serial:     %s\n", encodeSerial(c.SerialNumber))
	fmt.Fprintf(sb, "issuer:     %s\n", c.Issuer.String())
	fmt.Fprintf(sb, "version:    %d\n", c.Version)
	fmt.Fprintf(sb, "not before: %s\n", c.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(sb, "not after:  %s\n", c.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(sb, "public key: %s", c.PublicKeyAlgorithm.String())
	// public key
	switch pk := c.PublicKey.(type) {
	case *rsa.PublicKey:
		fmt.Fprintf(sb, " (%d bit)\n", pk.N.BitLen())
	case *ecdsa.PublicKey:
		fmt.Fprintf(sb, " (%d bit)\n", pk.Params().BitSize)
	default:
		fmt.Fprintln(sb)
	}

	fmt.Fprintf(sb, "signature:  %s\n", c.SignatureAlgorithm.String())

	fmt.Fprintf(sb, "key usage: %s\n", pcert.KeyUsageToString(c.KeyUsage))
	fmt.Fprintf(sb, "extended key usage: %s\n", pcert.ExtKeyUsageToString(c.ExtKeyUsage))
	if c.BasicConstraintsValid {
		fmt.Fprintf(sb, "basic constraints: CA:%t", c.IsCA)
		if c.MaxPathLen > 0 || (c.MaxPathLen == 0 && c.MaxPathLenZero) {
			fmt.Fprintf(sb, " pathLen:%d\n", c.MaxPathLen)
		} else {
			fmt.Fprintln(sb)
		}
	}

	fmt.Fprintf(sb, "subject key identifier: %s\n", hex.EncodeToString(c.SubjectKeyId))
	fmt.Fprintf(sb, "authority key identifier: %s\n", hex.EncodeToString(c.AuthorityKeyId))

	if len(c.OCSPServer) > 0 {
		fmt.Fprintf(sb, "ocsp servers: %s\n", strings.Join(c.OCSPServer, ", "))
	}

	if len(c.IssuingCertificateURL) > 0 {
		fmt.Fprintf(sb, "issuing url: %s\n", strings.Join(c.IssuingCertificateURL, ", "))
	}

	if len(c.DNSNames) > 0 || len(c.IPAddresses) > 0 || len(c.EmailAddresses) > 0 || len(c.URIs) > 0 {
		fmt.Fprintf(sb, "subject alternative names\n")
		for _, dns := range c.DNSNames {
			fmt.Fprintf(sb, "    dns:%s\n", dns)
		}
		for _, ip := range c.IPAddresses {
			fmt.Fprintf(sb, "    ip:%s\n", ip)
		}
		for _, email := range c.EmailAddresses {
			fmt.Fprintf(sb, "    email:%s\n", email)
		}
		for _, uri := range c.URIs {
			fmt.Fprintf(sb, "    uri:%s\n", uri)
		}
	}

	if len(c.PolicyIdentifiers) > 0 {
		fmt.Fprintf(sb, "certificate policies:\n")
		for _, oid := range c.PolicyIdentifiers {
			fmt.Fprintf(sb, "    policy: %s\n", oid.String())
		}
	}
	if len(c.CRLDistributionPoints) > 0 {
		fmt.Fprintf(sb, "CRL distribution points:\n")
		for _, uri := range c.CRLDistributionPoints {
			fmt.Fprintf(sb, "    uri:%s\n", uri)
		}
	}
	fmt.Println(sb.String())
}

func printJSON(cert *x509.Certificate) {
	// TODO: implement proper JSON encoding
	jsonCert := &JSONCertificate{cert}
	out, err := json.MarshalIndent(jsonCert, "", "  ")
	if err != nil {
		// should never fail because all fields are marshalable
		panic(err)
	}
	fmt.Printf("%s\n", out)
}

type JSONCertificate struct {
	*x509.Certificate
}

func (c *JSONCertificate) MarshalJSON() ([]byte, error) {
	publicKeyInfo := map[string]any{
		"algorithm": c.PublicKeyAlgorithm.String(),
	}
	switch publicKey := c.PublicKey.(type) {
	case *rsa.PublicKey:
		publicKeyInfo["size"] = publicKey.N.BitLen()
	case *ecdsa.PublicKey:
		publicKeyInfo["size"] = publicKey.Params().BitSize
	}
	tmp := map[string]any{
		// top level
		"signature_algorithm": c.SignatureAlgorithm.String(),
		"signature":           c.Signature,

		// tbsCertificate
		"public_key":         publicKeyInfo,
		"version":            c.Version,
		"serial_number":      c.SerialNumber,
		"issuer":             c.Issuer.String(),
		"subject":            c.Subject.String(),
		"not_before":         c.NotBefore,
		"not_after":          c.NotAfter,
		"key_usage":          pcert.KeyUsageToStringSlice(c.KeyUsage),
		"extended_key_usage": c.ExtKeyUsage,
		"san": map[string]any{
			"dns":   c.DNSNames,
			"ip":    c.IPAddresses,
			"email": c.EmailAddresses,
			"uri":   c.URIs,
		},
	}
	extensions := []string{}
	for _, extension := range c.Extensions {
		name := "unknown"
		for extName, e := range ext {
			if e.Equal(extension.Id) {
				name = extName
			}
		}
		extensions = append(extensions, extension.Id.String()+" (+"+name+")")
	}
	tmp["extensions"] = extensions
	if c.BasicConstraintsValid {
		constraints := map[string]any{
			"is_ca": c.IsCA,
		}
		if c.MaxPathLen > 0 || (c.MaxPathLen == 0 && c.MaxPathLenZero) {
			constraints["max_path_len"] = c.MaxPathLen
		}

		tmp["basic_constraints"] = constraints
	}

	return json.Marshal(tmp)
}

var ext = map[string]asn1.ObjectIdentifier{
	"SubjectKeyId":          {1, 5, 29, 14},
	"KeyUsage":              {2, 5, 29, 15},
	"ExtendedKeyUsage":      {2, 5, 29, 37},
	"AuthorityKeyId":        {2, 5, 29, 35},
	"BasicConstraints":      {2, 5, 29, 19},
	"SubjectAltName":        {2, 5, 29, 17},
	"CertificatePolicies":   {2, 5, 29, 32},
	"NameConstraints":       {2, 5, 29, 30},
	"CRLDistributionPoints": {2, 5, 29, 31},
	"AuthorityInfoAccess":   {1, 3, 6, 1, 5, 5, 7, 1, 1},
	"CRLNumber":             {2, 5, 29, 20},
}
