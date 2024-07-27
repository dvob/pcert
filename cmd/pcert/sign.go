package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var (
		profiles []string

		csrLocation string

		certOpts     pcert.CertificateOptions
		certLocation string

		defaultSignCertLocation = "ca.crt"
		signCertLocation        = defaultSignCertLocation
		signKeyLocation         string
	)
	cmd := &cobra.Command{
		Use:   "sign INPUT-CSR OUTPUT-CERTIFICATE",
		Short: "Create a certificate based on a CSR",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			csrLocation = args[0]
			certLocation = args[1]

			if signKeyLocation == "" && isFile(signCertLocation) {
				signKeyLocation = getKeyRelativeToFile(signCertLocation)
			}

			var (
				stdin    []byte
				err      error
				csr      *x509.CertificateRequest
				signCert *x509.Certificate
				signKey  any
			)

			if !isFile(csrLocation) || !isFile(signCertLocation) || !isFile(signKeyLocation) {
				stdin, err = io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
			}

			// CSR
			if isFile(csrLocation) {
				csr, err = pcert.LoadCSR(csrLocation)
				if err != nil {
					return err
				}
			} else {
				csr, err = pcert.ParseCSR(stdin)
				if err != nil {
					return err
				}
			}

			// sign cert
			if isFile(signCertLocation) {
				signCert, err = pcert.Load(signCertLocation)
				if os.IsNotExist(err) && signCertLocation == defaultSignCertLocation {
					return fmt.Errorf("sign cert '%s' does not exist. set --sign-cert accordingly.", signCertLocation)
				} else {
					return err
				}
			} else {
				signCert, err = pcert.Parse(stdin)
				if err != nil {
					return err
				}
			}

			// sign key
			if isFile(signKeyLocation) {
				signKey, err = pcert.LoadKey(signKeyLocation)
				if err != nil {
					return err
				}
			} else {
				signKey, err = pcert.ParseKey(stdin)
				if err != nil {
					return err
				}
			}

			cert := pcert.NewCertificate(&certOpts)

			certDER, err := pcert.CreateCertificateWithCSR(csr, cert, signCert, signKey)
			if err != nil {
				return err
			}

			certPEM := pcert.Encode(certDER)

			if isFile(certLocation) {
				err := os.WriteFile(certLocation, certPEM, 0640)
				if err != nil {
					return err
				}
			} else {
				_, err := cmd.OutOrStdout().Write(certPEM)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&signCertLocation, "sign-cert", "s", signCertLocation, "Certificate used to sign. If not specified a self-signed certificate is created")
	cmd.Flags().StringVar(&signKeyLocation, "sign-key", signKeyLocation, "Key used to sign. If not specified but --sign-cert is specified we use the key file relative to the certificate specified with --sign-cert.")

	cmd.Flags().StringSliceVar(&profiles, "profile", profiles, "profile to set on the certificate (server, client, ca)")
	BindCertificateOptionsFlags(cmd.Flags(), &certOpts)

	return cmd
}
