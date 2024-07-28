package main

import (
	"fmt"
	"os"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

type signOptions struct {
	CSR string

	Cert               string
	CertificateOptions pcert.CertificateOptions
	Profiles           []string

	SignCert string
	SignKey  string
}

func newSignCmd() *cobra.Command {
	var (
		defaultSignCertLocation = "ca.crt"
		opts                    = &signOptions{
			SignCert: defaultSignCertLocation,
		}
	)

	cmd := &cobra.Command{
		Use:   "sign [INPUT-CSR] [OUTPUT-CERTIFICATE]",
		Short: "Create a certificate based on a CSR",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.CSR = args[0]
			}
			if len(args) > 1 {
				opts.Cert = args[1]
			}

			if opts.SignKey == "" && isFile(opts.SignCert) {
				opts.SignKey = getKeyRelativeToFile(opts.SignCert)
			}

			stdin := &stdinKeeper{
				stdin: cmd.InOrStdin(),
			}

			// CSR
			data, err := readStdinOrFile(opts.CSR, stdin)
			if err != nil {
				return err
			}

			csr, err := pcert.ParseCSR(data)
			if err != nil {
				return err
			}

			// SignCert
			data, err = readStdinOrFile(opts.SignCert, stdin)
			if os.IsNotExist(err) && opts.SignCert == defaultSignCertLocation {
				return fmt.Errorf("sign cert '%s' does not exist. set --sign-cert accordingly", opts.SignCert)
			} else if err != nil {
				return err
			}

			signCert, err := pcert.Parse(data)
			if err != nil {
				return err
			}

			// SignKey
			data, err = readStdinOrFile(opts.SignKey, stdin)
			if err != nil {
				return err
			}

			signKey, err := pcert.ParseKey(data)
			if err != nil {
				return err
			}

			// create new certificate
			cert := pcert.NewCertificate(&opts.CertificateOptions)
			err = setProfiles(opts.Profiles, cert)
			if err != nil {
				return err
			}

			certDER, err := pcert.CreateCertificateWithCSR(csr, cert, signCert, signKey)
			if err != nil {
				return err
			}

			certPEM := pcert.Encode(certDER)

			err = writeStdoutOrFile(opts.Cert, certPEM, 0o644, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.SignCert, "sign-cert", "s", opts.SignCert, "Certificate used to sign. If not specified a self-signed certificate is created")
	cmd.Flags().StringVar(&opts.SignKey, "sign-key", opts.SignKey, "Key used to sign. If not specified but --sign-cert is specified we use the key file relative to the certificate specified with --sign-cert.")

	cmd.Flags().StringSliceVar(&opts.Profiles, "profile", opts.Profiles, "profile to set on the certificate (server, client, ca)")

	registerCertFlags(cmd, &opts.CertificateOptions)

	return cmd
}
