package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"github.com/dsbrng25b/pcert"
	cmdutil "github.com/dsbrng25b/pcert/cmd"
	"github.com/spf13/cobra"
)

func newRequestCmd() *cobra.Command {
	var (
		csrFile string
		csr     = &x509.CertificateRequest{}
		key     = &key{}
	)
	cmd := &cobra.Command{
		Use:   "request <name>",
		Short: "Create a certificate signing request (CSR)",
		Long:  "Creates a CSR and a coresponding key.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if csr.Subject.CommonName == "" {
				csr.Subject.CommonName = name
			}

			if csrFile == "" {
				csrFile = name + csrFileSuffix
			}

			if key.path == "" {
				key.path = name + keyFileSuffix
			}

			csrPEM, keyPEM, err := pcert.RequestWithKeyOption(csr, key.config)
			if err != nil {
				return err
			}

			err = ioutil.WriteFile(key.path, keyPEM, 0600)
			if err != nil {
				return fmt.Errorf("failed to write key '%s': %w", key.path, err)
			}
			err = ioutil.WriteFile(csrFile, csrPEM, 0640)
			if err != nil {
				return fmt.Errorf("failed to write CSR '%s': %w", csrFile, err)
			}
			return nil
		},
	}

	key.bindFlags(cmd)

	cmdutil.BindCertificateRequestFlags(cmd.Flags(), csr)
	cmdutil.RegisterCertificateRequestCompletionFuncs(cmd)
	cmd.Flags().StringVar(&csrFile, "csr", "", "Output file for the CSR. Defaults to <name>.csr")

	return cmd
}
