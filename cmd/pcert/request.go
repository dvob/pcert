package main

import (
	"crypto/x509"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

type requestOptions struct {
	// CSR is the location where the CSR will be written.
	CSR string

	// Key is the location where the key will be written.
	Key string

	KeyOptions         pcert.KeyOptions
	CertificateRequest x509.CertificateRequest
}

func newRequestCmd() *cobra.Command {
	opts := &requestOptions{}
	cmd := &cobra.Command{
		Use:   "request [OUTPUT-CSR [OUTPUT-KEY]]",
		Short: "Create a certificate signing request (CSR) and key",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.CSR = args[0]
			}
			if len(args) > 1 {
				opts.Key = args[1]
			}

			if opts.Key == "" && isFile(opts.CSR) {
				opts.Key = getKeyRelativeToFile(opts.CSR)
			}

			csrDER, privateKey, err := pcert.CreateRequestWithKeyOptions(&opts.CertificateRequest, opts.KeyOptions)
			if err != nil {
				return err
			}

			keyPEM, err := pcert.EncodeKey(privateKey)
			if err != nil {
				return err
			}

			csrPEM := pcert.EncodeCSR(csrDER)

			err = writeStdoutOrFile(opts.CSR, csrPEM, 0664, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			err = writeStdoutOrFile(opts.Key, keyPEM, 0600, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			return nil
		},
	}

	registerRequestFlags(cmd, &opts.CertificateRequest)
	registerKeyFlags(cmd, &opts.KeyOptions)

	return cmd
}
