package main

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

func newRequestCmd() *cobra.Command {
	var (
		csrOutput string
		csr       = &x509.CertificateRequest{}

		keyOutput string
		keyOpts   = pcert.KeyOptions{}
	)
	cmd := &cobra.Command{
		Use:   "request [OUTPUT-CSR [OUTPUT-KEY]]",
		Short: "Create a certificate signing request (CSR) and key",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && args[0] != "-" {
				csrOutput = args[0]
				keyOutput = getKeyRelativeToCert(args[0])
			}

			if len(args) == 2 {
				csrOutput = args[0]
				keyOutput = args[1]
			}

			csrDER, privateKey, err := pcert.CreateRequestWithKeyOptions(csr, keyOpts)
			if err != nil {
				return err
			}

			keyPEM, err := pcert.EncodeKey(privateKey)
			if err != nil {
				return err
			}

			csrPEM := pcert.EncodeCSR(csrDER)

			if csrOutput == "" || csrOutput == "-" {
				_, err := cmd.OutOrStdout().Write(csrPEM)
				if err != nil {
					return err
				}
			} else {
				err := os.WriteFile(csrOutput, csrPEM, 0664)
				if err != nil {
					return fmt.Errorf("failed to write CSR '%s': %w", csrOutput, err)
				}
			}

			if keyOutput == "" || keyOutput == "-" {
				_, err := cmd.OutOrStdout().Write(keyPEM)
				if err != nil {
					return err
				}
			} else {
				err = os.WriteFile(keyOutput, keyPEM, 0600)
				if err != nil {
					return fmt.Errorf("failed to write key '%s': %w", keyOutput, err)
				}
			}
			return nil
		},
	}

	BindKeyFlags(cmd.Flags(), &keyOpts)
	RegisterKeyCompletionFuncs(cmd)

	BindCertificateRequestFlags(cmd.Flags(), csr)
	RegisterCertificateRequestCompletionFuncs(cmd)

	return cmd
}
