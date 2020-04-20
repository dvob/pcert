package main

import (
	"crypto/x509"
	"io/ioutil"

	"github.com/dsbrng25b/pcert"
	cmdutil "github.com/dsbrng25b/pcert/cmd"
	"github.com/spf13/cobra"
)

func newRequestCmd(cfg *app) *cobra.Command {
	var (
		csrFile string
		csr     = &x509.CertificateRequest{}
	)
	cmd := &cobra.Command{
		Use:   "request <name>",
		Short: "Create a certificate signing request (CSR)",
		Long:  "Creates a CSR and a coresponding key.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			defaultSetting(&cfg.cert.Subject.CommonName, name)
			defaultSetting(&csrFile, name+csrFileSuffix)
			cfg.defaultOutputSettings(name)

			csr, key, err := pcert.RequestWithKeyOption(csr, cfg.keyConfig)
			if err != nil {
				return err
			}

			err = ioutil.WriteFile(cfg.keyFile, key, 0600)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(csrFile, csr, 0640)
			return err
		},
	}

	cmdutil.BindCertificateRequestFlags(cmd.Flags(), csr)
	cmdutil.RegisterCertificateRequestCompletionFuncs(cmd)
	cfg.bindKeyFlags(cmd)
	cmd.Flags().StringVar(&csrFile, "csr", "", "Output file for the CSR. Defaults to <name>.csr")
	return cmd
}
