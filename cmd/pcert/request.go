package main

import (
	"io/ioutil"

	"github.com/dsbrng25b/pcert"
	"github.com/spf13/cobra"
)

func newRequestCmd(cfg *app) *cobra.Command {
	var (
		csrFile string
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
			cfg.applyProfile()

			csr, key, err := pcert.RequestWithKeyOption(cfg.cert, cfg.keyConfig)
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

	cfg.bindKeyFlags(cmd)
	cfg.bindCertFlags(cmd)
	cmd.Flags().StringVar(&csrFile, "csr", "", "Output file for the CSR. Defaults to <name>.csr")
	return cmd
}
