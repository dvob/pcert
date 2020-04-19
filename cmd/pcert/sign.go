package main

import (
	"io/ioutil"
	"strings"

	"github.com/dsbrng25b/pcert"
	"github.com/spf13/cobra"
)

func newSignCmd(cfg *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <csr-file>",
		Short: "Sign a CSR.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			csrFile := args[0]
			if strings.HasSuffix(csrFile, ".csr") {
				// myfile.csr -> myfile.crt
				defaultSetting(&cfg.certFile, csrFile[:len(csrFile)-len(CSRFileSuffix)]+CertFileSuffix)
			} else {
				defaultSetting(&cfg.certFile, csrFile+CertFileSuffix)
			}

			cfg.applyCertOptions()

			err := cfg.setupSignSettings()
			if err != nil {
				return err
			}

			csr, err := pcert.LoadCSR(csrFile)
			if err != nil {
				return err
			}

			cert, err := pcert.SignCSR(csr, cfg.cert, cfg.signCert, cfg.signKey)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(cfg.certFile, cert, 0640)
			return err
		},
	}

	cfg.bindCertFlags(cmd)
	cfg.bindSignFlags(cmd)
	return cmd
}
