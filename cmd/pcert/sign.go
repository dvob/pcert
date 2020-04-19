package main

import (
	"io/ioutil"
	"strings"

	"github.com/dsbrng25b/pcert"
	"github.com/dsbrng25b/pcert/pem"
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
				defaultSetting(&cfg.certFile, csrFile[:len(csrFile)-len(CSR_FILE_SUFFIX)]+CERT_FILE_SUFFIX)
			} else {
				defaultSetting(&cfg.certFile, csrFile+CERT_FILE_SUFFIX)
			}

			cfg.applyCertOptions()

			err := cfg.setupSignSettings()
			if err != nil {
				return err
			}

			csr, err := pem.LoadCSR(csrFile)
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