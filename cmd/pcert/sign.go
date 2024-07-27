package main

import (
	"crypto/x509"
	"os"
	"strings"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var (
		cert = &cert{
			cert: &x509.Certificate{},
		}
		signPair = &signPair{}
	)
	cmd := &cobra.Command{
		Use:   "sign <csr-file>",
		Short: "Sign a CSR.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			csrFile := args[0]
			name := csrFile

			if strings.HasSuffix(csrFile, csrFileSuffix) {
				// myfile.csr -> myfile
				name = csrFile[:len(csrFile)-len(csrFileSuffix)]
			}

			if cert.path == "" {
				cert.path = name + certFileSuffix
			}

			cert.configure()

			err := signPair.load()
			if err != nil {
				return err
			}

			csr, err := pcert.LoadCSR(csrFile)
			if err != nil {
				return err
			}

			certDER, err := pcert.CreateCertificateWithCSR(csr, cert.cert, signPair.cert, signPair.key)
			if err != nil {
				return err
			}

			certPEM := pcert.Encode(certDER)

			err = os.WriteFile(cert.path, certPEM, 0o640)
			return err
		},
	}

	cert.bindFlags(cmd)
	signPair.bindFlags(cmd)
	return cmd
}
