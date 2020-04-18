package main

import (
	"io/ioutil"

	"github.com/dsbrng25b/pcert"
	"github.com/spf13/cobra"
)

func newCreateCmd(cfg *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a signed certificate and a key",
		Long: `Creates a key and certificate. If --from or --sign-cert and --sign-key
are specified the certificate is signed by these. Otherwise it will be self-signed.
The argument <name> is used as common name in the certificate if not overwritten
with the --subject option and as file name for the certificate (<name>.crt) and
the key (<name>.key).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			defaultSetting(&cfg.cert.Subject.CommonName, name)
			cfg.defaultOutputSettings(name)
			cfg.applyCertOptions()

			err := cfg.setupSignSettings()
			if err != nil {
				return err
			}

			cert, key, err := pcert.CreateWithKeyConfig(cfg.cert, cfg.keyConfig, cfg.signCert, cfg.signKey)
			if err != nil {
				return err
			}

			err = ioutil.WriteFile(cfg.keyFile, key, 0600)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(cfg.certFile, cert, 0640)
			return err
		},
	}
	cfg.bindCertFlags(cmd)
	cfg.bindSignFlags(cmd)
	cfg.bindKeyFlags(cmd)
	return cmd
}
