package main

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

func newCreateCmd() *cobra.Command {
	var (
		cert = &cert{
			cert: &x509.Certificate{},
		}
		signPair = &signPair{}
		key      = &key{}
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a signed certificate and a key",
		Long: `Creates a key and certificate. If --with or --sign-cert and --sign-key
are specified the certificate is signed by these. Otherwise it will be self-signed.
The argument <name> is used as common name in the certificate if not overwritten
with the --subject option and as file name for the certificate (<name>.crt) and
the key (<name>.key).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			if cert.cert.Subject.CommonName == "" {
				cert.cert.Subject.CommonName = name
			}

			if cert.path == "" {
				cert.path = name + certFileSuffix
			}

			if key.path == "" {
				key.path = name + keyFileSuffix
			}

			cert.configure()

			err := signPair.load()
			if err != nil {
				return err
			}

			certDER, privateKey, err := pcert.CreateWithKeyOptions(cert.cert, key.opts, signPair.cert, signPair.key)
			if err != nil {
				return err
			}

			keyPEM, err := pcert.EncodeKey(privateKey)
			if err != nil {
				return err
			}

			certPEM := pcert.Encode(certDER)

			err = os.WriteFile(key.path, keyPEM, 0600)
			if err != nil {
				return fmt.Errorf("failed to write key '%s': %w", key.path, err)
			}
			err = os.WriteFile(cert.path, certPEM, 0640)
			if err != nil {
				return fmt.Errorf("failed to write certificate '%s': %w", key.path, err)
			}
			return nil
		},
	}
	cert.bindFlags(cmd)
	key.bindFlags(cmd)
	signPair.bindFlags(cmd)
	return cmd
}
