package main

import (
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"strings"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

type createOptions struct {
	// Cert is the location where the certificate will be written to. A
	// filepath or - for stdin. If empty it defaults to stdin.
	Cert string
	// Key is the location where the key will be written to. If empty and
	// Cert is a filepath the key will be written alongside the certificate
	// file. For example if the certificate is named tls.crt the key is
	// stored under tls.key.
	Key string

	// SignCert is the location of the certificate to sign the new
	// certificate. Its either a filepath or - to read it from stdin. If
	// SignCert and SignKey are not set a self-signed certificate is
	// created.
	SignCert string
	// SignKey is the location of the key used to sign the certificate. Its
	// either a filepath or - to read the key from stdin.
	// If SignCert is a filepath and SignKey is not set, by defaults the
	// key is searchd alongside the certificate.
	SignKey string

	// Profiles are special certificate settings to set. E.g. client,
	// server or CA.
	Profiles []string

	// CertificateOptions certificate settings.
	CertificateOptions pcert.CertificateOptions

	// KeyOptions are the key settings.
	KeyOptions pcert.KeyOptions
}

func getKeyRelativeToFile(certPath string) string {
	outputDir := filepath.Dir(certPath)
	certFileName := filepath.Base(certPath)
	certExtension := filepath.Ext(certFileName)
	keyFileName := strings.TrimSuffix(certFileName, certExtension) + ".key"

	keyFilePath := filepath.Join(outputDir, keyFileName)
	return keyFilePath
}

func newCreateCmd() *cobra.Command {
	opts := &createOptions{
		Cert:               "",
		Key:                "",
		SignCert:           "",
		SignKey:            "",
		CertificateOptions: pcert.CertificateOptions{},
		KeyOptions:         pcert.KeyOptions{},
	}
	cmd := &cobra.Command{
		Use:   "create [OUTPUT-CERTIFICATE [OUTPUT-KEY]]",
		Short: "Create a key and certificate",
		Long: `Creates a key and certificate. If OUTPUT-CERTIFICATE and OUTPUT-KEY are specified
the certificate and key are stored in the respective files. If only
OUTPUT-CERTIFICATE is specifed the key is stored next to the certificate. For
example the following invocation would store the certificate in tls.crt and the
key in tls.key:

pcert create tls.crt
`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			stdin := &stdinKeeper{
				stdin: cmd.InOrStdin(),
			}

			// default key output file relative to certificate
			if len(args) == 1 && args[0] != "-" {
				opts.Cert = args[0]
				opts.Key = getKeyRelativeToFile(args[0])
			}
			if len(args) == 2 {
				opts.Cert = args[0]
				opts.Key = args[1]
			}

			// SignCert is set but SignKey is empty we default
			// SignKey
			if opts.SignCert != "" && opts.SignKey == "" {
				if isFile(opts.SignCert) {
					opts.SignKey = getKeyRelativeToFile(opts.SignCert)
				}
			}

			certTemplate := pcert.NewCertificate(&opts.CertificateOptions)

			err := setProfiles(opts.Profiles, certTemplate)
			if err != nil {
				return err
			}

			privateKey, publicKey, err := pcert.GenerateKey(opts.KeyOptions)
			if err != nil {
				return err
			}

			var (
				signCert *x509.Certificate
				signKey  any
			)

			// if set we sign certificate
			if opts.SignCert != "" {
				data, err := readStdinOrFile(opts.SignCert, stdin)
				if err != nil {
					return err
				}
				signCert, err = pcert.Parse(data)
				if err != nil {
					return err
				}

				data, err = readStdinOrFile(opts.SignKey, stdin)
				if err != nil {
					return err
				}
				signKey, err = pcert.ParseKey(data)
				if err != nil {
					return err
				}

			} else {
				signCert = certTemplate
				signKey = privateKey
			}

			certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, signCert, publicKey, signKey)
			if err != nil {
				return err
			}

			certPEM := pcert.Encode(certDER)
			keyPEM, err := pcert.EncodeKey(privateKey)
			if err != nil {
				return err
			}

			err = writeStdoutOrFile(opts.Cert, certPEM, 0o644, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			err = writeStdoutOrFile(opts.Key, keyPEM, 0o644, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.SignCert, "sign-cert", "s", opts.SignCert, "Certificate used to sign. If not specified a self-signed certificate is created")
	cmd.Flags().StringVar(&opts.SignKey, "sign-key", opts.SignKey, "Key used to sign. If not specified but --sign-cert is specified we use the key file relative to the certificate specified with --sign-cert.")
	cmd.Flags().StringSliceVar(&opts.Profiles, "profile", opts.Profiles, "Certificates profiles to apply (server, client, ca)")

	registerCertFlags(cmd, &opts.CertificateOptions)
	registerKeyFlags(cmd, &opts.KeyOptions)
	return cmd
}
