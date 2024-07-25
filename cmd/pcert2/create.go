package main

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
	"log/slog"
)

type createCommand struct {
	Out io.Writer
	In  io.Writer

	CertificateOutputLocation string
	KeyOutputLocation         string

	SignCertificateLocation string
	SignKeyLocation         string

	Profile            []string
	CertificateOptions CertificateOptions
	KeyOptions         pcert.KeyOptions
}

func getKeyRelativeToCert(certPath string) string {
	outputDir := filepath.Dir(certPath)
	certFileName := filepath.Base(certPath)
	certExtension := filepath.Ext(certFileName)
	keyFileName := strings.TrimSuffix(certFileName, certExtension) + ".key"

	keyFilePath := filepath.Join(outputDir, keyFileName)
	return keyFilePath
}

func newCreateCmd() *cobra.Command {
	createCommand := &createCommand{
		Out:                       os.Stdout,
		In:                        os.Stdin,
		CertificateOutputLocation: "",
		KeyOutputLocation:         "",
		SignCertificateLocation:   "",
		SignKeyLocation:           "",
		CertificateOptions:        CertificateOptions{},
		KeyOptions:                pcert.KeyOptions{},
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
			// default key output file relative to certificate
			if len(args) == 1 && args[0] != "-" {
				createCommand.CertificateOutputLocation = args[0]
				createCommand.KeyOutputLocation = getKeyRelativeToCert(args[0])
			}
			if len(args) == 2 {
				createCommand.CertificateOutputLocation = args[0]
				createCommand.KeyOutputLocation = args[1]
			}

			certTemplate := NewCertificate(&createCommand.CertificateOptions)

			for _, p := range createCommand.Profile {
				switch p {
				case "client":
					pcert.SetClientProfile(certTemplate)
				case "server":
					pcert.SetServerProfile(certTemplate)
				case "ca":
					pcert.SetCAProfile(certTemplate)
				default:
					return fmt.Errorf("unknown profile '%s'", p)
				}
			}

			privateKey, publicKey, err := pcert.GenerateKey(createCommand.KeyOptions)
			if err != nil {
				return err
			}

			var (
				stdin    []byte
				signCert *x509.Certificate
				signKey  any
			)

			// if set we sign certificate
			if createCommand.SignCertificateLocation != "" {
				slog.Info("process signer")
				if createCommand.SignCertificateLocation == "-" {
					stdin, err = io.ReadAll(os.Stdin)
					if err != nil {
						return err
					}

					slog.Info("read certificate from stdin")
					signCert, err = pcert.Parse(stdin)
					if err != nil {
						return err
					}
				} else {
					slog.Info("read certificate from file", "file", createCommand.SignCertificateLocation)
					signCert, err = pcert.Load(createCommand.SignCertificateLocation)
					if err != nil {
						return err
					}
				}

				if createCommand.SignKeyLocation == "" && createCommand.SignCertificateLocation != "-" {
					slog.Info("read key from relatvie location", "file", getKeyRelativeToCert(createCommand.SignCertificateLocation))
					signKey, err = pcert.LoadKey(getKeyRelativeToCert(createCommand.SignCertificateLocation))
					if err != nil {
						return err
					}
				} else if createCommand.SignKeyLocation == "" && createCommand.SignCertificateLocation == "-" {
					slog.Info("read key from stdin")
					signKey, err = pcert.ParseKey(stdin)
					if err != nil {
						return err
					}
				} else {
					slog.Info("read key from file", "file", createCommand.SignKeyLocation)
					signKey, err = pcert.LoadKey(createCommand.SignKeyLocation)
					if err != nil {
						return err
					}
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

			if createCommand.CertificateOutputLocation == "" || createCommand.CertificateOutputLocation == "-" {
				createCommand.Out.Write(certPEM)
			} else {
				err := os.WriteFile(createCommand.CertificateOutputLocation, certPEM, 0664)
				if err != nil {
					return err
				}
			}

			if createCommand.KeyOutputLocation == "" || createCommand.KeyOutputLocation == "-" {
				createCommand.Out.Write(keyPEM)
			} else {
				err := os.WriteFile(createCommand.KeyOutputLocation, keyPEM, 0600)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&createCommand.SignCertificateLocation, "sign-cert", "s", createCommand.SignCertificateLocation, "Certificate used to sign. If not specified a self-signed certificate is created")
	cmd.Flags().StringVar(&createCommand.SignKeyLocation, "sign-key", createCommand.SignKeyLocation, "Key used to sign. If not specified but --sign-cert is specified we use the key file relative to the certificate specified with --sign-cert.")
	cmd.Flags().StringSliceVar(&createCommand.Profile, "profile", createCommand.Profile, "Certificates profiles to apply (server, client, ca)")
	createCommand.CertificateOptions.BindFlags(cmd.Flags())
	return cmd
}
