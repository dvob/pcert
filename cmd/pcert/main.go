package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/dsbrng25b/pcert"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const ENV_PREFIX = "PCERT_"

type app struct {
	signCert  string
	signKey   string
	cert      string
	key       string
	expiry    time.Duration
	config    *x509.Certificate
	keyConfig pcert.KeyConfig
}

func bindCertFileFlag(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.cert, "cert", "", "Output file for the certificate. Defaults to <name>.crt")
}

func bindKeyFileFlag(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.key, "key", "", "Output file for the key. Defaults to <name>.key")
}

func bindSignFileFlags(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.signCert, "sign-cert", "ca.crt", "Certificate used to sign the certificate")
	fs.StringVar(&cfg.signKey, "sign-key", "ca.key", "Key used to sign the certificates")
}

func bindExpiryFlag(fs *pflag.FlagSet, cfg *app) {
	fs.Var(newDurationValue(&cfg.expiry), "expiry", "Validity period of the certificate. If --not-after is set this option has no effect.")
}

func setExpiry(cert *x509.Certificate, expiry time.Duration) {
	// expiry no set
	if expiry == time.Duration(0) {
		return
	}

	if cert.NotBefore.IsZero() {
		cert.NotBefore = time.Now()
	}

	if cert.NotAfter.IsZero() {
		cert.NotAfter = cert.NotBefore.Add(expiry)
		return
	}
}

func defaultSetting(setting *string, value string) {
	if *setting == "" {
		*setting = value
	}
}

func main() {
	newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	var cfg = &app{
		config:    &x509.Certificate{},
		expiry:    pcert.DefaultValidityPeriod,
		keyConfig: pcert.NewDefaultKeyConfig(),
	}
	cmd := &cobra.Command{
		Use:   "pcert",
		Short: "pcert helps you to quickly create and sign certificates",
		Long: `The pcert command helps you to create and sign certificates and CSRs.
All options can also be set as environment variable with the TLSUTIL_
prefix (e.g TLSUTIL_CERT instad of --cert).`,
		TraverseChildren: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			cmd.Flags().VisitAll(func(f *pflag.Flag) {
				varName := ENV_PREFIX + strings.ToUpper(f.Name)
				if val, ok := os.LookupEnv(varName); !f.Changed && ok {
					f.Value.Set(val)
				}
			})
		},
	}
	cmd.AddCommand(
		newCreateCmd(cfg),
		newRequestCmd(cfg),
		newSignCmd(cfg),
		newListCmd(),
		newCompletionCmd(),
	)
	return cmd
}

func newCreateCmd(cfg *app) *cobra.Command {
	var (
		selfSign bool
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "create a signed certificate",
		Long: `Creates a signed certificate and a coresponding key. If --self-sign or
--ca is used it creates a self signed certificate. Otherwise it uses 
--sign-cert and --sign-key to sign the certificate.`,
		Args: cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			name := args[0]
			defaultSetting(&cfg.cert, name+".crt")
			defaultSetting(&cfg.key, name+".key")
			defaultSetting(&cfg.config.Subject.CommonName, args[0])
			setExpiry(cfg.config, cfg.expiry)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cert, key, err := pcert.Create(cfg.config, nil, cfg.keyConfig, nil)
			if err != nil {
				return err
			}

			err = ioutil.WriteFile(cfg.key, key, 0600)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(cfg.cert, cert, 0640)
			return err
		},
	}
	bindSignFileFlags(cmd.Flags(), cfg)
	bindKeyFileFlag(cmd.Flags(), cfg)
	bindCertFileFlag(cmd.Flags(), cfg)
	pcert.BindFlags(cmd.Flags(), cfg.config, "")
	pcert.BindKeyFlags(cmd.Flags(), &cfg.keyConfig, "")
	bindExpiryFlag(cmd.Flags(), cfg)
	cmd.Flags().BoolVar(&selfSign, "self-sign", false, "Create a self-signed certificate")
	cmd.Flags().BoolVar(&selfSign, "ca", false, "Create a CA. Same as self-signed")
	return cmd
}

func newRequestCmd(cfg *app) *cobra.Command {
	var (
		csrFile string
	)
	cmd := &cobra.Command{
		Use:   "request <name>",
		Short: "create a certificate signing request (CSR)",
		Long:  "creates a CSR and a coresponding key.",
		Args:  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			name := args[0]
			defaultSetting(&cfg.key, name+".key")
			defaultSetting(&csrFile, name+".csr")
			defaultSetting(&cfg.config.Subject.CommonName, args[0])
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			csr, key, err := pcert.Request(cfg.config, cfg.keyConfig)
			if err != nil {
				return err
			}

			err = ioutil.WriteFile(cfg.key, key, 0600)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(csrFile, csr, 0640)
			return err
		},
	}
	bindKeyFileFlag(cmd.Flags(), cfg)
	pcert.BindFlags(cmd.Flags(), cfg.config, "")
	cmd.Flags().StringVar(&csrFile, "csr", "", "Output file for the CSR. Defaults to <name>.csr")
	return cmd
}

func newSignCmd(cfg *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <csr-file>",
		Short: "Sign a CSR.",
		Args:  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			csrFile := args[0]
			if strings.HasSuffix(csrFile, ".csr") {
				defaultSetting(&cfg.cert, csrFile[:len(csrFile)-len(".csr")]+".crt")
			} else {
				defaultSetting(&cfg.cert, csrFile+".crt")
			}

		},
		RunE: func(cmd *cobra.Command, args []string) error {
			csrFile := args[0]
			csrPEM, err := ioutil.ReadFile(csrFile)
			if err != nil {
				return err
			}
			signCertPEM, err := ioutil.ReadFile(cfg.signCert)
			if err != nil {
				return err
			}
			signKeyPEM, err := ioutil.ReadFile(cfg.signKey)
			if err != nil {
				return err
			}

			csr, err := pcert.CSRFromPEM(csrPEM)
			if err != nil {
				return err
			}

			signCert, err := pcert.CertificateFromPEM(signCertPEM)
			if err != nil {
				return err
			}

			signKey, err := pcert.KeyFromPEM(signKeyPEM)
			if err != nil {
				return err
			}

			cert, err := pcert.Sign(csr, cfg.config, signCert, signKey)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(cfg.cert, cert, 0640)
			return err
		},
	}
	bindCertFileFlag(cmd.Flags(), cfg)
	bindSignFileFlags(cmd.Flags(), cfg)
	return cmd
}

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "list <type>",
		ValidArgs: []string{"key-usage", "ext-key-usage", "sign-alg", "key-alg"},
		Args:      cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			switch t {
			case "key-usage":
				for u, _ := range pcert.KeyUsage {
					fmt.Println(u)
				}
			case "ext-key-usage":
				for u, _ := range pcert.ExtKeyUsage {
					fmt.Println(u)
				}
			case "sign-alg":
				for _, a := range pcert.GetSignatureAlgorithms() {
					fmt.Println(a)
				}
			case "key-alg":
				fmt.Println("rsa")
				fmt.Println("ecdsa")
				fmt.Println("ed25519")
			default:
				return fmt.Errorf("unknown type: %s", t)
			}
			return nil
		},
	}
	return cmd
}

func newCompletionCmd() *cobra.Command {
	var shell string
	cmd := &cobra.Command{
		Use:       "completion <shell>",
		ValidArgs: []string{"bash", "zsh"},
		Args:      cobra.ExactArgs(1),
		Hidden:    true,
		RunE: func(cmd *cobra.Command, args []string) error {
			shell = args[0]
			var err error
			switch shell {
			case "bash":
				err = newRootCmd().GenBashCompletion(os.Stdout)
			case "zsh":
				err = newRootCmd().GenZshCompletion(os.Stdout)
			default:
				err = fmt.Errorf("unknown shell: %s", shell)
			}
			return err
		},
	}
	return cmd
}
