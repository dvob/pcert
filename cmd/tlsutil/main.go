package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dsbrng25b/tlsutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const ENV_PREFIX = "TLSUTIL_"

type app struct {
	caCert string
	caKey  string
	cert   string
	key    string
	stdout bool
	config *tlsutil.Config
}

func bindCertFileFlag(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.cert, "cert", "", "Output file for the certificate. Defaults to <name>.crt")
}

func bindKeyFileFlag(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.key, "key", "", "Output file for the key. Defaults to <name>.key")
}

func bindCAFileFlags(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.caCert, "ca-cert", "ca.crt", "Certificate used to sign the certificate")
	fs.StringVar(&cfg.caKey, "ca-key", "ca.key", "Key used to sign the certificates")
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
		config: &tlsutil.Config{},
	}
	cmd := &cobra.Command{
		Use:   "tlsutil",
		Short: "tlsutil helps you to quickly create and sign certificates",
		Long: `The tlsutil command helps you to create and sign certificates and CSRs.
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
--ca-cert and --ca-key to sign the certificate.`,
		Args: cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			name := args[0]
			defaultSetting(&cfg.cert, name+".crt")
			defaultSetting(&cfg.key, name+".key")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cert, key, err := tlsutil.Create(name, cfg.config)
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
	bindCAFileFlags(cmd.Flags(), cfg)
	bindKeyFileFlag(cmd.Flags(), cfg)
	bindCertFileFlag(cmd.Flags(), cfg)
	tlsutil.BindFlags(cmd.Flags(), cfg.config, "")
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
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			csr, key, err := tlsutil.Request(name, cfg.config)
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
	tlsutil.BindFlags(cmd.Flags(), cfg.config, "")
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
			caCertPEM, err := ioutil.ReadFile(cfg.caCert)
			if err != nil {
				return err
			}
			caKeyPEM, err := ioutil.ReadFile(cfg.caKey)
			if err != nil {
				return err
			}

			csr, err := tlsutil.CSRFromPEM(csrPEM)
			if err != nil {
				return err
			}

			caCert, err := tlsutil.CertificateFromPEM(caCertPEM)
			if err != nil {
				return err
			}

			caKey, err := tlsutil.KeyFromPEM(caKeyPEM)
			if err != nil {
				return err
			}

			cert, err := tlsutil.Sign(csr, cfg.config, caCert, caKey)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(cfg.cert, cert, 0640)
			return err
		},
	}
	bindCertFileFlag(cmd.Flags(), cfg)
	bindCAFileFlags(cmd.Flags(), cfg)
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
