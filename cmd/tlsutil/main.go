package main

import (
	"fmt"
	"io/ioutil"
	"log"
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
			// TODO
			if cfg.cert == "" {
				cfg.cert = args[0] + ".crt"
			}
			if cfg.key == "" {
				cfg.key = args[0] + ".key"
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cert, key, err := tlsutil.Create(args[0], cfg.config)
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
		csrName string
	)
	cmd := &cobra.Command{
		Use:   "request <name>",
		Short: "create a certificate signing request (CSR)",
		Long:  "creates a CSR and a coresponding key.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("request")
			return nil
		},
	}
	bindKeyFileFlag(cmd.Flags(), cfg)
	tlsutil.BindFlags(cmd.Flags(), cfg.config, "")
	cmd.Flags().StringVar(&csrName, "csr", "", "Output file for the CSR. Defaults to <name>.csr")
	return cmd
}

func newSignCmd(cfg *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <csr-file>",
		Short: "Sign a CSR.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("sign")
			return nil
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
		Run: func(cmd *cobra.Command, args []string) {
			shell = args[0]
			var err error
			switch shell {
			case "bash":
				err = newRootCmd().GenBashCompletion(os.Stdout)
			case "zsh":
				err = newRootCmd().GenZshCompletion(os.Stdout)
			default:
				log.Fatal("unknown shell: ", shell)
				os.Exit(1)
			}
			if err != nil {
				log.Fatal(err)
				os.Exit(1)
			}
		},
	}
	return cmd
}
