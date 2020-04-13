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

const (
	ENV_PREFIX       = "PCERT_"
	CERT_FILE_SUFFIX = ".crt"
	KEY_FILE_SUFFIX  = ".key"
	CSR_FILE_SUFFIX  = ".csr"
)

type app struct {
	// signer settings
	signCertFile string
	signCert     *x509.Certificate
	signKeyFile  string
	signKey      interface{}

	// signFrom is a shortcut for signCertFile and signKeyFile.
	// If it is set signCertFile and signKeyFile are set to <signFrom>.crt and <signFrom>.key
	signFrom string

	certFile  string
	keyFile   string
	expiry    time.Duration
	cert      *x509.Certificate
	keyConfig pcert.KeyConfig

	// profiles
	ca     bool
	client bool
	server bool
}

func (a *app) setupSignSettings() (err error) {
	if a.signFrom != "" {
		a.signCertFile = a.signFrom + CERT_FILE_SUFFIX
		a.signKeyFile = a.signFrom + KEY_FILE_SUFFIX
	}

	if a.signCertFile == "" && a.signKeyFile == "" {
		return nil
	}

	a.signCert, err = pcert.FromFile(a.signCertFile)
	if err != nil {
		return fmt.Errorf("failed to read signing certificate: %w", err)
	}
	a.signKey, err = pcert.KeyFromFile(a.signKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read signing key: %w", err)
	}
	return nil
}

func (a *app) applyProfile() {
	if a.ca {
		pcert.SetCAProfile(a.cert)
	}

	if a.client {
		pcert.SetClientProfile(a.cert)
	}

	if a.server {
		pcert.SetServerProfile(a.cert)
	}
}

func (a *app) setupOutputSettings(name string) {
	if a.certFile == "" {
		a.certFile = name + CERT_FILE_SUFFIX
	}
	if a.keyFile == "" {
		a.keyFile = name + KEY_FILE_SUFFIX
	}
}

func (a *app) setExpiry() {
	// expiry no set
	if a.expiry == time.Duration(0) {
		return
	}

	if a.cert.NotBefore.IsZero() {
		a.cert.NotBefore = time.Now()
	}

	if a.cert.NotAfter.IsZero() {
		a.cert.NotAfter = a.cert.NotBefore.Add(a.expiry)
		return
	}
}

func bindCertFileFlag(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.certFile, "cert", "", "Output file for the certificate. Defaults to <name>.crt")
}

func bindKeyFileFlag(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.keyFile, "key", "", "Output file for the key. Defaults to <name>.key")
}

func bindSignFileFlags(fs *pflag.FlagSet, cfg *app) {
	fs.StringVar(&cfg.signCertFile, "sign-cert", "", "Certificate used to sign the certificate")
	fs.StringVar(&cfg.signKeyFile, "sign-key", "", "Key used to sign the certificates")
	fs.StringVar(&cfg.signFrom, "from", "", "Specifiy a name of a key pair (<name>.crt, <name>.key) from which you want to sign your certificate. This can be used insted of --sign-cert and --sign-key")
}

func bindProfileFlags(fs *pflag.FlagSet, cfg *app) {
	fs.BoolVar(&cfg.ca, "ca", false, "Create a CA certificate")
	fs.BoolVar(&cfg.server, "server", false, "Create a server certificate")
	fs.BoolVar(&cfg.client, "client", false, "Create a client certificate")
}

func bindExpiryFlag(fs *pflag.FlagSet, cfg *app) {
	fs.Var(newDurationValue(&cfg.expiry), "expiry", "Validity period of the certificate. If --not-after is set this option has no effect.")
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
		cert:      &x509.Certificate{},
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
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "create a signed certificate",
		Long: `Creates a key and certificate. If --from or --sign-cert and --sign-key
are specified the certificate is signed by these. Otherwise it will be self-signed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			defaultSetting(&cfg.cert.Subject.CommonName, name)
			cfg.setupOutputSettings(name)
			cfg.setExpiry()
			cfg.applyProfile()

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
	bindSignFileFlags(cmd.Flags(), cfg)
	bindKeyFileFlag(cmd.Flags(), cfg)
	bindCertFileFlag(cmd.Flags(), cfg)
	bindProfileFlags(cmd.Flags(), cfg)
	bindExpiryFlag(cmd.Flags(), cfg)

	pcert.BindFlags(cmd.Flags(), cfg.cert, "")
	pcert.BindKeyFlags(cmd.Flags(), &cfg.keyConfig, "")

	cmd.RegisterFlagCompletionFunc("key-usage", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := []string{}
		for u, _ := range pcert.KeyUsage {
			out = append(out, u)
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("ext-key-usage", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := []string{}
		for u, _ := range pcert.ExtKeyUsage {
			out = append(out, u)
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	})
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
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			defaultSetting(&cfg.cert.Subject.CommonName, name)
			defaultSetting(&csrFile, name+CSR_FILE_SUFFIX)
			cfg.setupOutputSettings(name)
			cfg.applyProfile()

			csr, key, err := pcert.RequestWithKeyOption(cfg.cert, cfg.keyConfig)
			if err != nil {
				return err
			}

			err = ioutil.WriteFile(cfg.keyFile, key, 0600)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(csrFile, csr, 0640)
			return err
		},
	}
	bindKeyFileFlag(cmd.Flags(), cfg)
	pcert.BindFlags(cmd.Flags(), cfg.cert, "")
	cmd.Flags().StringVar(&csrFile, "csr", "", "Output file for the CSR. Defaults to <name>.csr")
	return cmd
}

func newSignCmd(cfg *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <csr-file>",
		Short: "Sign a CSR.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			csrFile := args[0]
			if strings.HasSuffix(csrFile, ".csr") {
				defaultSetting(&cfg.certFile, csrFile[:len(csrFile)-len(".csr")]+".crt")
			} else {
				defaultSetting(&cfg.certFile, csrFile+".crt")
			}

			cfg.applyProfile()
			cfg.setExpiry()

			err := cfg.setupSignSettings()
			if err != nil {
				return err
			}

			csr, err := pcert.CSRFromFile(csrFile)
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
