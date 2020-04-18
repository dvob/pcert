package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dsbrng25b/pcert"
	cmdutil "github.com/dsbrng25b/pcert/cmd"
	"github.com/dsbrng25b/pcert/pem"
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

	a.signCert, err = pem.Load(a.signCertFile)
	if err != nil {
		return fmt.Errorf("failed to read signing certificate: %w", err)
	}
	a.signKey, err = pem.LoadKey(a.signKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read signing key: %w", err)
	}
	return nil
}

func (a *app) applyCertOptions() {
	a.applyExpiry()
	a.applyProfile()
}

func (a *app) applyProfile() {
	if a.ca {
		pcert.SetCAProfile(a.cert)
	}

	if a.server {
		pcert.SetServerProfile(a.cert)
	}

	if a.client {
		pcert.SetClientProfile(a.cert)
	}
}

func (a *app) applyExpiry() {
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

func (a *app) defaultOutputSettings(name string) {
	if a.certFile == "" {
		a.certFile = name + CERT_FILE_SUFFIX
	}
	if a.keyFile == "" {
		a.keyFile = name + KEY_FILE_SUFFIX
	}
}

func (a *app) bindCertFlags(cmd *cobra.Command) {
	// cert
	cmd.Flags().BoolVar(&a.ca, "ca", false, "Create a CA certificate")
	cmd.Flags().BoolVar(&a.server, "server", false, "Create a server certificate")
	cmd.Flags().BoolVar(&a.client, "client", false, "Create a client certificate")
	cmd.Flags().Var(newDurationValue(&a.expiry), "expiry", "Validity period of the certificate. If --not-after is set this option has no effect.")
	cmdutil.BindCertificateFlags(cmd.Flags(), a.cert, "")

	// output
	cmd.Flags().StringVar(&a.certFile, "cert", "", "Output file for the certificate. Defaults to <name>.crt")

	// TODO: move these
	cmd.RegisterFlagCompletionFunc("key-usage", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := []string{}
		for u, _ := range pcert.KeyUsages {
			out = append(out, u)
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("ext-key-usage", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := []string{}
		for u, _ := range pcert.ExtKeyUsages {
			out = append(out, u)
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	})
}

func (a *app) bindKeyFlags(cmd *cobra.Command) {
	cmdutil.BindKeyFlags(cmd.Flags(), &a.keyConfig, "")
	cmd.Flags().StringVar(&a.keyFile, "key", "", "Output file for the key. Defaults to <name>.key")
}

func (a *app) bindSignFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&a.signCertFile, "sign-cert", "", "Certificate used to sign the certificate")
	cmd.Flags().StringVar(&a.signKeyFile, "sign-key", "", "Key used to sign the certificates")
	cmd.Flags().StringVar(&a.signFrom, "from", "", "Specifiy a name of a key pair (<name>.crt, <name>.key) from which you want to sign your certificate. This can be used insted of --sign-cert and --sign-key")
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
All options can also be set as environment variable with the PCERT_
prefix (e.g PCERT_CERT instad of --cert).`,
		TraverseChildren: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cmd.Flags().VisitAll(func(f *pflag.Flag) {
				optName := strings.ToUpper(f.Name)
				optName = strings.ReplaceAll(optName, "-", "_")
				varName := ENV_PREFIX + optName
				if val, ok := os.LookupEnv(varName); !f.Changed && ok {
					err2 := f.Value.Set(val)
					if err2 != nil {
						err = fmt.Errorf("invalid environment variable %s: %w", varName, err2)
					}
				}
			})
			return err
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
