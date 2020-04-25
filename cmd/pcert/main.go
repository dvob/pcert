package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dsbrng25b/pcert"
	cmdutil "github.com/dsbrng25b/pcert/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	envVarPrefix   = "PCERT_"
	certFileSuffix = ".crt"
	keyFileSuffix  = ".key"
	csrFileSuffix  = ".csr"
)

var (
	version = "n/a"
	commit  = "n/a"
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
		a.signCertFile = a.signFrom + certFileSuffix
		a.signKeyFile = a.signFrom + keyFileSuffix
	}

	if a.signCertFile == "" && a.signKeyFile == "" {
		return nil
	}

	a.signCert, err = pcert.Load(a.signCertFile)
	if err != nil {
		return fmt.Errorf("failed to read signing certificate: %w", err)
	}
	a.signKey, err = pcert.LoadKey(a.signKeyFile)
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
		a.certFile = name + certFileSuffix
	}
	if a.keyFile == "" {
		a.keyFile = name + keyFileSuffix
	}
}

func (a *app) bindCertFlags(cmd *cobra.Command) {
	// cert
	cmd.Flags().BoolVar(&a.ca, "ca", false, "Create a CA certificate")
	cmd.Flags().BoolVar(&a.server, "server", false, "Create a server certificate")
	cmd.Flags().BoolVar(&a.client, "client", false, "Create a client certificate")
	cmd.Flags().Var(newDurationValue(&a.expiry), "expiry", "Validity period of the certificate. If --not-after is set this option has no effect.")
	cmdutil.BindCertificateFlags(cmd.Flags(), a.cert)
	cmdutil.RegisterCertificateCompletionFuncs(cmd)

	// output
	cmd.Flags().StringVar(&a.certFile, "cert", "", "Output file for the certificate. Defaults to <name>.crt")
}

func (a *app) bindKeyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&a.keyFile, "key", "", "Output file for the key. Defaults to <name>.key")
	cmdutil.BindKeyFlags(cmd.Flags(), &a.keyConfig)
	cmdutil.RegisterKeyCompletionFuncs(cmd)
}

func (a *app) bindSignFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&a.signCertFile, "sign-cert", "", "Certificate used to sign the certificate")
	cmd.Flags().StringVar(&a.signKeyFile, "sign-key", "", "Key used to sign the certificates")
	cmd.Flags().StringVar(&a.signFrom, "from", "", "Specify a name of a key pair (<name>.crt, <name>.key) from which you want to sign your certificate. This can be used insted of --sign-cert and --sign-key")
}

func defaultSetting(setting *string, value string) {
	if *setting == "" {
		*setting = value
	}
}

func main() {
	err := newRootCmd().Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfg = &app{
		cert:   &x509.Certificate{},
		expiry: pcert.DefaultValidityPeriod,
		keyConfig: pcert.KeyConfig{
			Algorithm: x509.ECDSA,
		},
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
				varName := envVarPrefix + optName
				merger, merge := f.Value.(cmdutil.Merger)
				if val, ok := os.LookupEnv(varName); ok {
					var err2 error
					if !f.Changed {
						err2 = f.Value.Set(val)
					} else if merge {
						err2 = merger.Merge(val)
					}
					if err2 != nil {
						err = fmt.Errorf("invalid environment variable %s: %w", varName, err2)
					}
				}
			})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return err
		},
	}
	cmd.AddCommand(
		newCreateCmd(cfg),
		newRequestCmd(cfg),
		newSignCmd(cfg),
		newListCmd(),
		newCompletionCmd(),
		newVersionCmd(),
	)
	return cmd
}

func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("pcert", version, commit)
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
