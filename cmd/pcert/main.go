package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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

func main() {
	err := WithEnv(newRootCmd(), os.Args[1:], os.LookupEnv).Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pcert",
		Short: "pcert helps you to quickly create and sign certificates",
		Long: `The pcert command helps you to create and sign certificates and CSRs.
All options can also be set as environment variable with the PCERT_
prefix (e.g PCERT_CERT instad of --cert).`,
		TraverseChildren: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
		},
	}
	cmd.AddCommand(
		newCreateCmd(),
		newRequestCmd(),
		newSignCmd(),
		newShowCmd(),
		newConnectCmd(),
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
		ValidArgs: []string{"bash", "zsh", "fish", "ps"},
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
			case "fish":
				err = newRootCmd().GenFishCompletion(os.Stdout, true)
			case "ps":
				err = newRootCmd().GenPowerShellCompletion(os.Stdout)
			default:
				err = fmt.Errorf("unknown shell: %s", shell)
			}
			return err
		},
	}
	return cmd
}
