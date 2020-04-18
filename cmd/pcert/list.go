package main

import (
	"fmt"

	"github.com/dsbrng25b/pcert"
	cmdutil "github.com/dsbrng25b/pcert/cmd"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "list <type>",
		ValidArgs: []string{"key-usage", "ext-key-usage", "sign-alg", "key-alg"},
		Args:      cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			switch t {
			case "key-usage":
				for u, _ := range pcert.KeyUsages {
					fmt.Println(u)
				}
			case "ext-key-usage":
				for u, _ := range pcert.ExtKeyUsages {
					fmt.Println(u)
				}
			case "sign-alg":
				for _, a := range cmdutil.GetSignatureAlgorithms() {
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
