package main

import (
	"fmt"

	"github.com/dsbrng25b/pcert"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "list <option>",
		Short:     "List avialable settings for options.",
		Long:      "List avialable settings for the following options: key-usage, ext-key-usage, sign-alg, key-alg",
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
				for s, _ := range pcert.SignatureAlgorithms {
					fmt.Println(s)
				}
			case "key-alg":
				for k, _ := range pcert.PublicKeyAlgorithms {
					fmt.Println(k)
				}
			default:
				return fmt.Errorf("unknown type: %s", t)
			}
			return nil
		},
	}
	return cmd
}
