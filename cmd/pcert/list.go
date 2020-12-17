package main

import (
	"fmt"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "list <option>",
		Short:     "List available settings for options.",
		Long:      "List available settings for the following options: key-usage, ext-key-usage, sign-alg, key-alg",
		ValidArgs: []string{"key-usage", "ext-key-usage", "sign-alg", "key-alg"},
		Args:      cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			switch t {
			case "key-usage":
				for u := range pcert.KeyUsages {
					fmt.Println(u)
				}
			case "ext-key-usage":
				for u := range pcert.ExtKeyUsages {
					fmt.Println(u)
				}
			case "sign-alg":
				for s := range pcert.SignatureAlgorithms {
					fmt.Println(s)
				}
			case "key-alg":
				for k := range pcert.PublicKeyAlgorithms {
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
