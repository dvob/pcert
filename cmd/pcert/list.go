package main

import (
	"fmt"

	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available settings for options.",
		Long:  "List available settings for the following options: key-usage, ext-key-usage, sign-alg, key-alg",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Key Usage (--key-usage):")
			for usage := range pcert.KeyUsages {
				fmt.Printf("  %s\n", usage)
			}
			fmt.Println()

			fmt.Println("Extended Key Usage (--ext-key-usage):")
			for usage := range pcert.ExtKeyUsages {
				fmt.Printf("  %s\n", usage)
			}
			fmt.Println()

			fmt.Println("Signature Algorithm (--sign-alg):")
			for _, alg := range pcert.SignatureAlgorithms {
				fmt.Printf("  %s\n", alg)
			}
			fmt.Println()

			fmt.Println("Public Key Algorithm (--key-alg):")
			for _, alg := range pcert.PublicKeyAlgorithms {
				fmt.Printf("  %s\n", alg)
			}

			return nil
		},
	}
	return cmd
}
