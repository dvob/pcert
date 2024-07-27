package main

import (
	"github.com/dvob/pcert"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func registerKeyFlags(cmd *cobra.Command, keyOpts *pcert.KeyOptions) {
	bindKeyFlags(cmd.Flags(), keyOpts)

	_ = cmd.RegisterFlagCompletionFunc("key-alg", keyAlgorithmCompletionFunc)
}

func bindKeyFlags(fs *pflag.FlagSet, keyOptions *pcert.KeyOptions) {
	fs.Var(newKeyAlgorithmValue(&keyOptions.Algorithm), "key-alg", "Public key algorithm. See 'pcert list' for available algorithms.")
	fs.IntVar(&keyOptions.Size, "key-size", keyOptions.Size, "Key Size. This defaults to 256 for ECDSA and to 2048 for RSA.")
}
