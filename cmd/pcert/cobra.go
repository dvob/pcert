package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func WithEnv(c *cobra.Command) *cobra.Command {
	if c.HasParent() {
		c = c.Root()
	}

	args := os.Args[1:]

	var (
		cmd *cobra.Command
		err error
	)
	if c.TraverseChildren {
		cmd, _, err = c.Traverse(args)
	} else {
		cmd, _, err = c.Find(args)
	}

	if err != nil {
		fmt.Println("ERRROR hier")
		return c
	}

	var errs []error
	for _, fs := range []*pflag.FlagSet{
		cmd.Flags(),
		cmd.PersistentFlags(),
	} {
		fs.VisitAll(func(f *pflag.Flag) {
			optName := strings.ToUpper(f.Name)
			optName = strings.ReplaceAll(optName, "-", "_")
			varName := envVarPrefix + optName
			if val, ok := os.LookupEnv(varName); ok {
				err := f.Value.Set(val)
				if err != nil {
					errs = append(errs, fmt.Errorf("invalid environment variable '%s': %w", varName, err))
				}
				f.Changed = true
			}
		})
	}
	if len(errs) != 0 {
		// we want to report the error after errors from the normal
		// parsing that for example a --help would still take effect.
		// to report the error we just overwrite PreRunE
		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			return errors.Join(errs...)
		}
	}
	return c
}
