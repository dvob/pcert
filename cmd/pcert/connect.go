package main

import (
	"crypto/tls"

	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	var (
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
		}
		all bool
	)
	cmd := &cobra.Command{
		Use:   "connect <host:port>",
		Short: "Connect to a host via TLS and print its server certificate",
		Long:  `Connect to a host via TLS.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]

			conn, err := tls.Dial("tcp", host, tlsConfig)
			if err != nil {
				return err
			}
			conn.Close()

			state := conn.ConnectionState()

			certs := state.PeerCertificates

			if !all {
				certs = certs[0:1]
			}

			for _, cert := range certs {
				printPEM(cert)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&tlsConfig.InsecureSkipVerify, "insecure", tlsConfig.InsecureSkipVerify, "Ignore certificate validation errors during the connect.")
	cmd.Flags().BoolVar(&all, "all", all, "Print all certificates presented by the server and not just the server certificate (leaf).")
	return cmd
}
