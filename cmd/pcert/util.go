package main

import (
	"crypto/x509"
	"time"

	"github.com/dvob/pcert"
	cmdutil "github.com/dvob/pcert/cmd"
	"github.com/spf13/cobra"
)

type cert struct {
	path   string
	cert   *x509.Certificate
	expiry time.Duration
	ca     bool
	client bool
	server bool
}

func (c *cert) bindFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&c.ca, "ca", false, "Create a CA certificate")
	cmd.Flags().BoolVar(&c.server, "server", false, "Create a server certificate")
	cmd.Flags().BoolVar(&c.client, "client", false, "Create a client certificate")
	cmd.Flags().Var(newDurationValue(&c.expiry), "expiry", "Validity period of the certificate. If --not-after is set this option has no effect.")
	cmd.Flags().StringVar(&c.path, "cert", "", "Output file for the certificate. Defaults to <name>.crt")

	cmdutil.BindCertificateFlags(cmd.Flags(), c.cert)
	cmdutil.RegisterCertificateCompletionFuncs(cmd)
}

// set options on certificate
func (c *cert) configure() {
	// profile
	if c.ca {
		pcert.SetCAProfile(c.cert)
	}

	if c.server {
		pcert.SetServerProfile(c.cert)
	}

	if c.client {
		pcert.SetClientProfile(c.cert)
	}

	// expiry
	if c.expiry == time.Duration(0) {
		return
	}

	if c.cert.NotBefore.IsZero() {
		c.cert.NotBefore = time.Now()
	}

	if c.cert.NotAfter.IsZero() {
		c.cert.NotAfter = c.cert.NotBefore.Add(c.expiry)
		return
	}
}

type key struct {
	path string
	opts pcert.KeyOptions
}

func (k *key) bindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&k.path, "key", "", "Output file for the key. Defaults to <name>.key")

	cmdutil.BindKeyFlags(cmd.Flags(), &k.opts)
	cmdutil.RegisterKeyCompletionFuncs(cmd)
}

type signPair struct {
	key       interface{}
	keyFile   string
	cert      *x509.Certificate
	certFile  string
	shortPath string
}

func (s *signPair) bindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&s.certFile, "sign-cert", "", "Certificate used to sign the certificate")
	cmd.Flags().StringVar(&s.keyFile, "sign-key", "", "Key used to sign the certificates")
	cmd.Flags().StringVar(&s.shortPath, "with", "", "Specify a name of a key pair (<name>.crt, <name>.key) which you want to sign your certificate with. This can be used insted of --sign-cert and --sign-key")
}

func (s *signPair) load() error {
	var err error
	if s.shortPath != "" {
		s.certFile = s.shortPath + certFileSuffix
		s.keyFile = s.shortPath + keyFileSuffix
	}

	if s.certFile == "" && s.keyFile == "" {
		return nil
	}

	s.key, err = pcert.LoadKey(s.keyFile)
	if err != nil {
		return err
	}
	s.cert, err = pcert.Load(s.certFile)
	return err
}
