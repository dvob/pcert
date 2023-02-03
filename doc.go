/*
Package pcert aims to ease the creation of x509 certificates and keys.
This package provides the following main functions:

  - Create: creates a certificate and a key
  - Request: creates a CSR and a key
  - Sign: signs a certificate or a CSR with an existing certificate and key

The results of the functions which return certificates, CSRs and keys are all
PEM encoded.

All functions without special suffix refer to a certificates. Functions for CSR
and Key use an appropriate suffix.
For example the function Load loads a certificate from a file, whereas LoadKey
or LoadCSR are for keys resp. CSRs.

	    import (
	            "io/ioutil"

	            "github.com/dvob/pcert"
	    )

	    func main() {
	            cert := pcert.NewServerCertificate("www.example.local")

				// self-signed
	            certPEM, keyPEM, _ := pcert.Create(cert, nil, nil)

	            _ = ioutil.WriteFile("server.crt", certPEM, 0644)
	            _ = ioutil.WriteFile("server.key", keyPEM, 0600)

	    }
*/
package pcert
