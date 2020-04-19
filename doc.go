/*
Package pcert aims to ease the creation of x509 certificates and keys.
It allows to create and sign certificates and their coresponding keys in only a few simple steps.
    import (
            "io/ioutil"

            "github.com/dsbrng25b/pcert"
    )

    func main() {
            cert := pcert.NewServerCertificate("www.example.local")

            certPEM, keyPEM, _ := pcert.Create(cert, nil, nil)

            _ = ioutil.WriteFile("server.crt", certPEM, 0644)
            _ = ioutil.WriteFile("server.key", keyPEM, 0600)

    }
*/
package pcert
