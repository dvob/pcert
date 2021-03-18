package pcert

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// Create a key and a self-signed certificate and save it to server.crt and server.key
func ExampleCreate_selfSigned() {
	cert := NewServerCertificate("localhost")

	// self-signed
	certPEM, keyPEM, err := Create(cert, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("server.crt", certPEM, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("server.crt", keyPEM, 0o600)
	if err != nil {
		log.Fatal(err)
	}
}

// Load a root CA from ca.crt and ca.key and use it to create a signed server certificate
func ExampleCreate_signed() {
	// load root CA
	rootCACert, err := Load("ca.crt")
	if err != nil {
		log.Fatal(err)
	}

	rootCAKey, err := LoadKey("ca.key")
	if err != nil {
		log.Fatal(err)
	}

	// create signed server certificate
	cert := NewServerCertificate("localhost")

	certPEM, keyPEM, err := Create(cert, rootCACert, rootCAKey)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("server.crt", certPEM, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("server.crt", keyPEM, 0o600)
	if err != nil {
		log.Fatal(err)
	}
}

// Create a self-signed certificate with a 4096 bit RSA key
func ExampleCreateWithKeyOptions() {
	cert := NewServerCertificate("localhost")

	keyOptions := KeyOptions{
		Algorithm: x509.RSA,
		Size:      4096,
	}

	certPEM, keyPEM, err := CreateWithKeyOptions(cert, keyOptions, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, _ = os.Stdout.Write(certPEM)
	_, _ = os.Stdout.Write(keyPEM)
}

func ExampleExtKeyUsageToString() {
	cert := NewClientCertificate("myUser")
	usageStr := ExtKeyUsageToString(cert.ExtKeyUsage)
	fmt.Println(usageStr)
	// Output:
	// ClientAuth
}

func ExampleKeyUsageToString() {
	cert := NewCACertificate("My Super Root CA")
	usageStr := KeyUsageToString(cert.KeyUsage)
	fmt.Println(usageStr)
	// Output:
	// CRLSign,CertSign
}
