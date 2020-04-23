# plaincert
[![GoDoc](https://godoc.org/github.com/dsbrng25b/pcert?status.svg)](https://godoc.org/github.com/dsbrng25b/pcert)
[![Go Report Card](https://goreportcard.com/badge/github.com/dsbrng25b/pcert)](https://goreportcard.com/report/github.com/dsbrng25b/pcert)
[![Build](https://github.com/dsbrng25b/pcert/workflows/main/badge.svg?branch=master)](https://github.com/dsbrng25b/pcert/actions)

**p**lain**cert** aims to ease the creation of x509 certificates and keys. It can be used as CLI tool or as Go library ([godoc](https://godoc.org/github.com/dsbrng25b/pcert)).  

## Quick Start
```shell
# create CA
pcert create myca --ca

# create server certificate
pcert create myapp.company.com --from myca \
	--server \
	--dns api.myapp.company.com \
	--dns localhost \
	--ip 127.0.0.1 \
	--ip 192.168.10.5

# create client certificate
pcert create myuser --client --from myca
```

## General
With `pcert create <name>` you can create a new certificate and key. The output file names are constructed using the name (`<name>.crt` and `<name>.key`). This can be changed by using the options `--cert <file>` and `--key <file>`.   
The name is also set as the common name in the subject of the certificate. This can be changed with the `--subject` option (e.g `--subject "CN=My fancy name"`).  
All created certificates, keys and CSRs are saved PEM encoded and all files which are read are expected to be PEM encoded as well.  
All options can also be specified using environment variables in the form `PCERT_<OPTION>` (e.g. `--sign-cert` is `PCERT_SIGN_CERT`).  
Shell completion can be enabled for `bash` and `zsh`. It supports not only completion for the commands, but also for certain flags (e.g. `--key-usage`, `--ext-key-usage`, `--sign-alg`) where the valid options are hard to remember.
```shell
source <( pcert completion bash )
```

### Self-Signed Certificates
If no options for signing are specified a self-signed certificate is created. This is used for the creation of a CA certificates or for test purposes.

Create a CA certificate `myca.crt` and key `myca.key`:
```shell
pcert create myca --ca
```

### Signed Certificates
To sign a new certificate with an existing certificate and key, you can use the options `--sign-cert <file>` and `--sign-key <file>`. For these two options there is also the shortform `--from <name>`, which uses the files `<name>.crt` and `<name>.key`.

Create a server certificate signed from `myca.crt` and `myca.key`:
```shell
pcert create api.test.local --server --from myca
```

Create a client certificate signed from `myca.crt` and `myca.key`:
```shell
pcert create myUser --client --from myca
```

### Subject Alternative Names (SANs)
To set subject alternative names on certificates you can use the options `--dns`, `--ip`, `--email` and `--uri`:
```shell
pcert create api.test.local --from myca --server \
	--dns api1.test.local \
	--dns superapi.test.local \
	--ip 127.0.0.1 \
	--ip 192.168.23.5
```

### Profiles
To ease the creation of certificates with certain characteristics theare are three predefined profiles:
* CA: `--ca`
* Server: `--server`
* Client: `--client`

If you use these options, settings (e.g key usage) which are typical for the specific profile are set for you. The same effect can be achieved by using the appropriate options individually.

### Expiry
The validity period of certificates default to one year starting from the creation time.
The period can be changed by using the options `--not-before`, `--not-after` and `--expiry`.
The options `--not-before` and `--not-after` allow to set the NotBefore and NotAfter value to a certain date (RFC3339):
```shell
pcert create mycert --not-before 2020-01-01T12:00:00+01:00 --not-after 2020-06-01T12:00:00+01:00
```

The option `--expiry` allows to specify a duration instead of explicit dates:
```shell
# certificate valid until 90days from now
pcert create mycert --expiry 90d

# certificate valid until 3 years (3 * 365 days)
pcert create mycert --expiry 3y
```

### Subject
With the option `--subject` you can set the subject of the certificate:
```shell
pcert create myclient --client --subject "CN=My User/O=Snakeoil Ltd./OU=My Team"
```

If the option is specified multiple times the values are combined:
```shell
export PCERT_SUBJECT="C=CH/L=Bern/O=Snakeoil Ltd."
pcert create myclient --client --subject "CN=David Schneider" --subject "OU=My Org Unit"
```
This would result in: `C=CH/L=Bern/O=Snakeoil Ltd./OU=My Org Unit/CN=David Schneider`

## Examples
### Local CA
Here is an example of how you could use `pcert` to create a local CA:

Create CA certificate and key in `~/pki`:
```shell
mkdir ~/pki
pcert create ca --ca --cert ~/pki/ca.crt --key ~/pki/ca.key
```
If you like you can add the newly created certificate `~/pki/ca.crt` to you system trust store.

Now we set `PCERT_SIGN_CERT` and `PCERT_SIGN_KEY` that all newly created certificates are signed with our CA in `~/pki`. This could be added for example to `.bashrc`:
```shell
export PCERT_SIGN_CERT=~/pki/ca.crt
export PCERT_SIGN_KEY=~/pki/ca.key
```

From now on if we use `pcert create` it creates certificates which are signed by our local CA.

### Intermediate CA
This example shows how to make an intermediate CA certificate:

Create root CA certificate and key:
```shell
pcert create myroot --ca
```

Create intermediate CA certificate:
```shell
pcert create myindtermediate --ca --sign-cert myroot.crt --sign-key myroot.key
```

Create server certificate from the intermediate CA:
```shell
pcert create myserver --server --sign-cert myindtermediate.crt --sign-key myindtermediate.key
```
