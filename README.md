# pcert
[![PkgGoDev](https://pkg.go.dev/badge/github.com/dvob/pcert)](https://pkg.go.dev/github.com/dvob/pcert)

`pcert` aims to ease the creation of x509 certificates and keys.

The simple case is as easy as this:
```
pcert create
```

This would write the certificate and key to standard output.

You can write the certificate and key to a file by specifying either only the certificate path or both pathes:
```
pcert create tls.crt
pcert create tls.crt tls.key
```

The two invocations above are equivalent. When omitting the path for the key file the key file is written into the same directory as the certificate to a file with the same name but ending in `.key`.

# Quick start
## Self-signed server certificate
```
pcert create tls.crt --server --dns myserver.example.com
```

## Signed certificates (CA)
To create your own CA and sign certificates with it you first create a CA (self-signed) certificate:
```
pcert create ca.crt --ca --name "My CA"
```

Then you can create and sign certificates with it:
```
# server
pcert create server.crt --server --dns foo.example.com --dns bar.example.com

# client
pcert create client.crt --client --name "my client"
```

# Auto completion
Shell completion can be enabled for `bash`, `zsh`, `fish` and `ps` (Power Shell). It supports not only completion for the commands, but also for certain flags (e.g. `--key-usage`, `--ext-key-usage`, `--sign-alg`) where the valid options are hard to remember.
```shell
source <( pcert completion bash )
```

# Expiry
The validity period of certificates default to one year starting from the creation time.
The period can be changed by using the options `--not-before`, `--not-after` and `--expiry`.
The options `--not-before` and `--not-after` allow to set the NotBefore and NotAfter value to a certain date (RFC3339):
```shell
pcert create --not-before 2020-01-01T12:00:00+01:00 --not-after 2020-06-01T12:00:00+01:00
```

The option `--expiry` allows to specify a duration instead of explicit dates:
```shell
# certificate valid until 90days from now
pcert create --expiry 90d

# certificate valid until 3 years (3 * 365 days)
pcert create --expiry 3y
```

# Environment variables
All command line flags can also be set using environment variables.
For this you have to make the flag name upper-case, repalce `-` with `_` and prefix it with `PCERT_`.

For example:
* `--sign-cert=ca.crt` => `PCERT_SIGN_CERT=ca.crt`
* `--subject-country CH` => `PCERT_SUBJECT_COUNTRY=CH`

Command line flags take precedence over environment variables.
Be aware that for flags you can specify multiple times (e.g. `--dns`) the values from the environment and form the command line flags are combined.

# Examples
## Local CA
Here is an example of how you could use `pcert` to create a local CA:

Create CA certificate and key in `~/pki`:
```shell
mkdir ~/pki
pcert create ~/pki/ca.crt --ca
```

If you like you can add the newly created certificate `~/pki/ca.crt` to you system trust store.

Now we set `PCERT_SIGN_CERT` that all newly created certificates are signed with our CA in `~/pki`. This environment variable could be added to `.bashrc` for example:
```shell
export PCERT_SIGN_CERT=~/pki/ca.crt
export PCERT_SIGN_KEY=~/pki/ca.key
```

From now on if we use `pcert create` it creates certificates which are signed by our local CA.
If you still would create a self-signed certificate you would have to set `--sign-cert=""`.

## Intermediate CA
This example shows how to make an intermediate CA certificate:

Create root CA certificate and key:
```shell
pcert create root.crt --ca
```

Create intermediate CA certificate:
```shell
pcert create intermediate.crt --ca --sign-cert root.crt
```

Create server certificate from the intermediate CA:
```shell
pcert create server.crt --sign-cert indtermediate.crt --dns myserver.example.com
```
