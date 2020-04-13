# p(lain)cert
`pcert` is a thin wrapper around the `crypto/x509`certificate library. Its goal is to make creation of certifictes and keys as simple as possible. In addition to `crypto/x509` it sets some defaults during the certificate creation if they are not already set explicitly:
* **SerialNumber**: Generates and sets a random serial number
* **SubjectKeyId**: Generates and sets the subject key id from the public key
* **AuthorityKeyId**: Sets authority key id from signing certificate
* **NotBefore, NotAfter**: Sets the validity period

If you dont know what these things are and just want to create some certificates then you might want to use `pcert`.

## Usage
### CLI
Create a CA certificate `myca.crt`and `myca.key`:
```
pcert create myca --ca
```

Create a server certificate or `api.test.local` signed from `myca`:
```
pcert create api.test.local --server --from myca
# or set SANs
pcert create api.test.local --server --from myca --dns api1.test.local --dns superapi.test.local --ip 127.0.0.1
```
This creates `api.test.local.crt` and `api.test.local.key`. With the `--from myca` option we say that we want to sign the new certificate with `myca.crt` and `myca.key`. The option `--from` is a shortcut for `--sign-cert=myca.crt` and `--sign-key=myca.key`.
