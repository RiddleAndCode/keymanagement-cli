# Generating Key Management CLI Certificates

The Keymanager CLI requires client certificates to run. Specifically the certificate generated can be any valid TLSv3 non CA certificate keypair where

* `client-key.pem`: is a PEM encoded private key
* `client-cert.pem`: is the PEM encoded certificate chain belonging to the private key including the Certificate Authority certificate
* `client-ca-cert.pem`: is the PEM encoded certifcate belonging to the signing certificate authority

`client-key.pem` and `client-cert.pem` should be kept for usage with the CLI, whereas the `client-ca-cert.pem` should be sent to Riddle&Code.

## Generating self-signed certificates

1. Configure OpenSSL by renaming either `openssl-linux.cnf` or `openssl-mac-os-x.cnf` to `openssl.cnf`.
2. Run `sh generate.sh`. This will create the certificates in `keymanagement-cli/ssl`.

Remark: the Mac OS X configuration was created based on hints given in https://github.com/jetstack/cert-manager/issues/279.