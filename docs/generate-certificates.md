# Generating Key Management CLI Certificates

The Keymanager CLI requires client certificates to run. Specifically the certificate generated can be any valid TLSv3 non CA certificate keypair where

* `client-key.pem`: is a PEM encoded private key
* `client-cert.pem`: is the PEM encoded certificate chain belonging to the private key including the Certificate Authority certificate
* `client-ca-cert.pem`: is the PEM encoded certifcate belonging to the signing certificate authority

`client-key.pem` and `client-cert.pem` should be kept for usage with the CLI, whereas the `client-ca-cert.pem` should be sent to Riddle&Code.

## Example
`generate.sh`

```sh
#!/bin/sh

set -xe

out=generated

rm -rf $out/
mkdir -p $out/

# setup
openssl ecparam -name prime256v1 -out $out/nistp256.pem
openssl ecparam -name secp384r1 -out $out/nistp384.pem


# generate CA keypair
openssl req -nodes \
        -x509 \
        -newkey ec:$out/nistp384.pem \
        -keyout $out/client-ca-key.pem \
        -out $out/client-ca-cert.pem \
        -sha256 \
        -batch \
        -days 3650 \
        -subj "/CN=Client CA"


# generate leaf keypair
openssl req -nodes \
        -newkey ec:$out/nistp256.pem \
        -keyout $out/client-key.pem \
        -out $out/client.req \
        -sha256 \
        -batch \
        -days 2000 \
        -subj "/CN=Client"

# sign leaf certificate
openssl x509 -req \
        -in $out/client.req \
        -out $out/client-end-cert.pem \
        -CA $out/client-ca-cert.pem \
        -CAkey $out/client-ca-key.pem \
        -sha256 \
        -days 2000 \
        -set_serial 456 \
        -extensions client -extfile openssl.cnf

cat $out/client-end-cert.pem $out/client-ca-cert.pem > $out/client-cert.pem


# cleanup
rm $out/client-end-cert.pem $out/client.req $out/nistp256.pem $out/nistp384.pem
```

`openssl.cnf`

```sh
[ client ]
basicConstraints = critical,CA:false
keyUsage = nonRepudiation, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
```

## Running The Example
Copy the two files above to a directory and run `sh generate.sh`. The script should generate valid client certificates in the correct format.