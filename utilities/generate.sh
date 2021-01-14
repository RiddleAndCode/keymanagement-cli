#!/bin/sh

set -xe

out=../ssl/

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
-extensions v3_ca \
-extfile ./openssl.cnf

cat $out/client-end-cert.pem $out/client-ca-cert.pem > $out/client-cert.pem

# cleanup
rm $out/client-end-cert.pem $out/client.req $out/nistp256.pem $out/nistp384.pem