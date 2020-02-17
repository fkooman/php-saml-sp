#!/bin/sh

for TYPE in encryption signing
do
    openssl req \
            -nodes \
            -subj "/CN=SAML SP (${TYPE})" \
            -set_serial 1 \
            -x509 \
            -sha256 \
            -newkey rsa:3072 \
            -keyout "./${TYPE}.key" \
            -out "./${TYPE}.crt" \
            -days 3650
done
