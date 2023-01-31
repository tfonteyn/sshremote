#!/bin/bash

cd ./openssl || exit

export PASSWORD=secret

openssl dsaparam -out dsa.param 2048

openssl gendsa -out dsa.pem dsa.param
openssl dsa -in dsa.pem -outform PEM -pubout -out dsa.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in dsa.pem -out dsa.pkcs8

openssl gendsa -out dsa_enc.pem -passout pass:$PASSWORD dsa.param
openssl dsa -in dsa_enc.pem -outform PEM -pubout -out dsa_enc.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -passin pass:$PASSWORD -passout pass:$PASSWORD -in dsa_enc.pem -out dsa_enc.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -passin pass:$PASSWORD -passout pass:$PASSWORD -in dsa_enc.pem -traditional -out dsa_enc.pkcs8_traditional


openssl genrsa -out rsa.pem 2048
openssl rsa -in rsa.pem -outform PEM -pubout -out rsa.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa.pem -out rsa.pkcs8

openssl genrsa -out rsa_enc.pem -passout pass:$PASSWORD 2048
openssl rsa -in rsa_enc.pem -outform PEM -pubout -out rsa_enc.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -passin pass:$PASSWORD -passout pass:$PASSWORD -in rsa_enc.pem -out rsa_enc.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -passin pass:$PASSWORD -passout pass:$PASSWORD -in rsa_enc.pem -traditional -out rsa_enc.pkcs8_traditional


# openssl ecparam -list_curves   to get a list of all possible "-name" values
openssl ecparam -name secp256r1 -out secp256r1.param
openssl ecparam -name secp384r1 -out secp384r1.param
openssl ecparam -name secp521r1 -out secp521r1.param

openssl ecparam -in secp256r1.param -genkey -noout -out secp256r1.pem
openssl ecparam -in secp384r1.param -genkey -noout -out secp384r1.pem
openssl ecparam -in secp521r1.param -genkey -noout -out secp521r1.pem

openssl ec -in secp256r1.pem -pubout -out secp256r1.pub
openssl ec -in secp384r1.pem -pubout -out secp384r1.pub
openssl ec -in secp521r1.pem -pubout -out secp521r1.pub

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp256r1.pem -out secp256r1.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp256r1.pem -traditional -out secp256r1.pkcs8_traditional
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp384r1.pem -out secp384r1.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp384r1.pem -traditional -out secp384r1.pkcs8_traditional
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp521r1.pem -out secp521r1.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp521r1.pem -traditional -out secp521r1.pkcs8_traditional


openssl ec -in secp256r1.pem -passout pass:$PASSWORD -out secp256r1_enc.pem -aes256
openssl ec -in secp384r1.pem -passout pass:$PASSWORD -out secp384r1_enc.pem -aes256
openssl ec -in secp521r1.pem -passout pass:$PASSWORD -out secp521r1_enc.pem -aes256

openssl pkcs8 -topk8 -inform PEM -outform PEM -passout pass:$PASSWORD -in secp256r1.pem -out secp256r1_enc.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -passout pass:$PASSWORD -in secp256r1.pem -traditional -out secp256r1_enc.pkcs8_traditional
openssl pkcs8 -topk8 -inform PEM -outform PEM -passout pass:$PASSWORD -in secp384r1.pem -out secp384r1_enc.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -passout pass:$PASSWORD -in secp384r1.pem -traditional -out secp384r1_enc.pkcs8_traditional
openssl pkcs8 -topk8 -inform PEM -outform PEM -passout pass:$PASSWORD -in secp521r1.pem -out secp521r1_enc.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -passout pass:$PASSWORD -in secp521r1.pem -traditional -out secp521r1_enc.pkcs8_traditional


openssl genpkey -algorithm ed25519 -out ed25519.pem
openssl pkey -in ed25519.pem -pubout -out ed25519.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ed25519.pem -out ed25519.pkcs8

openssl genpkey -algorithm ed25519 -pass pass:$PASSWORD -out ed25519_enc.pem
openssl pkey -in ed25519_enc.pem -pubout -out ed25519_enc.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -passin pass:$PASSWORD -passout pass:$PASSWORD -in ed25519_enc.pem -out ed25519_enc.pkcs8


openssl genpkey -algorithm ed448 -out ed448.pem
openssl pkey -in ed448.pem -pubout -out ed448.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ed448.pem -out ed448.pkcs8

openssl genpkey -algorithm ed448 -pass pass:$PASSWORD -out ed448_enc.pem
openssl pkey -in ed448_enc.pem -pubout -out ed448_enc.pub
openssl pkcs8 -topk8 -inform PEM -outform PEM -passin pass:$PASSWORD -passout pass:$PASSWORD -in ed448_enc.pem -out ed448_enc.pkcs8




