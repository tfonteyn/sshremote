#!/bin/bash

cd ./opensshv1 || exit

export PASSWORD=secret

ssh-keygen -t dsa -f dsa -N "" -C "ssh-keygen dsa"
ssh-keygen -t dsa -f dsa_enc -N "$PASSWORD" -C "ssh-keygen dsa_enc"

ssh-keygen -t rsa -b 4096 -f rsa -N "" -C "ssh-keygen rsa"
ssh-keygen -t rsa -b 4096 -f rsa_enc -N "$PASSWORD" -C "ssh-keygen rsa_enc"

ssh-keygen -t ecdsa -b 256 -f ecdsa256 -N "" -C "ssh-keygen ecdsa 256"
ssh-keygen -t ecdsa -b 384 -f ecdsa384 -N "" -C "ssh-keygen ecdsa 384"
ssh-keygen -t ecdsa -b 521 -f ecdsa521 -N "" -C "ssh-keygen ecdsa 521"

ssh-keygen -t ecdsa -b 256 -f ecdsa256_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 256_enc"
ssh-keygen -t ecdsa -b 384 -f ecdsa384_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 384_enc"
ssh-keygen -t ecdsa -b 521 -f ecdsa521_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 521_enc"

ssh-keygen -t ed25519 -f ed25519  -N "" -C "ssh-keygen ed25519"
ssh-keygen -t ed25519 -f ed25519_enc  -N "$PASSWORD" -C "ssh-keygen ed25519_enc"


cd ../legacy || exit

ssh-keygen -t dsa -f dsa -N "" -C "ssh-keygen dsa" -m PEM
ssh-keygen -t dsa -f dsa_enc -N "$PASSWORD" -C "ssh-keygen dsa_enc" -m PEM

ssh-keygen -t rsa -b 4096 -f rsa -N "" -C "ssh-keygen rsa" -m PEM
ssh-keygen -t rsa -b 4096 -f rsa_enc -N "$PASSWORD" -C "ssh-keygen rsa_enc" -m PEM

ssh-keygen -t ecdsa -b 256 -f ecdsa256 -N "" -C "ssh-keygen ecdsa 256" -m PEM
ssh-keygen -t ecdsa -b 384 -f ecdsa384 -N "" -C "ssh-keygen ecdsa 384" -m PEM
ssh-keygen -t ecdsa -b 521 -f ecdsa521 -N "" -C "ssh-keygen ecdsa 521" -m PEM

ssh-keygen -t ecdsa -b 256 -f ecdsa256_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 256_enc" -m PEM
ssh-keygen -t ecdsa -b 384 -f ecdsa384_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 384_enc" -m PEM
ssh-keygen -t ecdsa -b 521 -f ecdsa521_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 521_enc" -m PEM

ssh-keygen -t ed25519 -f ed25519  -N "" -C "ssh-keygen ed25519" -m PEM
ssh-keygen -t ed25519 -f ed25519_enc  -N "$PASSWORD" -C "ssh-keygen ed25519_enc" -m PEM