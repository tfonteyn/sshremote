#!/bin/bash

export PASSWORD=secret

mkdir -p opensshv1
cd ./opensshv1 || exit

ssh-keygen -t dsa -f dsa -N "" -C "ssh-keygen dsa"
ssh-keygen -y -f dsa >dsa.pub_ssh2
ssh-keygen -l -f dsa.pub | awk '{print $2}' | sed 's|SHA256:||' | tee dsa.pub.fp_sha256

ssh-keygen -t dsa -f dsa_enc -N "$PASSWORD" -C "ssh-keygen dsa_enc"
ssh-keygen -P "$PASSWORD" -y -f dsa_enc  >dsa_enc.pub_ssh2
ssh-keygen -l -f dsa_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee dsa_enc.pub.fp_sha256

ssh-keygen -t rsa -b 4096 -f rsa -N "" -C "ssh-keygen rsa"
ssh-keygen -y -f rsa >rsa.pub_ssh2
ssh-keygen -l -f rsa.pub | awk '{print $2}' | sed 's|SHA256:||' | tee rsa.pub.fp_sha256

ssh-keygen -t rsa -b 4096 -f rsa_enc -N "$PASSWORD" -C "ssh-keygen rsa_enc"
ssh-keygen -P "$PASSWORD" -y -f rsa_enc  >rsa_enc.pub_ssh2
ssh-keygen -l -f rsa_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee rsa_enc.pub.fp_sha256


ssh-keygen -t ecdsa -b 256 -f ecdsa256 -N "" -C "ssh-keygen ecdsa 256"
ssh-keygen -y -f ecdsa256 >ecdsa256.pub_ssh2
ssh-keygen -l -f ecdsa256.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa256.pub.fp_sha256

ssh-keygen -t ecdsa -b 384 -f ecdsa384 -N "" -C "ssh-keygen ecdsa 384"
ssh-keygen -y -f ecdsa384 >ecdsa384.pub_ssh2
ssh-keygen -l -f ecdsa384.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa384.pub.fp_sha256

ssh-keygen -t ecdsa -b 521 -f ecdsa521 -N "" -C "ssh-keygen ecdsa 521"
ssh-keygen -y -f ecdsa521 >ecdsa521.pub_ssh2
ssh-keygen -l -f ecdsa521.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa521.pub.fp_sha256

ssh-keygen -t ecdsa -b 256 -f ecdsa256_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 256_enc"
ssh-keygen -P "$PASSWORD" -y -f ecdsa256_enc  >ecdsa256_enc.pub_ssh2
ssh-keygen -l -f ecdsa256_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa256_enc.pub.fp_sha256

ssh-keygen -t ecdsa -b 384 -f ecdsa384_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 384_enc"
ssh-keygen -P "$PASSWORD" -y -f ecdsa384_enc  >ecdsa384_enc.pub_ssh2
ssh-keygen -l -f ecdsa384_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa384_enc.pub.fp_sha256

ssh-keygen -t ecdsa -b 521 -f ecdsa521_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 521_enc"
ssh-keygen -P "$PASSWORD" -y -f ecdsa521_enc  >ecdsa521_enc.pub_ssh2
ssh-keygen -l -f ecdsa521_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa521_enc.pub.fp_sha256


ssh-keygen -t ed25519 -f ed25519  -N "" -C "ssh-keygen ed25519"
ssh-keygen -y -f ed25519 >ed25519.pub_ssh2
ssh-keygen -l -f ed25519.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ed25519.pub.fp_sha256

ssh-keygen -t ed25519 -f ed25519_enc  -N "$PASSWORD" -C "ssh-keygen ed25519_enc"
ssh-keygen -P "$PASSWORD" -y -f ed25519_enc  >ed25519_enc.pub_ssh2
ssh-keygen -l -f ed25519_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ed25519_enc.pub.fp_sha256

cd ..

mkdir -p legacy
cd ./legacy || exit

ssh-keygen -t dsa -f dsa -N "" -C "ssh-keygen dsa" -m PEM
ssh-keygen -y -f dsa >dsa.pub_ssh2
ssh-keygen -l -f dsa.pub | awk '{print $2}' | sed 's|SHA256:||' | tee dsa.pub.fp_sha256

ssh-keygen -t dsa -f dsa_enc -N "$PASSWORD" -C "ssh-keygen dsa_enc" -m PEM
ssh-keygen -P "$PASSWORD" -y -f dsa_enc  >dsa_enc.pub_ssh2
ssh-keygen -l -f dsa_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee dsa_enc.pub.fp_sha256

ssh-keygen -t rsa -b 4096 -f rsa -N "" -C "ssh-keygen rsa" -m PEM
ssh-keygen -y -f rsa >rsa.pub_ssh2
ssh-keygen -l -f rsa.pub | awk '{print $2}' | sed 's|SHA256:||' | tee rsa.pub.fp_sha256

ssh-keygen -t rsa -b 4096 -f rsa_enc -N "$PASSWORD" -C "ssh-keygen rsa_enc" -m PEM
ssh-keygen -P "$PASSWORD" -y -f rsa_enc  >rsarsa_enc.pub_ssh2
ssh-keygen -l -f rsa_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee rsa_enc.pub.fp_sha256

ssh-keygen -t ecdsa -b 256 -f ecdsa256 -N "" -C "ssh-keygen ecdsa 256" -m PEM
ssh-keygen -y -f ecdsa256 >ecdsa256.pub_ssh2
ssh-keygen -l -f ecdsa256.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa256.pub.fp_sha256

ssh-keygen -t ecdsa -b 384 -f ecdsa384 -N "" -C "ssh-keygen ecdsa 384" -m PEM
ssh-keygen -y -f ecdsa384 >ecdsa384.pub_ssh2
ssh-keygen -l -f ecdsa384.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa384.pub.fp_sha256

ssh-keygen -t ecdsa -b 521 -f ecdsa521 -N "" -C "ssh-keygen ecdsa 521" -m PEM
ssh-keygen -y -f ecdsa521 >ecdsa521.pub_ssh2
ssh-keygen -l -f ecdsa521.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa521.pub.fp_sha256


ssh-keygen -t ecdsa -b 256 -f ecdsa256_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 256_enc" -m PEM
ssh-keygen -P "$PASSWORD" -y -f ecdsa256_enc  >ecdsa256_enc.pub_ssh2
ssh-keygen -l -f ecdsa256_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa256_enc.pub.fp_sha256

ssh-keygen -t ecdsa -b 384 -f ecdsa384_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 384_enc" -m PEM
ssh-keygen -P "$PASSWORD" -y -f ecdsa384_enc  >ecdsa384_enc.pub_ssh2
ssh-keygen -l -f ecdsa384_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa384_enc.pub.fp_sha256

ssh-keygen -t ecdsa -b 521 -f ecdsa521_enc -N "$PASSWORD" -C "ssh-keygen ecdsa 521_enc" -m PEM
ssh-keygen -P "$PASSWORD" -y -f ecdsa521_enc  >ecdsa521_enc.pub_ssh2
ssh-keygen -l -f ecdsa521_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ecdsa521_enc.pub.fp_sha256


ssh-keygen -t ed25519 -f ed25519  -N "" -C "ssh-keygen ed25519" -m PEM
ssh-keygen -y -f ed25519 >ed25519.pub_ssh2
ssh-keygen -l -f ed25519.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ed25519.pub.fp_sha256

ssh-keygen -t ed25519 -f ed25519_enc  -N "$PASSWORD" -C "ssh-keygen ed25519_enc" -m PEM
ssh-keygen -P "$PASSWORD" -y -f ed25519_enc  >ed25519.pub_ssh2
ssh-keygen -l -f ed25519_enc.pub | awk '{print $2}' | sed 's|SHA256:||' | tee ed25519_enc.pub.fp_sha256

cd ..