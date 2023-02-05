package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.KeyPairPKCS8;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;

import org.bouncycastle.util.io.pem.PemObject;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

class PKCS8Reader {

    @NonNull
    private final SshClientConfig config;

    PKCS8Reader(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    @NonNull
    SshKeyPair parse(@NonNull final PemObject pem)
            throws InvalidKeyException, GeneralSecurityException {
        switch (pem.getType()) {
            case "ENCRYPTED PRIVATE KEY": {
                return new KeyPairPKCS8.Builder(config)
                        .setPrivateKey(pem.getContent(), true)
                        .build();
            }
            case "PRIVATE KEY": {
                return new KeyPairPKCS8.Builder(config)
                        .setPrivateKey(pem.getContent(), false)
                        .build();
            }
            default:
                throw new InvalidKeyException("Invalid PKCS8 PEM format: " + pem.getType());
        }
    }
}
