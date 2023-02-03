package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.KeyPairDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairECDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairEdDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairRSA;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;

import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;

/**
 * Provides {@link #generateKeyPair(String, int)} to generate keys.
 */
public class KeyPairGen {

    private static final String UNSUPPORTED_TYPE_X = "Unsupported type: ";


    @NonNull
    private final SshClientConfig config;

    public KeyPairGen(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Creates a new key pair.
     *
     * @param keyType dsa | ecdsa | ed25519 | ed448 | rsa
     * @param keySize the size of the keys, in bits. Must be suitable to the type.
     *                Ignored for ed25519 | ed448
     *
     * @return the new key pair.
     */
    @NonNull
    public SshKeyPair generateKeyPair(@NonNull final String keyType,
                                      final int keySize)
            throws GeneralSecurityException {
        switch (keyType.toLowerCase(Locale.ENGLISH)) {
            case "rsa":
                return new KeyPairRSA(config, keySize);

            case "dsa":
                return new KeyPairDSA(config, keySize);

            case "ecdsa":
                return new KeyPairECDSA(config, keySize);

            case "ed25519":
                return new KeyPairEdDSA(config, "Ed25519");

            case "ed448":
                return new KeyPairEdDSA(config, "Ed448");

            default:
                throw new InvalidKeySpecException(UNSUPPORTED_TYPE_X + keyType);
        }
    }
}
