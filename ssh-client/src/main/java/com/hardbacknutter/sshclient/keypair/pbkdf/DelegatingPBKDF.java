package com.hardbacknutter.sshclient.keypair.pbkdf;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;

/**
 * Acts as a placeholder for a deferred decryption as used by OpenSSH.
 */
public class DelegatingPBKDF
        implements PBKDF {

    @Nullable
    private String algorithm;
    private int keySize;
    private byte @Nullable [] cipherIV;

    @Nullable
    private PBKDF delegate;

    @Override
    public void setCipher(final @NonNull String transformation,
                          final int keySize,
                          final byte @NonNull [] cipherIV) {
        this.algorithm = transformation;
        this.keySize = keySize;
        this.cipherIV = cipherIV;
    }

        @Override
    public byte @NonNull [] generateSecretKey(final byte @NonNull [] passphrase,
                                    final int keyLength)
            throws GeneralSecurityException {
        if (delegate == null) {
            throw new KeyException("delegate not set");
        }
        return delegate.generateSecretKey(passphrase, keyLength);
    }

    public void setDelegate(@Nullable final PBKDF delegate) {
        this.delegate = delegate;
    }

        @Override
    public byte @NonNull [] decrypt(final byte @NonNull [] passphrase,
                          final byte @NonNull [] blob)
            throws GeneralSecurityException, IOException {
        if (algorithm == null || cipherIV == null) {
            throw new KeyException("Cipher/iv not set");
        }

        if (delegate == null) {
            throw new KeyException("delegate not set");
        }

        delegate.setCipher(algorithm, keySize, cipherIV);
        return delegate.decrypt(passphrase, blob);
    }
}
