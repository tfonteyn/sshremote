package com.hardbacknutter.sshclient.keypair.pbkdf;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;

/**
 * Acts as a placeholder for a deferred decryption as used by OpenSSH.
 */
public class DelegatingPBKDF
        implements PBKDF {

    @Nullable
    private SshCipher cipher;
    private byte @Nullable [] cipherIV;

    @Nullable
    private PBKDF delegate;

    @Override
    public void setCipher(@NonNull final SshCipher cipher,
                          final byte @NonNull [] cipherIV) {
        this.cipher = cipher;
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
        if (cipher == null || cipherIV == null) {
            throw new KeyException("Cipher/iv not set");
        }

        if (delegate == null) {
            throw new KeyException("delegate not set");
        }

        delegate.setCipher(cipher, cipherIV);
        return delegate.decrypt(passphrase, blob);
    }
}
