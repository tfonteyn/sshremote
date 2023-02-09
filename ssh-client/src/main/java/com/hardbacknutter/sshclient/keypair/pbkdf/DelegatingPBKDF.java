package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

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
    @Nullable
    private byte[] cipherIV;

    @Nullable
    private PBKDF delegate;

    @Override
    public void setCipher(@NonNull final SshCipher cipher,
                          @NonNull final byte[] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
    }

    @NonNull
    @Override
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
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

    @NonNull
    @Override
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
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
