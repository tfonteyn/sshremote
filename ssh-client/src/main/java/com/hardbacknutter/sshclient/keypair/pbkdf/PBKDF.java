package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Password Based Key Derivation Function.
 * <p>
 * If an implementation has an {@code init(...)} method then it MUST be called after instantiation.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898#section-5">rfc2898#section-5</a>
 */
public interface PBKDF {

    default void setCipher(@NonNull final SshCipher cipher) {
        setCipher(cipher, new byte[cipher.getIVSize()]);
    }

    void setCipher(@NonNull SshCipher cipher,
                   @NonNull byte[] cipherIV);

    /**
     * Generates an encoded SecretKey using the given passphrase and length using
     * the algorithm of the specific implementation.
     * <p>
     * Dev. note: not strictly needed to be part of the interface, but provided as per PBKDF.
     *
     * @param passphrase to use
     * @param keyLength  desired key length to generate
     *
     * @return encoded SecretKey
     *
     * @throws GeneralSecurityException on any failure
     */
    @NonNull
    byte[] generateSecretKey(@NonNull byte[] passphrase,
                             int keyLength)
            throws GeneralSecurityException;

    /**
     * Decrypt the given private key blob using the given passphrase.
     *
     * @param passphrase to use
     * @param blob       to decrypt
     *
     * @return plain (encoded) key blob
     */
    @NonNull
    byte[] decrypt(@NonNull byte[] passphrase,
                   @NonNull byte[] blob)
            throws GeneralSecurityException, IOException;
}
