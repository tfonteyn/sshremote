package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;

/**
 * Password based key derivation function.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898#section-5">rfc2898#section-5</a>
 */
public interface PBKDF {

    /**
     * Generates an encoded SecretKey using the given passphrase and length using
     * the algorithm of the specific implementation.
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
}
