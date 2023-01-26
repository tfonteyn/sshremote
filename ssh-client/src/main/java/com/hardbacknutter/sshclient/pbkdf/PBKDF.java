package com.hardbacknutter.sshclient.pbkdf;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;

/**
 * Password based key derivation function.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898#section-5">rfc2898#section-5</a>
 */
public interface PBKDF {

    @NonNull
    byte[] generateSecretKey(@NonNull byte[] passphrase,
                             int keyLength)
            throws GeneralSecurityException;
}
