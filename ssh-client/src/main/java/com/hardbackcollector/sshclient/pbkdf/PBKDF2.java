package com.hardbackcollector.sshclient.pbkdf;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;

public interface PBKDF2 {

    @NonNull
    byte[] generateSecretKey(@NonNull byte[] passphrase,
                             @NonNull byte[] salt,
                             int iterations,
                             int keyLength)
            throws GeneralSecurityException;
}
