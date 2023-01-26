package com.hardbacknutter.sshclient.pbkdf;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;

public interface PBKDF2 {

    @NonNull
    byte[] generateSecretKey(@NonNull byte[] passphrase,
                             int keyLength)
            throws GeneralSecurityException;
}
