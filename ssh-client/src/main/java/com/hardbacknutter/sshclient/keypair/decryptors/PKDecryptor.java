package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface PKDecryptor {

    default void setCipher(@NonNull final SshCipher cipher) {
        setCipher(cipher, new byte[cipher.getIVSize()]);
    }

    void setCipher(@NonNull SshCipher cipher,
                   @NonNull byte[] cipherIV);

    @NonNull
    byte[] decrypt(@NonNull byte[] passphrase,
                   @NonNull byte[] blob)
            throws GeneralSecurityException, IOException;
}
