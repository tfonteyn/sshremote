package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFBCrypt;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;

public class DecryptBCrypt
        implements PKDecryptor {

    @NonNull
    private final PBKDFBCrypt pbkdf;
    @Nullable
    private SshCipher cipher;

    public DecryptBCrypt(@NonNull final byte[] salt,
                         final int rounds)
            throws NoSuchAlgorithmException {
        pbkdf = new PBKDFBCrypt().init(salt, rounds);
    }

    @Override
    public void setCipher(@Nullable final SshCipher cipher,
                          @Nullable final byte[] cipherIV) {
        this.cipher = cipher;
    }

    @NonNull
    @Override
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
            throws GeneralSecurityException, IOException {
        if (cipher == null) {
            throw new KeyException("Cipher not set");
        }

        final byte[] plainKey = new byte[blob.length];

        byte[] pbeKey = null;
        try {
            pbeKey = pbkdf.generateSecretKey(passphrase, 48);
            // split into key and IV
            final byte[] key = Arrays.copyOfRange(pbeKey, 0, 32);
            final byte[] iv = Arrays.copyOfRange(pbeKey, 32, 48);
            // and decrypt the blob
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            cipher.doFinal(blob, 0, blob.length, plainKey, 0);

        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
            Arrays.fill(passphrase, (byte) 0);
        }

        return plainKey;
    }
}
