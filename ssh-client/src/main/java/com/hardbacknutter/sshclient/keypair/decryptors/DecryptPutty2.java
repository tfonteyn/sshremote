package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.pbkdf.PBKDFPutty2;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;

public class DecryptPutty2 implements PKDecryptor {

    @NonNull
    private final PBKDF pbkdf;
    @Nullable
    private SshCipher cipher;
    @Nullable
    private byte[] cipherIV;

    public DecryptPutty2()
            throws NoSuchAlgorithmException {
        pbkdf = new PBKDFPutty2();
    }

    @Override
    public void setCipher(@Nullable final SshCipher cipher,
                          @Nullable final byte[] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
    }

    @NonNull
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
            throws GeneralSecurityException {
        if (cipher == null || cipherIV == null) {
            throw new KeyException("Cipher/iv not set");
        }

        byte[] pbeKey = null;
        try {
            pbeKey = pbkdf.generateSecretKey(passphrase, 32);

            final byte[] plainKey = new byte[blob.length];
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
            cipher.doFinal(blob, 0, blob.length, plainKey, 0);
            return plainKey;
        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
            Arrays.fill(passphrase, (byte) 0);
        }
    }
}
