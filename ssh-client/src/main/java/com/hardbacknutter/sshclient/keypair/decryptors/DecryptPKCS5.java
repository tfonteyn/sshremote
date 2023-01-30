package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF1;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;

@SuppressWarnings("NotNullFieldNotInitialized")
public class DecryptPKCS5 implements PKDecryptor {

    @NonNull
    private PBKDF pbkdf;

    @Nullable
    private SshCipher cipher;
    @Nullable
    private byte[] cipherIV;

    public DecryptPKCS5 init(@NonNull final String algorithm,
                             @NonNull final byte[] salt)
            throws NoSuchAlgorithmException {
        pbkdf = new PBKDF1().init(algorithm, salt);
        return this;
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
            pbeKey = pbkdf.generateSecretKey(passphrase, cipher.getKeySize());

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
