package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.pbkdf.PBKDF2Argon;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;

public class DecryptPutty3 implements PKDecryptor {

    private static final byte[] Z_BYTE_ARRAY = new byte[0];

    private final int macLength;
    @Nullable
    private final PBKDF pbkdf;
    @Nullable
    private SshCipher cipher;
    @Nullable
    private byte[] cipherIV;

    public DecryptPutty3(@NonNull final String keyDerivation,
                         @NonNull final String memoryAsKB,
                         @NonNull final String iterations,
                         @NonNull final String parallelism,
                         @NonNull final String salt,
                         final int macLength)
            throws KeyException {

        this.macLength = macLength;

        pbkdf = new PBKDF2Argon()
                .init(keyDerivation, salt, iterations,
                      memoryAsKB, parallelism,
                      //  a secret key, and some ‘associated data’.
                      //  In PPK's use of Argon2, these are both set
                      //  to the empty string.
                      Z_BYTE_ARRAY, Z_BYTE_ARRAY);
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
        Objects.requireNonNull(pbkdf, "PUTTY3 encrypted but no pbkdf?");

        byte[] pbeKey = null;
        try {
            // from the Putty docs:
            // encryption-type is ‘aes256-cbc’, then the symmetric cipher key
            // is 32 bytes long, and the initialisation vector is 16 bytes
            // (one cipher block).
            // The length of the MAC key is also chosen to be 32 bytes.

            byte[] tmp = new byte[cipher.getKeySize() + cipher.getIVSize() + macLength];
            // The output data is interpreted as the concatenation of the cipher key,
            // the IV and the MAC key, in that order.
            tmp = pbkdf.generateSecretKey(passphrase, tmp.length);

            pbeKey = new byte[cipher.getKeySize()];
            System.arraycopy(tmp, 0, pbeKey, 0, cipher.getKeySize());
            System.arraycopy(tmp, cipher.getKeySize(), cipherIV, 0, cipherIV.length);

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
