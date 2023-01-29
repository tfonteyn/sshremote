package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFArgon2;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.util.Arrays;

import javax.crypto.Cipher;


@SuppressWarnings("NotNullFieldNotInitialized")
public class DecryptPutty3 implements PKDecryptor {

    private static final byte[] Z_BYTE_ARRAY = new byte[0];

    private int macLength;
    @NonNull
    private PBKDF pbkdf;
    @Nullable
    private SshCipher cipher;
    @Nullable
    private byte[] cipherIV;

    public DecryptPutty3 init(@NonNull final String keyDerivation,
                              @NonNull final String memoryAsKB,
                              @NonNull final String iterationCount,
                              @NonNull final String parallelism,
                              @NonNull final String salt,
                              final int macLength)
            throws KeyException {

        this.macLength = macLength;

        pbkdf = new PBKDFArgon2()
                .init(keyDerivation, salt, iterationCount,
                      memoryAsKB, parallelism,
                      //  a secret key, and some ‘associated data’.
                      //  In PPK's use of Argon2, these are both set
                      //  to the empty string.
                      Z_BYTE_ARRAY, Z_BYTE_ARRAY);

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
