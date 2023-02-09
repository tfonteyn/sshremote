package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

import org.bouncycastle.crypto.generators.SCrypt;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * <a href="https://www.rfc-editor.org/rfc/rfc7914.html">
 * rfc7914 The scrypt Password-Based Key Derivation Function</a>
 */
public class PBKDFSCrypt implements PBKDF {

    private SshCipher cipher;
    private byte[] cipherIV;

    private byte[] salt;
    private int cost;
    private int blockSize;
    private int parallel;

    /**
     * @param salt      the salt to use for this invocation.
     * @param cost      CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than
     *                  {@code 2^(128 * r / 8)}.
     * @param blockSize the block size, must be &gt;= 1.
     * @param parallel  Parallelization parameter. Must be a positive integer less than or equal to
     *                  {@code Integer.MAX_VALUE / (128 * r * 8)}.
     */
    public PBKDFSCrypt init(@NonNull final byte[] salt,
                            final int cost,
                            final int blockSize,
                            final int parallel) {
        this.salt = salt;
        this.cost = cost;
        this.blockSize = blockSize;
        this.parallel = parallel;
        return this;
    }

    @Override
    public void setCipher(@NonNull final SshCipher cipher,
                          @NonNull final byte[] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
    }

    @NonNull
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int keyLength) {
        return SCrypt.generate(passphrase, salt, cost, blockSize, parallel, keyLength);
    }

    @NonNull
    @Override
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
            throws GeneralSecurityException, IOException {
        byte[] pbeKey = null;
        final byte[] plainKey = new byte[blob.length];
        try {
            pbeKey = generateSecretKey(passphrase, cipher.getKeySize());

            cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
            cipher.doFinal(blob, 0, blob.length, plainKey, 0);

        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
        }
        return plainKey;
    }
}
