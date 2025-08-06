package com.hardbacknutter.sshclient.keypair.pbkdf;

import org.jspecify.annotations.NonNull;

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
    public PBKDFSCrypt init(final byte @NonNull [] salt,
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
                          final byte @NonNull [] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
    }

    public byte @NonNull [] generateSecretKey(final byte @NonNull [] passphrase,
                                    final int keyLength) {
        return SCrypt.generate(passphrase, salt, cost, blockSize, parallel, keyLength);
    }

        @Override
    public byte @NonNull [] decrypt(final byte @NonNull [] passphrase,
                          final byte @NonNull [] blob)
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
