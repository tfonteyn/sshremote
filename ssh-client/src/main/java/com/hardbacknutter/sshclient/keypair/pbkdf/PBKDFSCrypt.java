package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import org.bouncycastle.crypto.generators.SCrypt;

import java.security.GeneralSecurityException;

/**
 * <a href="https://www.rfc-editor.org/rfc/rfc7914.html">
 * rfc7914 The scrypt Password-Based Key Derivation Function</a>
 */
@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDFSCrypt
        implements PBKDF {

    @NonNull
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

    @NonNull
    @Override
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int keyLength)
            throws GeneralSecurityException {

        return SCrypt.generate(passphrase, salt, cost, blockSize, parallel, keyLength);
    }
}
