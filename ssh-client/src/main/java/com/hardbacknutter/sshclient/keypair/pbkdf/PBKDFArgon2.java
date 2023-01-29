package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.KeyException;
import java.util.Arrays;

@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDFArgon2
        implements PBKDF {

    private int type;
    private int memory;
    private int iterationCount;
    private int parallelism;
    @NonNull
    private byte[] salt;

    @SuppressWarnings("FieldNotUsedInToString")
    @NonNull
    private Argon2BytesGenerator generator;

    /**
     * Init.
     *
     * @param type           String for the Argon2 key derivation type.
     *                       One of "Argon2d", "Argon2i" or "Argon2id".
     * @param salt           the salt.
     * @param iterationCount the iteration count.
     */
    public PBKDFArgon2 init(@NonNull final String type,
                            @NonNull final String salt,
                            @NonNull final String iterationCount,
                            @NonNull final String memoryAsKB,
                            @NonNull final String parallelism,
                            @NonNull final byte[] secret,
                            @NonNull final byte[] Additional)
            throws KeyException {
        switch (type) {
            case "Argon2d":
                this.type = Argon2Parameters.ARGON2_d;
                break;
            case "Argon2i":
                this.type = Argon2Parameters.ARGON2_i;
                break;
            case "Argon2id":
                this.type = Argon2Parameters.ARGON2_id;
                break;
            default:
                throw new KeyException("Invalid Key-Derivation: " + type);
        }
        try {
            this.memory = Integer.parseInt(memoryAsKB);
            this.iterationCount = Integer.parseInt(iterationCount);
            this.parallelism = Integer.parseInt(parallelism);
            this.salt = new byte[salt.length() / 2];
            for (int i = 0; i < this.salt.length; i++) {
                final int j = i * 2;
                this.salt[i] = (byte) Integer.parseInt(salt.substring(j, j + 2), 16);
            }
        } catch (@NonNull final NumberFormatException e) {
            throw new KeyException(e);
        }

        final Argon2Parameters parameters = new Argon2Parameters.Builder(this.type)
                .withMemoryAsKB(this.memory)
                .withIterations(this.iterationCount)
                .withParallelism(this.parallelism)
                .withSalt(this.salt)
                .withSecret(secret)
                .withAdditional(Additional)
                .build();

        generator = new Argon2BytesGenerator();
        generator.init(parameters);

        return this;
    }

    @NonNull
    @Override
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int keyLength) {

        final byte[] key = new byte[keyLength];
        generator.generateBytes(passphrase, key);
        return key;
    }

    @Override
    public String toString() {
        return "PBKDFArgon2{"
                + "type=" + type
                + ", memory=" + memory
                + ", iterations=" + iterationCount
                + ", parallelism=" + parallelism
                + ", salt=" + Arrays.toString(salt)
                + '}';
    }
}
