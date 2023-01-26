package com.hardbacknutter.sshclient.pbkdf;

import androidx.annotation.NonNull;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.KeyException;
import java.util.Arrays;

@SuppressWarnings("FieldCanBeLocal")
public class PBKDFArgon2
        implements PBKDF2 {

    private final int flavour;
    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final byte[] salt;

    @SuppressWarnings("FieldNotUsedInToString")
    @NonNull
    private final Argon2BytesGenerator generator;

    public PBKDFArgon2(@NonNull final String keyDerivation,
                       @NonNull final String memoryAsKB,
                       @NonNull final String iterations,
                       @NonNull final String parallelism,
                       @NonNull final String salt,
                       @NonNull final byte[] secret,
                       @NonNull final byte[] Additional)
            throws KeyException {
        switch (keyDerivation) {
            case "Argon2d":
                flavour = Argon2Parameters.ARGON2_d;
                break;
            case "Argon2i":
                flavour = Argon2Parameters.ARGON2_i;
                break;
            case "Argon2id":
                flavour = Argon2Parameters.ARGON2_id;
                break;
            default:
                throw new KeyException("Invalid Key-Derivation: " + keyDerivation);
        }
        try {
            this.memory = Integer.parseInt(memoryAsKB);
            this.iterations = Integer.parseInt(iterations);
            this.parallelism = Integer.parseInt(parallelism);
            this.salt = new byte[salt.length() / 2];
            for (int i = 0; i < this.salt.length; i++) {
                final int j = i * 2;
                this.salt[i] = (byte) Integer.parseInt(salt.substring(j, j + 2), 16);
            }
        } catch (@NonNull final NumberFormatException e) {
            throw new KeyException(e);
        }

        final Argon2Parameters parameters = new Argon2Parameters.Builder(flavour)
                .withMemoryAsKB(this.memory)
                .withIterations(this.iterations)
                .withParallelism(this.parallelism)
                .withSalt(this.salt)
                .withSecret(secret)
                .withAdditional(Additional)
                .build();

        generator = new Argon2BytesGenerator();
        generator.init(parameters);
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
                + "flavour=" + flavour
                + ", memory=" + memory
                + ", iterations=" + iterations
                + ", parallelism=" + parallelism
                + ", salt=" + Arrays.toString(salt)
                + '}';
    }
}
