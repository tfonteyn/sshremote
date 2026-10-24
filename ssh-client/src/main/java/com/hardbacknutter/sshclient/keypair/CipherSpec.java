package com.hardbacknutter.sshclient.keypair;

import java.security.NoSuchAlgorithmException;

import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public final class CipherSpec {
    private static final @Nullable String ERROR_ALGORITHM_NOT_FOUND = "Algorithm not found: ";
    @NonNull
    private final String transformation;
    private final int keySize;
    private final int ivSize;

    private CipherSpec(@NonNull final String transformation,
                       final int keySize,
                       final int ivSize) {
        this.transformation = transformation;
        this.keySize = keySize;
        this.ivSize = ivSize;
    }

    /**
     * Transform the given ssh cipher name to a JCE transformation.
     *
     * @param algorithm ssh cipher name
     *
     * @return CipherSpec with transformation, keySize and IVsize.
     *
     * @throws NoSuchAlgorithmException if none found
     */
    @NonNull
    public static CipherSpec parseCipherSpec(@Nullable final String algorithm)
            throws NoSuchAlgorithmException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("No algorithm name given");
        }

        switch (algorithm) {
            case SshCipherConstants.CHACHA20_POLY1305_OPENSSH_COM:
                return new CipherSpec("ChaCha20-Poly1305", 32, 12);

            case SshCipherConstants.AES_256_GCM_OPENSSH_COM:
                return new CipherSpec("AES/GCM/NoPadding", 32, 12);
            case SshCipherConstants.AES_128_GCM_OPENSSH_COM:
                return new CipherSpec("AES/GCM/NoPadding", 16, 12);

            case SshCipherConstants.AES_256_CBC:
                return new CipherSpec("AES/CBC/NoPadding", 32, 16);
            case SshCipherConstants.AES_192_CBC:
                return new CipherSpec("AES/CBC/NoPadding", 24, 16);
            case SshCipherConstants.AES_128_CBC:
                return new CipherSpec("AES/CBC/NoPadding", 16, 16);

            case SshCipherConstants.AES_256_CTR:
                return new CipherSpec("AES/CTR/NoPadding", 32, 16);
            case SshCipherConstants.AES_192_CTR:
                return new CipherSpec("AES/CTR/NoPadding", 24, 16);
            case SshCipherConstants.AES_128_CTR:
                return new CipherSpec("AES/CTR/NoPadding", 16, 16);

            case SshCipherConstants.TWOFISH_CBC:
            case SshCipherConstants.TWOFISH_256_CBC:
                return new CipherSpec("Twofish/CBC/NoPadding", 32, 16);
            case SshCipherConstants.TWOFISH_192_CBC:
                return new CipherSpec("Twofish/CBC/NoPadding", 24, 16);
            case SshCipherConstants.TWOFISH_128_CBC:
                return new CipherSpec("Twofish/CBC/NoPadding", 16, 16);

            case SshCipherConstants.TWOFISH_256_CTR:
                return new CipherSpec("Twofish/CTR/NoPadding", 32, 16);
            case SshCipherConstants.TWOFISH_192_CTR:
                return new CipherSpec("Twofish/CTR/NoPadding", 24, 16);
            case SshCipherConstants.TWOFISH_128_CTR:
                return new CipherSpec("Twofish/CTR/NoPadding", 16, 16);

            case SshCipherConstants.TRIPLE_DES_CBC:
                return new CipherSpec("DESede/CBC/NoPadding", 24, 8);
            case SshCipherConstants.TRIPLE_DES_CTR:
                return new CipherSpec("DESede/CTR/NoPadding", 24, 8);

            case SshCipherConstants.SEED_CBC_SSH_COM:
                return new CipherSpec("SEED/CBC/NoPadding", 16, 16);

            case SshCipherConstants.CAST_128_CBC:
                return new CipherSpec("CAST5/CBC/NoPadding", 16, 8);
            case SshCipherConstants.CAST_128_CTR:
                return new CipherSpec("CAST5/CTR/NoPadding", 16, 8);

            case SshCipherConstants.BLOWFISH_CBC:
                return new CipherSpec("Blowfish/CBC/NoPadding", 16, 8);
            case SshCipherConstants.BLOWFISH_CTR:
                return new CipherSpec("Blowfish/CTR/NoPadding", 32, 8);

            case SshCipherConstants.AR_C_FOUR:
                return new CipherSpec("RC4", 16, 0);
            case SshCipherConstants.AR_C_FOUR_128:
                return new CipherSpec("RC4", 16, 0);
            case SshCipherConstants.AR_C_FOUR_256:
                return new CipherSpec("RC4", 32, 0);

            default:
                throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm);
        }
    }

    @NonNull
    public String getTransformation() {
        return transformation;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getIvSize() {
        return ivSize;
    }
}
