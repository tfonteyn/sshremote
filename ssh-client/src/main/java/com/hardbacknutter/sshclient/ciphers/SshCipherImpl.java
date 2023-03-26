package com.hardbacknutter.sshclient.ciphers;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The base for (nearly) all ciphers.
 *
 * @see SshCipher SshCipher class docs
 */
public class SshCipherImpl
        implements SshCipher {

    @NonNull
    final Cipher cipher;
    final int ivSize;
    @NonNull
    private final String algorithm;
    @NonNull
    private final String mode;
    @NonNull
    private final String padding;
    private final int keyLength;
    private final int blockSize;
    int opmode;

    @SuppressWarnings("FieldNotUsedInToString")
    SecretKeySpec secretKeySpec;

    /**
     * Constructor.
     *
     * @param algorithm for the cipher
     * @param mode      for the cipher
     * @param padding   for the cipher
     * @param keyLength The key size (in bytes) supported by the given algorithm/mode
     * @param blockSize The block size (in bytes) supported by the given algorithm/mode
     * @param ivSize    the size (in bytes) of the initial vector for the cipher
     */
    public SshCipherImpl(@NonNull final String algorithm,
                         @NonNull final String mode,
                         @NonNull final String padding,
                         final int keyLength,
                         final int blockSize,
                         final int ivSize)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
        this.keyLength = keyLength;
        this.blockSize = blockSize;
        this.ivSize = ivSize;

        final String transformation;
        if (this.mode.isEmpty()) {
            transformation = this.algorithm;
        } else {
            transformation = this.algorithm + "/" + this.mode + "/" + this.padding;
        }
        cipher = Cipher.getInstance(transformation);
    }

    @Override
    @NonNull
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    @NonNull
    public String getMode() {
        return mode;
    }

    @Override
    public int getKeySize() {
        return keyLength;
    }

    @Override
    public int getBlockSize() {
        return blockSize;
    }

    @Override
    public int getIVSize() {
        return ivSize;
    }

    @SuppressWarnings("OverlyBroadThrowsClause")
    @Override
    public void init(final int opmode,
                     @NonNull final byte[] key,
                     @NonNull final byte[] iv)
            throws GeneralSecurityException {

        // if the iv buffer is too large, it will automatically be shortened
        final AlgorithmParameterSpec params = new IvParameterSpec(iv, 0, ivSize);
        init(opmode, key, params);
    }

    void init(final int opmode,
              @NonNull final byte[] key,
              @NonNull final AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        this.opmode = opmode;

        // Make sure to limit the key length to the length the cipher wants.
        final byte[] keyBuf;
        if (key.length > keyLength) {
            keyBuf = new byte[keyLength];
            System.arraycopy(key, 0, keyBuf, 0, keyBuf.length);
        } else {
            keyBuf = key;
        }

        secretKeySpec = new SecretKeySpec(keyBuf, algorithm);
        cipher.init(opmode, secretKeySpec, params);
    }

    @Override
    public void update(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset)
            throws ShortBufferException {
        cipher.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    public void updateAAD(@NonNull final byte[] src,
                          final int offset,
                          final int len) {
        cipher.updateAAD(src, offset, len);
    }

    @SuppressWarnings("OverlyBroadThrowsClause")
    @Override
    public int doFinal(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset)
            throws GeneralSecurityException {
        return cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    public boolean isMode(@NonNull final String mode) {
        return this.mode.equalsIgnoreCase(mode);
    }

    @Override
    @NonNull
    public String toString() {
        return "BaseCipher{" +
                "algorithm='" + algorithm + '\'' +
                ", mode='" + mode + '\'' +
                ", padding='" + padding + '\'' +
                ", keyLength=" + keyLength +
                ", blockSize=" + blockSize +
                ", ivSize=" + ivSize +
                ", cipher=" + cipher.getAlgorithm() +
                ", opmode=" + opmode +
                '}';
    }
}
