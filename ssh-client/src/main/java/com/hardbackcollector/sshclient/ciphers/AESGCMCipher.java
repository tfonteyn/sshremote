package com.hardbackcollector.sshclient.ciphers;

import androidx.annotation.NonNull;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5647">
 * RFC 5647 AES Galois Counter Mode for the Secure Shell Transport Layer Protocol</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5288">
 * RFC 5288 AES Galois Counter Mode (GCM) Cipher Suites</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6239">
 * RFC 6239 Suite B Cryptographic Suites for Secure Shell</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5116">
 * RFC 5116  An Interface and Algorithms for Authenticated Encryption</a>
 */
public class AESGCMCipher
        extends SshCipherImpl
        implements AEADCipher {

    /**
     * Authentication strength parameter (e.g., authentication tag length)
     *
     * <pre>
     *    Both AEAD_AES_128_GCM and AEAD_AES_256_GCM produce a 16-octet
     *    Authentication Tag
     * </pre>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc5647#section-6.3">
     * RFC 5647, section 6.3 Size of the Authentication Tag</a>
     */
    private static final int TAG_SIZE_IN_BYTES = 16;
    private static final int TAG_SIZE_IN_BITS = 128;

    private ByteBuffer ivBuffer;
    private long initialCounter;

    /**
     * @param algorithm for the cipher
     * @param mode      for the cipher
     * @param padding   for the cipher
     * @param blockSize The block size (in bytes) supported by the given algorithm/mode
     * @param keyLength The key size (in bytes) supported by the given algorithm/mode
     * @param ivSize    the size (in bytes) of the initial vector for the cipher
     */
    public AESGCMCipher(@NonNull final String algorithm,
                        @NonNull final String mode,
                        @NonNull final String padding,
                        final int blockSize,
                        final int keyLength,
                        final int ivSize)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        super(algorithm, mode, padding, keyLength, blockSize, ivSize);
    }

    @Override
    public void init(final int opmode,
                     @NonNull final byte[] key,
                     @NonNull final byte[] iv)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        this.ivBuffer = ByteBuffer.wrap(iv);
        this.initialCounter = this.ivBuffer.getLong(4);

        super.init(opmode, key,
                   new GCMParameterSpec(TAG_SIZE_IN_BITS, ivBuffer.array(), 0, ivSize));
    }

    @Override
    public int getTagSizeInBytes() {
        return TAG_SIZE_IN_BYTES;
    }

    @Override
    public int doFinal(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset)
            throws GeneralSecurityException {

        final int nrOfBytes = super.doFinal(input, inputOffset, inputLen, output, outputOffset);

        // Update the counter
        final long newCounter = ivBuffer.getLong(4) + 1;
        if (newCounter == initialCounter) {
            throw new IllegalStateException("GCM IV cannot be reused");
        }
        ivBuffer.putLong(4, newCounter);

        // and re-init with the new counter
        cipher.init(opmode, secretKeySpec,
                    new GCMParameterSpec(TAG_SIZE_IN_BITS, ivBuffer.array(), 0, ivSize));

        return nrOfBytes;
    }
}
