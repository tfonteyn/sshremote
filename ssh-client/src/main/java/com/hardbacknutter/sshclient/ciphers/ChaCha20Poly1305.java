package com.hardbacknutter.sshclient.ciphers;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.utils.Util;

import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20 Stream cipher performs the Encryption and Poly1305 performs the Authentication.
 * Poly1305 is a cryptographic Message Authentication Code (MAC).
 * <p>
 * The inputs to ChaCha20 are:
 * <ul>
 *     <li>A 256-bit key, treated as a concatenation of eight 32-bit little-endian integers.</li>
 *     <li> A 96-bit nonce, treated as a concatenation of three 32-bit little-endian integers.<br>
 *          (a.k.a. the Initialization vector (IV))</li>
 *     <li>A 32-bit block count parameter, treated as a 32-bit little-endian integer.</li>
 * </ul>
 * The output is 64 random-looking bytes.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8439">
 * RFC 8439 ChaCha20 and Poly1305 for IETF Protocols</a>, June 2018.
 * @see <a href="https://www.javainterviewpoint.com/chacha20-poly1305-encryption-and-decryption/">
 * javainterviewpoint</a>
 */
public class ChaCha20Poly1305
        implements SshCipher, ChaChaCipher {

    /** SecretKeySpec algorithm. */
    private static final String keyAlgorithm = "ChaCha20";

    /** Cipher algorithm (No, do NOT use "ChaCha20-Poly1305"). */
    private static final String algorithm = "ChaCha20";
    @NonNull
    private static final String mode = "None";
    // @NonNull
    // private static final String padding = "NoPadding";

    /**
     * <pre>
     *    Poly1305 takes a 32-byte one-time key and a message and produces a
     *    16-byte tag.  This tag is used to authenticate the message.
     * </pre>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8439#section-2.5">
     * RFC 8439 section 2.5 The Poly1305 Algorithm</a>
     */
    private static final int TAG_SIZE_IN_BYTES = 16;

    /**
     * <pre>
     *     A 96-bit nonce, treated as a concatenation of three 32-bit little-
     *     endian integers
     * </pre>
     *
     * @see #update(int)
     */
    private static final int ivSize = 12;

    // According to the openssh sources, it must be 8.
    private static final int blockSize = 8;

    /**
     * <pre>
     *     A 256-bit key, treated as a concatenation of eight 32-bit little-
     *     endian integers.
     * </pre>
     * The real key size is 256 bits; i.e. 32 bytes. HOWEVER....
     */
    private static final int keyLength = 32;
    /**
     * ... we need 2 x 256 bit keys, hence this value MUST be 64.
     */
    private static final int doubleKeyLength = 64;

    /**
     * The instance keyed by K_1 is a stream cipher that is used only to
     * encrypt the 4 byte packet length field.
     */
    private final Cipher k1_cipher;

    /**
     * The second instance, keyed by K_2,
     * is used in conjunction with poly1305 to build an AEAD
     * (Authenticated Encryption with Associated Data) that is used to
     * encrypt and authenticate the entire packet.
     */
    private final Cipher k2_cipher;
    private final Poly1305 poly1305;

    private SecretKeySpec k1_spec;
    private SecretKeySpec k2_spec;

    /** {@link Cipher#DECRYPT_MODE} or {@link Cipher#ENCRYPT_MODE} */
    private int opmode;

    public ChaCha20Poly1305()
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        k1_cipher = Cipher.getInstance(algorithm);
        k2_cipher = Cipher.getInstance(algorithm);
        poly1305 = new Poly1305();
    }

    @NonNull
    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @NonNull
    @Override
    public String getMode() {
        return mode;
    }

    @Override
    public int getKeySize() {
        // key size is 32, but we need 2 x 256 bit keys, hence this value MUST be 64.
        return doubleKeyLength;
    }

    @Override
    public int getBlockSize() {
        return blockSize;
    }

    @Override
    public int getIVSize() {
        return ivSize;
    }

    @Override
    public int getTagSizeInBytes() {
        return TAG_SIZE_IN_BYTES;
    }

    @Override
    public void init(final int opmode,
                     @NonNull final byte[] key,
                     @NonNull final byte[] iv) {

        this.opmode = opmode;

        // Make sure to limit the key length to the length the cipher wants.
        final byte[] normalisedKey;
        // key size is 32, but we need 2 x 256 bit keys, hence this value MUST be 64.
        if (key.length > doubleKeyLength) {
            normalisedKey = new byte[doubleKeyLength];
            System.arraycopy(key, 0, normalisedKey, 0, normalisedKey.length);
        } else {
            normalisedKey = key;
        }

        // use the second part of the 512 bits
        final byte[] K_1 = new byte[keyLength];
        System.arraycopy(normalisedKey, keyLength, K_1, 0, keyLength);
        k1_spec = new SecretKeySpec(K_1, keyAlgorithm);

        // use the first part of the 512 bits
        final byte[] K_2 = new byte[keyLength];
        System.arraycopy(normalisedKey, 0, K_2, 0, keyLength);
        k2_spec = new SecretKeySpec(K_2, keyAlgorithm);
    }

    @Override
    public void update(final int packetSeqNum)
            throws InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {

        // The IV is the packet sequence number.
        // It's encoded as an uint64 under the SSH wire encoding rules
        final ByteBuffer nonce = ByteBuffer.allocate(ivSize);
        nonce.putLong(4, packetSeqNum);

        // Using IvParameterSpec is allowed
        // or else (JDK 11+) use ChaCha20ParameterSpec with a ChaCha20 block counter of zero.
        // final AlgorithmParameterSpec params = new ChaCha20ParameterSpec(nonce.array(), 0);

        final AlgorithmParameterSpec paramK1 = new IvParameterSpec(nonce.array());
        // Prep the header cipher; The next call will be doing
        // {@code  k1_cipher.update(input, inputOffset, inputLen, output, outputOffset);}
        k1_cipher.init(opmode, k1_spec, paramK1);

        // Prep the main cipher
        final AlgorithmParameterSpec paramK2 = new IvParameterSpec(nonce.array());
        k2_cipher.init(opmode, k2_spec, paramK2);

        // Generate the Poly1305 key
        final byte[] polyKey = new byte[keyLength];
        k2_cipher.update(polyKey, 0, keyLength, polyKey, 0);

        poly1305.init(new KeyParameter(polyKey));

        // Trying to re-init the cipher again with same nonce results in InvalidKeyException
        // So we just read the entire first 64-byte block,
        // which should increment the global counter from 0->1
        final byte[] discard = new byte[keyLength];
        k2_cipher.update(discard, 0, keyLength, discard, 0);
    }

    // Will be called only to encrypt the 4 bytes for the packet length
    @Override
    public void update(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset)
            throws ShortBufferException {
        k1_cipher.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    public void updateAAD(@NonNull final byte[] src,
                          final int offset,
                          final int len) {
        // Should never be called for ChaCha20
        throw new IllegalStateException();
    }

    @Override
    public int doFinal(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset)
            throws ShortBufferException, AEADBadTagException {

        if (opmode == Cipher.DECRYPT_MODE) {
            // If decrypting, check tag before anything else
            final byte[] actualTag = new byte[TAG_SIZE_IN_BYTES];
            System.arraycopy(input, inputLen, actualTag, 0, TAG_SIZE_IN_BYTES);

            final byte[] expectedTag = new byte[TAG_SIZE_IN_BYTES];
            poly1305.update(input, inputOffset, inputLen);
            poly1305.doFinal(expectedTag, 0);

            if (!Util.arraysEquals(actualTag, expectedTag)) {
                throw new AEADBadTagException("Tag mismatch");
            }
        }

        // the 'input' block includes the 4 bytes length, so add to the offset,
        // and deduct from the length.
        final int nrOfBytes = k2_cipher
                .update(input, inputOffset + 4, inputLen - 4,
                        output, outputOffset + 4);

        if (opmode == Cipher.ENCRYPT_MODE) {
            // If encrypting, calculate and append tag
            poly1305.update(output, outputOffset, inputLen);
            poly1305.doFinal(output, inputLen);
        }

        return nrOfBytes;
    }

    @Override
    public boolean isMode(@NonNull final String _mode) {
        return mode.equalsIgnoreCase(_mode);
    }
}
