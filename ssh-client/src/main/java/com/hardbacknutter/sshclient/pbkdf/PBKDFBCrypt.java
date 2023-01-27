package com.hardbacknutter.sshclient.pbkdf;

import androidx.annotation.NonNull;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * pkcs #5 pbkdf2 implementation using the "bcrypt" hash
 * <p>
 * The bcrypt hash function is derived from the bcrypt password hashing
 * function with the following modifications:
 * <ol>
 *     <li>The input password and salt are preprocessed with SHA512.</li>
 *     <li>The output length is expanded to 256 bits.</li>
 *     <li>Subsequently the magic string to be encrypted is lengthened and modified
 *     to "OxychromaticBlowfishSwatDynamite"</li>
 *     <li>The hash function is defined to perform 64 rounds of initial state
 *   expansion. (More rounds are performed by iterating the hash.)</li>
 * </ol>
 * Note that this implementation pulls the SHA512 operations into the caller
 * as a performance optimization.
 *
 * @see <a href="https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/bcrypt_pbkdf.c">
 * pkcs #5 pbkdf2 implementation using the "bcrypt" hash</a>
 */
@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDFBCrypt
        extends BCrypt
        implements PBKDF {

    /** OpenBSD IV: "OxychromaticBlowfishSwatDynamite" in big endian. */
    private static final int[] openbsd_iv = {
            0x4f787963, 0x68726f6d, 0x61746963, 0x426c6f77,
            0x66697368, 0x53776174, 0x44796e61, 0x6d697465,
    };
    @NonNull
    private byte[] salt;
    private int iterationCount;

    @SuppressWarnings("FieldNotUsedInToString")
    @NonNull
    private MessageDigest md;

    /**
     * Init..
     *
     * @param salt           the salt.
     * @param iterationCount the iteration count.
     */
    public PBKDFBCrypt init(@NonNull final byte[] salt,
                            final int iterationCount)
            throws NoSuchAlgorithmException {
        this.salt = salt;
        this.iterationCount = iterationCount;

        md = MessageDigest.getInstance("SHA-512");
        return this;
    }

    @Override
    @NonNull
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int keyLength)
            throws DigestException {
        final byte[] key = new byte[keyLength];
        pbkdf(passphrase, key);
        return key;
    }

    private void pbkdf(@NonNull final byte[] passphrase,
                       @NonNull final byte[] output)
            throws DigestException {

        final int nblocks = (output.length + 31) / 32;
        md.reset();
        final byte[] hpass = md.digest(passphrase);

        final byte[] hsalt = new byte[64];
        final byte[] block_b = new byte[4];
        final byte[] out = new byte[32];
        final byte[] tmp = new byte[32];
        for (int block = 1; block <= nblocks; block++) {
            // Block count is in big endian
            block_b[0] = (byte) ((block >> 24) & 0xFF);
            block_b[1] = (byte) ((block >> 16) & 0xFF);
            block_b[2] = (byte) ((block >> 8) & 0xFF);
            block_b[3] = (byte) (block & 0xFF);

            md.reset();
            md.update(salt);
            md.update(block_b);
            md.digest(hsalt, 0, hsalt.length);

            hash(hpass, hsalt, out);
            System.arraycopy(out, 0, tmp, 0, out.length);

            for (int round = 1; round < iterationCount; round++) {
                md.reset();
                md.update(tmp);
                md.digest(hsalt, 0, hsalt.length);
                hash(hpass, hsalt, tmp);

                for (int i = 0; i < tmp.length; i++) {
                    out[i] ^= tmp[i];
                }
            }

            for (int i = 0; i < out.length; i++) {
                final int idx = i * nblocks + (block - 1);
                if (idx < output.length) {
                    output[idx] = out[i];
                }
            }
        }
    }

    private void hash(@NonNull final byte[] hpass,
                      @NonNull final byte[] hsalt,
                      @NonNull final byte[] output) {
        init_key();
        ekskey(hsalt, hpass);
        for (int i = 0; i < 64; i++) {
            key(hsalt);
            key(hpass);
        }

        final int[] buf = new int[openbsd_iv.length];
        System.arraycopy(openbsd_iv, 0, buf, 0, openbsd_iv.length);
        for (int i = 0; i < 8; i += 2) {
            for (int j = 0; j < 64; j++) {
                encipher(buf, i);
            }
        }

        for (int i = 0, j = 0; i < buf.length; i++) {
            // Output of this is little endian
            output[j++] = (byte) (buf[i] & 0xff);
            output[j++] = (byte) ((buf[i] >> 8) & 0xff);
            output[j++] = (byte) ((buf[i] >> 16) & 0xff);
            output[j++] = (byte) ((buf[i] >> 24) & 0xff);
        }
    }

    @Override
    public String toString() {
        return "PBKDFBCrypt{"
                + "salt=" + Arrays.toString(salt)
                + ", iterations=" + iterationCount
                + '}';
    }
}
