package com.hardbackcollector.sshclient.ciphers;

import androidx.annotation.NonNull;

/**
 * An implementation of the Cipher {@code none}, i.e. unencrypted transport.
 * This is used during key-exchange until the first real Cipher can be used.
 *
 * <blockquote>
 * The "none" algorithm specifies that no encryption is to be done.
 * Note that this method provides no confidentiality protection, and it
 * is NOT RECOMMENDED.  Some functionality (e.g., password
 * authentication) may be disabled for security reasons if this cipher
 * is chosen.
 * </blockquote>
 * <p>
 * The implementation here consists mainly of no-ops.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.3">
 * RFC 4253 SSH Transport Layer Protocol, section 6.3. Encryption</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2410">
 * RFC 2410 The NULL Encryption Algorithm and Its Use With IPsec</a>
 */
public class NullCipher
        implements SshCipher {

    /**
     * @return 0
     */
    @Override
    public int getKeySize() {
        return 0;
    }

    /**
     * @return 1
     */
    @Override
    public int getBlockSize() {
        return 1;
    }

    /**
     * @return 0
     */
    @Override
    public int getIVSize() {
        return 0;
    }


    @Override
    public void init(final int opmode,
                     @NonNull final byte[] keyBuf,
                     @NonNull final byte[] iv) {
    }

    @Override
    public void update(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset) {
        System.arraycopy(input, inputOffset, output, outputOffset, inputLen);
    }

    @Override
    public void updateAAD(@NonNull final byte[] src,
                          final int offset,
                          final int len) {

    }

    @Override
    public int doFinal(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset) {
        return 0;
    }

    @Override
    public boolean isMode(@NonNull final String mode) {
        return false;
    }

    @NonNull
    @Override
    public String getAlgorithm() {
        return "";
    }

    @NonNull
    @Override
    public String getMode() {
        return "";
    }
}
