package com.hardbacknutter.sshclient.ciphers;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 * <a href="https://www.rfc-editor.org/rfc/rfc4345">RFC 4345 Improved Arcfour Modes</a>
 */
public class RC4Cipher
        extends SshCipherImpl {

    private final int discard;

    /**
     * Constructor.
     *
     * @param algorithm for the cipher
     * @param mode      for the cipher
     * @param padding   for the cipher
     * @param keyLength The key size (in bytes) supported by the given algorithm/mode
     * @param blockSize The block size (in bytes) supported by the given algorithm/mode
     * @param ivSize    the size (in bytes) of the initial vector for the cipher
     * @param discard   {@code 0} for plain RC4; {@code 1536} for arcfour128 and arcfour256
     */
    public RC4Cipher(@NonNull final String algorithm,
                     @NonNull final String mode,
                     @NonNull final String padding,
                     final int keyLength,
                     final int blockSize,
                     final int ivSize,
                     final int discard)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(algorithm, mode, padding, keyLength, blockSize, ivSize);
        this.discard = discard;
    }

    @Override
    public void init(final int opmode,
                     @NonNull final byte[] key,
                     @NonNull final byte[] iv)
            throws GeneralSecurityException {
        super.init(opmode, key, iv);

        if (discard > 0) {
            final byte[] tmp = new byte[1];
            for (int i = 0; i < discard; i++) {
                cipher.update(tmp, 0, 1, tmp, 0);
            }
        }
    }
}
