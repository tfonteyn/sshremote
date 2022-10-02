package com.hardbacknutter.sshclient.ciphers;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.ShortBufferException;

/**
 * A cipher object encapsulates an encryption/decryption algorithm.
 * The Cipher implementations used by the library can be selected using configuration options.
 * <p>
 * From RFC 4253
 * <pre>
 *       3des-cbc         REQUIRED          three-key 3DES in CBC mode
 *       blowfish-cbc     OPTIONAL          Blowfish in CBC mode
 *       twofish256-cbc   OPTIONAL          Twofish in CBC mode, with a 256-bit key
 *       twofish-cbc      OPTIONAL          alias for "twofish256-cbc"
 *                                          (this is being retained for historical reasons)
 *       twofish192-cbc   OPTIONAL          Twofish with a 192-bit key
 *       twofish128-cbc   OPTIONAL          Twofish with a 128-bit key
 *       aes256-cbc       OPTIONAL          AES in CBC mode, with a 256-bit key
 *       aes192-cbc       OPTIONAL          AES with a 192-bit key
 *       aes128-cbc       RECOMMENDED       AES with a 128-bit key
 *       serpent256-cbc   OPTIONAL          Serpent in CBC mode, with a 256-bit key
 *       serpent192-cbc   OPTIONAL          Serpent with a 192-bit key
 *       serpent128-cbc   OPTIONAL          Serpent with a 128-bit key
 *       arcfour          OPTIONAL          the ARCFOUR stream cipher with a 128-bit key
 *       idea-cbc         OPTIONAL          IDEA in CBC mode
 *       cast128-cbc      OPTIONAL          CAST-128 in CBC mode
 *       none             OPTIONAL          no encryption; NOT RECOMMENDED
 * </pre>
 * From RFC 4344:
 * <pre>
 *      aes128-ctr       RECOMMENDED       AES (Rijndael) in SDCTR mode, with 128-bit key
 *      aes192-ctr       RECOMMENDED       AES with 192-bit key
 *      aes256-ctr       RECOMMENDED       AES with 256-bit key
 *      3des-ctr         RECOMMENDED       Three-key 3DES in SDCTR mode
 *      blowfish-ctr     OPTIONAL          Blowfish in SDCTR mode
 *      twofish128-ctr   OPTIONAL          Twofish in SDCTR mode, with 128-bit key
 *      twofish192-ctr   OPTIONAL          Twofish with 192-bit key
 *      twofish256-ctr   OPTIONAL          Twofish with 256-bit key
 *      serpent128-ctr   OPTIONAL          Serpent in SDCTR mode, with 128-bit key
 *      serpent192-ctr   OPTIONAL          Serpent with 192-bit key
 *      serpent256-ctr   OPTIONAL          Serpent with 256-bit key
 *      idea-ctr         OPTIONAL          IDEA in SDCTR mode
 *      cast128-ctr      OPTIONAL          CAST-128 in SDCTR mode, with 128-bit key
 * </pre>
 * <p>
 * Current OpenSSH versions (2021) support:
 * <pre>
 *      3des-cbc
 *      aes128-cbc
 *      aes192-cbc
 *      aes256-cbc
 *      aes128-ctr
 *      aes192-ctr
 *      aes256-ctr
 *      aes128-gcm@openssh.com
 *      aes256-gcm@openssh.com
 *      chacha20-poly1305@openssh.com
 * </pre>
 * The OpenSSH server default is:
 * <pre>
 *      chacha20-poly1305@openssh.com,
 *      aes128-ctr,aes192-ctr,aes256-ctr,
 *      aes128-gcm@openssh.com,aes256-gcm@openssh.com
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4344#section-4>
 * RFC 4344 SSH Transport Layer Encryption Modes, section 4. Encryption Modes</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.3">
 * RFC 4253 SSH Transport Layer Protocol, section 6.3. Encryption</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4344#section-4">
 * RFC 4344 SSH Transport Layer, section 4. Encryption Modes</a>
 * @see <a href="https://man.openbsd.org/sshd_config#Ciphers">
 * OpenSSH supported Ciphers</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8758">
 * Deprecating RC4</a>
 * @see <a href="https://github.com/openssh/openssh-portable/blob/master/cipher.c">
 * openssh cipher.c, struct sshcipher and defined types</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2144">
 * RFC 2144 The CAST-128 Encryption Algorithm</a>
 */
public interface SshCipher {

    @NonNull
    String getAlgorithm();

    @NonNull
    String getMode();

    /**
     * Returns the key size (in bytes) of the algorithm.
     */
    int getKeySize();

    /**
     * Returns the block size (in bytes) of the algorithm.
     */
    int getBlockSize();

    /**
     * Returns the size (in bytes) of the initialization vector for this cipher.
     */
    int getIVSize();

    /**
     * Initializes the Cipher object for a new encryption
     * or decryption operation.
     *
     * @param opmode one of {@link javax.crypto.Cipher#ENCRYPT_MODE}
     *               or {@link  javax.crypto.Cipher#DECRYPT_MODE}.
     * @param key    the key to use for the operation.
     * @param iv     the initialization vector necessary for operation.
     *
     * @throws InvalidKeyException  if the given key is inappropriate for
     *                              initializing this cipher, or its key size exceeds
     *                              the maximum allowable key size (as determined from
     *                              the configured jurisdiction policy files).
     * @throws ShortBufferException when an output buffer provided by the user is too
     *                              short to hold the operation result.
     */
    void init(int opmode,
              @NonNull byte[] key,
              @NonNull byte[] iv)
            throws GeneralSecurityException;

    /**
     * Encrypts or decrypts some more data.
     *
     * @param input        the array from which the plaintext (for encrypting) or
     *                     ciphertext (for decrypting) should be taken.
     * @param inputOffset  the position in {@code input} at which the data is
     *                     to be found.
     * @param inputLen     the length of the input in bytes. The same number of output
     *                     bytes will be produced.
     * @param output       the array into which the ciphertext (for encrypting) or
     *                     plaintext (for decrypting) will be written.
     * @param outputOffset the position in {@code output} from which on the data
     *                     should be written.
     */
    void update(@NonNull byte[] input,
                int inputOffset,
                int inputLen,
                @NonNull byte[] output,
                int outputOffset)
            throws GeneralSecurityException;

    /**
     * Continues a multi-part update of the Additional Authentication
     * Data (AAD), using a subset of the provided buffer.
     *
     * @param src    the buffer containing the AAD
     * @param offset the offset in {@code src} where the AAD input starts
     * @param len    the number of AAD bytes
     */
    void updateAAD(@NonNull byte[] src,
                   int offset,
                   int len)
            throws GeneralSecurityException;

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     *
     * @param input        the input buffer
     * @param inputOffset  the offset in {@code input} where the input starts
     * @param inputLen     the input length
     * @param output       the buffer for the result
     * @param outputOffset the offset in {@code output} where the result is stored
     *
     * @return the number of bytes stored in {@code output}
     */
    int doFinal(@NonNull byte[] input,
                int inputOffset,
                int inputLen,
                @NonNull byte[] output,
                int outputOffset)
            throws GeneralSecurityException;

    /**
     * Checks whether this cipher is using the given mode.
     *
     * @param mode to check
     *
     * @return {@code true} if this cipher is in the given mode,
     * {@code false} if this cipher is in some other mode.
     */
    boolean isMode(@NonNull String mode);
}
