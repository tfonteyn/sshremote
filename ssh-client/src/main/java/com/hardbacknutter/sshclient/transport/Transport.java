package com.hardbacknutter.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;
import javax.crypto.Cipher;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.AEADCipher;
import com.hardbacknutter.sshclient.ciphers.ChaChaCipher;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.kex.KexAgreement;
import com.hardbacknutter.sshclient.macs.SshMac;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

/**
 * Encapsulate a {@link SshCipher} and {@link SshMac} used for either
 * client to server, or server to client packet transport.
 */
public abstract class Transport {

    static final String ERROR_CIPHER_IS_NOT_SET = "cipher is not set";

    @NonNull
    final SshClientConfig config;

    private final int cipherMode;
    @Nullable
    protected SshCipher cipher;
    @Nullable
    protected SshMac mac;

    /** Sequence number of the packets. */
    int seq;

    /**
     * Constructor.
     *
     * @param cipherMode {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}.
     */
    Transport(@NonNull final Session session,
              final int cipherMode) {
        this.config = session.getConfig();
        this.cipherMode = cipherMode;
    }

    /**
     * Output from Key Exchange
     * If the key length needed is longer than the output of the HASH, the
     * key is extended by computing HASH of the concatenation of K and H and
     * the entire key so far, and appending the resulting bytes (as many as
     * HASH generates) to the key.  This process is repeated until enough
     * key material is available; the key is taken from the beginning of
     * this value.  In other words:
     * K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
     * K2 = HASH(K || H || K1)
     * K3 = HASH(K || H || K1 || K2)
     * ...
     * key = K1 || K2 || K3 || ...
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-7.2">
     * RFC 4253 SSH Transport Layer Protocol, section 7.2. Output from Key Exchange</a>
     */
    private static byte[] expandKey(@NonNull final MessageDigest md,
                                    @NonNull final byte[] K,
                                    @NonNull final byte[] H,
                                    @NonNull final byte[] key,
                                    final int requiredLength) {
        final Buffer buffer = new Buffer();
        byte[] result = key;

        while (result.length < requiredLength) {
            buffer.reset()
                  .putMPInt(K)
                  .putBytes(H)
                  .putBytes(result);
            md.update(buffer.data, 0, buffer.writeOffset);

            final byte[] hash = md.digest();

            final byte[] dest = new byte[result.length + hash.length];
            System.arraycopy(result, 0, dest, 0, result.length);
            System.arraycopy(hash, 0, dest, result.length, hash.length);

            Arrays.fill(result, (byte) 0);
            result = dest;
        }
        return result;
    }

    /**
     * Initialise cipher and MAC.
     */
    void initEncryption(@NonNull final KexAgreement agreement,
                        @NonNull final MessageDigest md,
                        @NonNull final byte[] K,
                        @NonNull final byte[] H,
                        @NonNull final byte[] encKey,
                        @NonNull final byte[] encIv,
                        @NonNull final byte[] macKey)
            throws GeneralSecurityException {

        cipher = ImplementationFactory.getCipher(config, agreement.getCipher(cipherMode));
        cipher.init(cipherMode, expandKey(md, K, H, encKey, cipher.getKeySize()), encIv);

        if (cipher instanceof AEADCipher) {
            mac = null;
        } else {
            mac = ImplementationFactory.getMac(config, agreement.getMac(cipherMode));
            mac.init(expandKey(md, K, H, macKey, mac.getDigestLength()));
        }
    }

    // force api
    abstract void initCompression(@NonNull final KexAgreement agreement,
                                  final boolean authenticated)
            throws IOException, NoSuchAlgorithmException;

    boolean isChaCha() {
        return cipher instanceof ChaChaCipher;
    }

    boolean isAEAD() {
        return cipher instanceof AEADCipher;
    }

    boolean isEtM() {
        return !(cipher instanceof AEADCipher) && mac != null && mac.isEtm();
    }

    public int getSeq() {
        return seq;
    }

    /**
     * Get the block size used by the cipher.
     *
     * @return block-size
     */
    @NonNull
    public Optional<Integer> getCipherBlockSize() {
        if (cipher == null) {
            return Optional.empty();
        }
        return Optional.of(cipher.getBlockSize());
    }

    /**
     * Get the block size used by the mac.
     *
     * @return block-size
     */
    @NonNull
    public Optional<Integer> getMacBlockSize() {
        if (cipher != null && isAEAD()) {
            return Optional.of(((AEADCipher) cipher).getTagSizeInBytes());
        } else if (mac != null) {
            return Optional.of(mac.getDigestLength());
        } else {
            return Optional.empty();
        }
    }
}
