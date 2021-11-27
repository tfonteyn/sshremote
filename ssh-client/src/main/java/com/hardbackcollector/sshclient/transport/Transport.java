package com.hardbackcollector.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.ciphers.AEADCipher;
import com.hardbackcollector.sshclient.ciphers.ChaChaCipher;
import com.hardbackcollector.sshclient.ciphers.SshCipher;
import com.hardbackcollector.sshclient.kex.KexAgreement;
import com.hardbackcollector.sshclient.macs.SshMac;
import com.hardbackcollector.sshclient.utils.Buffer;
import com.hardbackcollector.sshclient.utils.ImplementationFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Encapsulate a {@link SshCipher} and {@link SshMac} used for either
 * client to server, or server to client packet transport.
 */
public abstract class Transport {

    static final String ERROR_CIPHER_IS_NOT_SET = "cipher is not set";

    @NonNull
    protected final SshClientConfig config;
    private final int cipherMode;
    @Nullable
    public SshCipher cipher;
    @Nullable
    public SshMac mac;

    private boolean isChaCha;
    private boolean isAEAD;
    private boolean isEtM;

    public Transport(@NonNull final SshClientConfig config,
                     final int cipherMode) {
        this.config = config;
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
    public void initEncryption(@NonNull final KexAgreement agreement,
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

        isChaCha = cipher instanceof ChaChaCipher;
        isAEAD = cipher instanceof AEADCipher;
        isEtM = mac != null && mac.isEtm() && !(cipher instanceof AEADCipher);
    }

    abstract void initCompression(@NonNull final KexAgreement agreement,
                                  final boolean authenticated)
            throws IOException, NoSuchAlgorithmException;

    boolean isChaCha() {
        return isChaCha;
    }

    boolean isAEAD() {
        return isAEAD;
    }

    boolean isEtM() {
        return isEtM;
    }
}
