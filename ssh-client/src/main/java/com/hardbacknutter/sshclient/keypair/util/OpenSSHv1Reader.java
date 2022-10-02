package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.KeyPairOpenSSHv1;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class OpenSSHv1Reader {

    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.UTF_8);

    @NonNull
    private final SshClientConfig config;
    @NonNull
    private final KeyPairOpenSSHv1.Builder keyPairBuilder;

    /**
     * Constructor.
     */
    OpenSSHv1Reader(@NonNull final SshClientConfig config,
                    @NonNull final KeyPairOpenSSHv1.Builder keyPairBuilder) {
        this.config = config;
        this.keyPairBuilder = keyPairBuilder;
    }

    static boolean isOpenSSHv1(@NonNull final byte[] blob) {
        return Arrays.equals(AUTH_MAGIC, Arrays.copyOfRange(blob, 0, AUTH_MAGIC.length));
    }

    /**
     * reads openssh key v1 format and returns key type.
     */
    @NonNull
    public static String getHostKeyType(@NonNull final byte[] blob)
            throws IOException, InvalidKeyException {

        if (blob.length % 8 != 0) {
            throw new IOException("The private key must be a multiple of the block size (8)");
        }

        final Buffer buffer = new Buffer(blob);
        // 64-bit dummy checksum  # a random 32-bit int, repeated
        final int checkInt1 = buffer.getInt();
        final int checkInt2 = buffer.getInt();
        if (checkInt1 != checkInt2) {
            throw new InvalidKeyException("checksum failed");
        }

        final String sshName = buffer.getJString();
        // the rest of the buffer contains the actual key data - not needed here.

        return HostKeyAlgorithm.parseType(sshName);
    }

    /**
     * @see <a href="https://coolaj86.com/articles/the-openssh-private-key-format/">
     * the-openssh-private-key-format</a>
     * @see <a href="http://dnaeon.github.io/openssh-private-key-binary-format/">
     * openssh-private-key-binary-format</a>
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=HEAD">
     * openbsd PROTOCOL</a>
     */
    void parse(@NonNull final byte[] blob)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException {

        final Buffer buffer = new Buffer(blob);
        // Skip "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
        buffer.setReadOffSet(AUTH_MAGIC.length);
        //32-bit length, "none"   # cipher name length and string
        final String cipherName = buffer.getJString();

        //32-bit length, "none"   # kdfname length and string
        //32-bit length, nil      # kdf (0 length, no kdf)
        keyPairBuilder.setKDF(buffer.getJString(), buffer.getString());

        //32-bit 0x01             # number of keys, hard-coded to 1 (no length)
        final int nrKeys = buffer.getInt();
        if (nrKeys != 1) {
            throw new IOException("We don't support having more than 1 key in the file (yet).");
        }

        //32-bit length, sshpub   # public key in ssh format
        //    32-bit length, keytype
        //    32-bit length, pub0
        final byte[] publicKeyBlob = buffer.getString();
        keyPairBuilder.setPublicKeyBlob(publicKeyBlob);

        // private key is encoded using the same rules as used for SSH agent
        final byte[] privateKeyBlob = buffer.getString();
        keyPairBuilder.setPrivateKeyBlob(privateKeyBlob, Vendor.OPENSSH_V1);

        if (SshCipherConstants.NONE.equals(cipherName)) {
            // not encrypted, we'll bypass the DEFERRED state and
            // create the real KeyPair directly.
            keyPairBuilder.setHostKeyType(getHostKeyType(privateKeyBlob));

        } else {
            // the type can only be determined after decryption,
            // so we take this intermediate here:
            keyPairBuilder.setHostKeyType(HostKeyAlgorithm.__DEFERRED__)
                          .setPkeCipher(ImplementationFactory.getCipher(config, cipherName));
        }
    }
}
