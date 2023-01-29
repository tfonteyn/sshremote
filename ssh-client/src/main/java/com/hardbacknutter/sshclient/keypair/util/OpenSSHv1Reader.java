package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.KeyPairOpenSSHv1;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.Vendor;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptDeferred;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;

public class OpenSSHv1Reader {

    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.UTF_8);

    @NonNull
    private final SshClientConfig config;

    /**
     * Constructor.
     */
    OpenSSHv1Reader(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    @SuppressWarnings("WeakerAccess")
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
    @Nullable
    SshKeyPair parse(@NonNull final byte[] blob)
            throws IOException, GeneralSecurityException {

        if (!isOpenSSHv1(blob)) {
            return null;
        }

        final KeyPairOpenSSHv1.Builder builder = new KeyPairOpenSSHv1.Builder(config);

        final Buffer buffer = new Buffer(blob);
        // Skip "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
        buffer.setReadOffSet(AUTH_MAGIC.length);
        //32-bit length, "name"   # cipher name length and string
        final String cipherName = buffer.getJString();

        //32-bit length, "name"   # kdfname length and string
        final String kdfname = buffer.getJString();
        //32-bit length, byte[]   # kdfoptions (can be 0 length depending on kdfname)
        final byte[] kdfoptions = buffer.getString();
        builder.setKDF(kdfname, kdfoptions);

        //32-bit 0x01             # number of keys, for now always hard-coded to 1
        final int nrKeys = buffer.getInt();
        if (nrKeys != 1) {
            throw new IOException("We don't support having more than 1 key in the file (yet).");
        }

        //32-bit length, sshpub   # public key in ssh format
        //    32-bit length, keytype
        //    32-bit length, pub0
        final byte[] publicKeyBlob = buffer.getString();
        builder.setPublicKeyBlob(publicKeyBlob);

        // private key is encoded using the same rules as used for SSH agent
        final byte[] privateKeyBlob = buffer.getString();

        if (SshCipherConstants.NONE.equals(cipherName)) {
            // not encrypted, create the real KeyPair directly.
            builder.setHostKeyType(getHostKeyType(privateKeyBlob))
                   .setPrivateKeyBlob(privateKeyBlob, Vendor.OPENSSH_V1, null);
        } else {
            // The type can only be determined after decryption.
            // Use a deferred decryptor.
            final PKDecryptor decryptor = new DecryptDeferred();
            decryptor.setCipher(ImplementationFactory.getCipher(config, cipherName));
            builder.setHostKeyType(HostKeyAlgorithm.__OPENSSH_V1__)
                   .setPrivateKeyBlob(privateKeyBlob, Vendor.OPENSSH_V1, decryptor);
        }

        return builder.build();
    }
}
