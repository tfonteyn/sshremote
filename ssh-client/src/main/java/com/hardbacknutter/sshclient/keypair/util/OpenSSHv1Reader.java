package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.KeyPairOpenSSHv1;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptDeferred;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;

class OpenSSHv1Reader {

    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.UTF_8);

    @NonNull
    private final SshClientConfig config;

    /**
     * Constructor.
     */
    OpenSSHv1Reader(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    private static boolean isOpenSSHv1(@NonNull final byte[] blob) {
        return Arrays.equals(AUTH_MAGIC, Arrays.copyOfRange(blob, 0, AUTH_MAGIC.length));
    }

    /**
     * @see <a href="https://coolaj86.com/articles/the-openssh-private-key-format/">
     * the-openssh-private-key-format</a>
     * @see <a href="http://dnaeon.github.io/openssh-private-key-binary-format/">
     * openssh-private-key-binary-format</a>
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=HEAD">
     * openbsd PROTOCOL</a>
     */
    @NonNull
    SshKeyPair parse(@NonNull final PemObject pem)
            throws IOException, InvalidKeyException, GeneralSecurityException {

        if (!"OPENSSH PRIVATE KEY".equals(pem.getType())) {
            throw new InvalidKeyException("Invalid OpenSSHv1 format");
        }

        final byte[] blob = pem.getContent();
        if (!isOpenSSHv1(blob)) {
            throw new InvalidKeyException("Invalid OpenSSHv1 format");
        }

        final KeyPairOpenSSHv1.Builder builder = new KeyPairOpenSSHv1.Builder(config);

        final Buffer buffer = new Buffer(blob);
        // "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
        buffer.setReadOffSet(AUTH_MAGIC.length);
        // cipher
        final String cipherName = buffer.getJString();

        // kdfname
        final String kdfname = buffer.getJString();
        // kdfoptions
        // Length will be 0 (and no string) if there are no options
        final byte[] kdfoptions = buffer.getString();
        builder.setKDF(kdfname, kdfoptions);

        // number of keys, for now always hard-coded to 1
        final int nrKeys = buffer.getInt();
        if (nrKeys != 1) {
            throw new IOException("We don't support having more than 1 key in the file (yet).");
        }
        // public key encoded in ssh format
        final byte[] publicKeyBlob = buffer.getString();
        builder.setPublicKeyBlob(publicKeyBlob);

        // private key encoded in ssh format
        final byte[] privateKeyBlob = buffer.getString();

        if (SshCipherConstants.NONE.equals(cipherName)) {
            // not encrypted, the builder will create the real SshKeypair directly
            builder.setHostKeyType(KeyPairOpenSSHv1.getHostKeyType(privateKeyBlob))
                   .setPrivateKey(privateKeyBlob);
        } else {
            // The type can only be determined after decryption.
            // Use a deferred decryptor.
            final PKDecryptor decryptor = new DecryptDeferred();
            decryptor.setCipher(ImplementationFactory.getCipher(config, cipherName));
            builder.setHostKeyType(HostKeyAlgorithm.__OPENSSH_V1__)
                   .setPrivateKey(privateKeyBlob)
                   .setDecryptor(decryptor);
        }

        return builder.build();
    }
}
