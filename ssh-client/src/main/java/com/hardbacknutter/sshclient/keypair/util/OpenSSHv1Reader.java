package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.keypair.KeyPairOpenSSHv1;
import com.hardbacknutter.sshclient.keypair.PublicKeyEncoding;
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
    private static final String ERROR_INVALID_OPEN_SSH_V1_FORMAT = "Invalid OpenSSHv1 format";

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
            throw new InvalidKeyException(ERROR_INVALID_OPEN_SSH_V1_FORMAT);
        }

        final byte[] blob = pem.getContent();
        if (!isOpenSSHv1(blob)) {
            throw new InvalidKeyException(ERROR_INVALID_OPEN_SSH_V1_FORMAT);
        }


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

        // number of keys, for now always hard-coded to 1
        final int nrKeys = buffer.getInt();
        if (nrKeys != 1) {
            throw new IOException("Expected only 1 key but there were: " + nrKeys);
        }
        // public key encoded in ssh format
        final byte[] publicKeyBlob = buffer.getString();
        // private key encoded in ssh format
        final byte[] privateKeyBlob = buffer.getString();

        final SshKeyPair keyPair;
        if (SshCipherConstants.NONE.equals(cipherName)
                // sanity check, if the cipher is "none" then kdfname SHOULD be "none"
                // and vice-versa.
                || KeyPairOpenSSHv1.KDFNAME_NONE.equals(kdfname)) {
            // not encrypted, the builder will create the real SshKeypair directly
            keyPair = new KeyPairOpenSSHv1.Builder(config)
                    .setHostKeyAlgorithm(KeyPairOpenSSHv1.getHostKeyAlgorithm(privateKeyBlob))
                    .setPrivateKey(privateKeyBlob)
                    .build();
        } else {
            // The type can only be determined after decryption.
            // Use a deferred decryptor which acts a a placeholder for the cipher.
            final PKDecryptor decryptor = new DecryptDeferred();
            decryptor.setCipher(ImplementationFactory.getCipher(config, cipherName));
            // can't set HostKeyAlgorithm; we don't know it yet
            keyPair = new KeyPairOpenSSHv1.Builder(config)
                    .setKDF(kdfname, kdfoptions)
                    .setPrivateKey(privateKeyBlob)
                    .setDecryptor(decryptor)
                    .build();
        }

        keyPair.setEncodedPublicKey(publicKeyBlob, PublicKeyEncoding.OPENSSH_V1);
        return keyPair;
    }
}
