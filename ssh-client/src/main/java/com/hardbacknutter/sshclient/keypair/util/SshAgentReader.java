package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.KeyPairBuilder;
import com.hardbacknutter.sshclient.keypair.KeyPairDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairECDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairEdDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairRSA;
import com.hardbacknutter.sshclient.keypair.PrivateKeyEncoding;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.UnsupportedAlgorithmException;
import com.hardbacknutter.sshclient.utils.Buffer;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * <a href="https://tools.ietf.org/html/draft-miller-ssh-agent-04">draft-miller-ssh-agent-04</a>
 */
class SshAgentReader {

    @NonNull
    private final SshClientConfig config;

    /**
     * Constructor.
     */
    SshAgentReader(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    static boolean isSSHAgent(@Nullable final byte[] prvKey,
                              @Nullable final byte[] pubKey) {

        // Do a FAST check by looking at the length byte for matching
        // one of the "key type" string lengths.
        return pubKey == null && prvKey != null && prvKey.length > 20 &&
                prvKey[0] == 0 && prvKey[1] == 0 && prvKey[2] == 0
                // "ssh-rsa", "ssh-dsa"
                && (prvKey[3] == 7
                // "ecdsa-sha2-nistp..."
                || prvKey[3] == 19
                // "ssh-ed25519"
                || prvKey[3] == 11
                // "ssh-ed448"
                || prvKey[3] == 9
        );
    }

    /**
     * Parse the payload of a SSH_AGENTC_ADD_IDENTITY message.
     * The generic format for the key SSH_AGENTC_ADD_IDENTITY message is:
     * <pre>{@code
     *        byte                    SSH_AGENTC_ADD_IDENTITY
     *        string                  key type
     *        byte[]                  key contents
     *        string                  key comment
     * }</pre>
     *
     * @param identityBlob the byte[] WITHOUT the message byte. i.e. starting with the "key type"
     *
     * @return a KeyPair
     */
    @NonNull
    public SshKeyPair parse(@NonNull final byte[] identityBlob)
            throws IOException, GeneralSecurityException {

        final Buffer buffer = new Buffer(identityBlob);
        final String hostKeyAlgorithm = buffer.getJString();

        final KeyPairBuilder builder;
        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA: {
                builder = new KeyPairRSA.Builder(config);
                break;
            }
            case HostKeyAlgorithm.SSH_DSS: {
                builder = new KeyPairDSA.Builder(config);
                break;
            }
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521: {
                builder = new KeyPairECDSA.Builder(config, hostKeyAlgorithm);
                break;
            }
            case HostKeyAlgorithm.SSH_ED25519:
            case HostKeyAlgorithm.SSH_ED448: {
                builder = new KeyPairEdDSA.Builder(config, hostKeyAlgorithm);
                break;
            }
            default:
                throw new UnsupportedAlgorithmException(hostKeyAlgorithm);
        }

        return builder
                .setPrivateKey(identityBlob, PrivateKeyEncoding.SSH_AGENT)
                .build();
    }
}
