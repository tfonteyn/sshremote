package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.ECKeyType;
import com.hardbacknutter.sshclient.keypair.EdKeyType;
import com.hardbacknutter.sshclient.keypair.KeyPairDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairECDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairEdDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairRSA;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.utils.Buffer;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.ECPoint;
import java.util.Arrays;

// URGENT: this class has never been tested

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
        return pubKey == null &&
                prvKey != null &&
                prvKey.length > 20 &&
                // Check the length byte for matching one of the "key type" string lengths.
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

        // Format for the key SSH_AGENTC_ADD_IDENTITY.
        // The "constraints" field is only present for the
        //   SSH_AGENTC_ADD_ID_CONSTRAINED message.
        // The below parsing expects the "identityBlob"

        final Buffer buffer = new Buffer(identityBlob);
        final String hostKeyAlgorithm = buffer.getJString();

        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA: {
                //       string                  "ssh-rsa"
                //       mpint                   n
                //       mpint                   e
                //       mpint                   d
                //       mpint                   iqmp
                //       mpint                   p
                //       mpint                   q
                //       string                  comment
                //       constraint[]            constraints
                final BigInteger modulus = buffer.getBigInteger();
                final BigInteger publicExponent = buffer.getBigInteger();
                final BigInteger privateExponent = buffer.getBigInteger();
                final BigInteger coefficient = buffer.getBigInteger();
                final BigInteger p = buffer.getBigInteger();
                final BigInteger q = buffer.getBigInteger();
                final String comment = buffer.getJString();

                final SshKeyPair keyPair = new KeyPairRSA.Builder(config)
                        .setModulus(modulus)
                        .setPublicExponent(publicExponent)
                        .setPrivateExponent(privateExponent)
                        .setCoefficient(coefficient)
                        .setPrimeP(p)
                        .setPrimeQ(q)
                        .build();
                keyPair.setPublicKeyComment(comment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_DSS: {
                //       string                  "ssh-dss"
                //       mpint                   p
                //       mpint                   q
                //       mpint                   g
                //       mpint                   y
                //       mpint                   x
                //       string                  comment
                //       constraint[]            constraints
                final BigInteger p = buffer.getBigInteger();
                final BigInteger q = buffer.getBigInteger();
                final BigInteger g = buffer.getBigInteger();
                final BigInteger y = buffer.getBigInteger();
                final BigInteger x = buffer.getBigInteger();
                final String comment = buffer.getJString();

                final SshKeyPair keyPair = new KeyPairDSA.Builder(config)
                        .setPQG(p, q, g)
                        .setX(x)
                        .setY(y)
                        .build();
                keyPair.setPublicKeyComment(comment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521: {
                //       string                  key type               HostKeyAlgorithm
                //       string                  ecdsa_curve_name       nistName
                //       string                  Q                      public w
                //       mpint                   d                      private s
                //       string                  comment
                //       constraint[]            constraints

                buffer.skipString(/* nistName */);
                final ECPoint w = ECKeyType.decodePoint(buffer.getString());
                final BigInteger s = buffer.getBigInteger();
                final String comment = buffer.getJString();

                final SshKeyPair keyPair = new KeyPairECDSA.Builder(config)
                        .setHostKeyAlgorithm(hostKeyAlgorithm)
                        .setPoint(w)
                        .setS(s)
                        .build();
                keyPair.setPublicKeyComment(comment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_ED25519:
            case HostKeyAlgorithm.SSH_ED448: {
                //       string                  "ssh-ed25519"
                //       string                  ENC(A)                 public key
                //       string                  k || ENC(A)            private key "k"
                //                                                      concatenated with public key
                //       string                  comment
                //       constraint[]            constraints

                // the public key
                final byte[] pub_array = buffer.getString();
                // OpenSSH stores private key in first half of string and duplicate copy
                // of public key in second half of string. Hence only copy one half.
                final EdKeyType type = EdKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm);
                final byte[] prv_array = Arrays.copyOf(buffer.getString(), type.keySize);

                final String comment = buffer.getJString();

                final SshKeyPair keyPair = new KeyPairEdDSA.Builder(config)
                        .setHostKeyAlgorithm(hostKeyAlgorithm)
                        .setPubArray(pub_array)
                        .setPrvArray(prv_array)
                        .build();
                keyPair.setPublicKeyComment(comment);
                return keyPair;
            }

            default:
                throw new InvalidKeyException("Invalid private key");
        }
    }

}
