package com.hardbackcollector.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbackcollector.sshclient.keypair.EdKeyType;
import com.hardbackcollector.sshclient.keypair.KeyPairDSA;
import com.hardbackcollector.sshclient.keypair.KeyPairECDSA;
import com.hardbackcollector.sshclient.keypair.KeyPairEdDSA;
import com.hardbackcollector.sshclient.keypair.KeyPairRSA;
import com.hardbackcollector.sshclient.keypair.SshKeyPair;
import com.hardbackcollector.sshclient.utils.Buffer;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;

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
                // Check the length byte; quick and easy
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

    @NonNull
    public SshKeyPair parse(@NonNull final byte[] prvKey)
            throws IOException, GeneralSecurityException {

        final Buffer buffer = new Buffer(prvKey);
        final String hostKeyAlgorithm = buffer.getJString();

        final SshKeyPair keyPair;
        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA: {
                final BigInteger modulus = buffer.getBigInteger();
                final BigInteger publicExponent = buffer.getBigInteger();
                final BigInteger privateExponent = buffer.getBigInteger();
                final BigInteger coefficient = buffer.getBigInteger();
                final BigInteger p = buffer.getBigInteger();
                final BigInteger q = buffer.getBigInteger();
                final String comment = buffer.getJString();

                keyPair = new KeyPairRSA.Builder(config)
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
                final BigInteger p = buffer.getBigInteger();
                final BigInteger q = buffer.getBigInteger();
                final BigInteger g = buffer.getBigInteger();
                final BigInteger y = buffer.getBigInteger();
                final BigInteger x = buffer.getBigInteger();
                final String comment = buffer.getJString();

                keyPair = new KeyPairDSA.Builder(config)
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
                buffer.skipString(/* nistName */);
                final byte[] encodedPoint = buffer.getString();
                final BigInteger s = buffer.getBigInteger();
                final String comment = buffer.getJString();

                keyPair = new KeyPairECDSA.Builder(config)
                        .setHostKeyAlgorithm(hostKeyAlgorithm)
                        .setPoint(encodedPoint)
                        .setS(s)
                        .build();
                keyPair.setPublicKeyComment(comment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_ED25519:
                return parseEdKey(buffer, hostKeyAlgorithm, EdKeyType.Ed25519.keySize);
            case HostKeyAlgorithm.SSH_ED448:
                return parseEdKey(buffer, hostKeyAlgorithm, EdKeyType.Ed448.keySize);

            default:
                throw new InvalidKeyException("Invalid private key");
        }
    }

    @NonNull
    private SshKeyPair parseEdKey(final Buffer buffer,
                                  final String hostKeyAlgorithm,
                                  final int keySize)
            throws IOException, GeneralSecurityException {
        final SshKeyPair keyPair;
        // the public key
        final byte[] pub_array = buffer.getString();
        // OpenSSH stores private key in first half of string and duplicate copy
        // of public key in second half of string. Hence only copy one half.
        final byte[] prv_array = Arrays.copyOf(buffer.getString(), keySize);
        // and finally the user comment for the key
        final String comment = buffer.getJString();

        keyPair = new KeyPairEdDSA.Builder(config, hostKeyAlgorithm)
                .setPubArray(pub_array)
                .setPrvArray(prv_array)
                .build();
        keyPair.setPublicKeyComment(comment);
        return keyPair;
    }

}
