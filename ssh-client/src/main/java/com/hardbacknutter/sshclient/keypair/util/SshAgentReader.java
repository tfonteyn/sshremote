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

// URGENT: this class has never been tested; we never set the keypair format, ....
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
                final ECPoint w = ECKeyType.decodePoint(buffer.getString());
                final BigInteger s = buffer.getBigInteger();
                final String comment = buffer.getJString();

                keyPair = new KeyPairECDSA.Builder(config)
                        .setType(ECKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm))
                        .setPoint(w)
                        .setS(s)
                        .build();
                keyPair.setPublicKeyComment(comment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_ED25519:
            case HostKeyAlgorithm.SSH_ED448: {
                // the public key
                final byte[] pub_array = buffer.getString();
                // OpenSSH stores private key in first half of string and duplicate copy
                // of public key in second half of string. Hence only copy one half.
                final EdKeyType type = EdKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm);
                final byte[] prv_array = Arrays.copyOf(buffer.getString(), type.keySize);

                // the user comment for the key
                final String comment = buffer.getJString();

                keyPair = new KeyPairEdDSA.Builder(config)
                        .setType(hostKeyAlgorithm)
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
