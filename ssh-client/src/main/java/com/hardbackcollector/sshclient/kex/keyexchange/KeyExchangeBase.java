package com.hardbackcollector.sshclient.kex.keyexchange;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbackcollector.sshclient.keypair.ECKeyType;
import com.hardbackcollector.sshclient.keypair.EdKeyType;
import com.hardbackcollector.sshclient.keypair.KeyPairDSA;
import com.hardbackcollector.sshclient.keypair.KeyPairECDSA;
import com.hardbackcollector.sshclient.keypair.KeyPairEdDSA;
import com.hardbackcollector.sshclient.keypair.KeyPairRSA;
import com.hardbackcollector.sshclient.signature.SshSignature;
import com.hardbackcollector.sshclient.transport.PacketIO;
import com.hardbackcollector.sshclient.utils.Buffer;
import com.hardbackcollector.sshclient.utils.ImplementationFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECPoint;

import javax.crypto.KeyAgreement;

/**
 * Abstract base class for key exchange algorithms.
 * <p>
 * The concrete implementation will be chosen based on the configuration
 * and on the negotiation between client and server.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-7">
 * RFC 4253 SSH Transport Layer Protocol, 7. Key Exchange</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-8">
 * RFC 4253 SSH Transport Layer Protocol, 8. Diffie-Hellman Key Exchange</a>
 * @see <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3">
 * Key Exchange (KEX) Method Updates and Recommendations</a>
 */
abstract class KeyExchangeBase
        implements KeyExchange {

    @NonNull
    private final String digestAlgorithm;
    /** string   V_C, client's identification string (CR and LF excluded). */
    byte[] V_C;
    /** string   V_S, server's identification string (CR and LF excluded). */
    byte[] V_S;
    /** string   I_C, payload of the client's SSH_MSG_KEXINIT. */
    byte[] I_C;
    /** string   I_S, payload of the server's SSH_MSG_KEXINIT. */
    byte[] I_S;
    /** string   K_S, server's public host key. */
    byte[] K_S;
    /** mpint    K,   shared secret. */
    byte[] K;
    /** The NEXT packet we expect. i.e. the reply to our send. */
    byte state;
    PacketIO io;
    private SshClientConfig config;
    /** The hash generator. */
    private MessageDigest md;
    /** The hash H is computed by {@link MessageDigest#digest()}. */
    private byte[] H;
    @NonNull
    private String hostKeyAlgorithm = "";

    /**
     * Constructor.
     *
     * @param digestAlgorithm standard JDK digest algorithm name
     */
    KeyExchangeBase(@NonNull final String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    @SuppressWarnings("OverlyBroadThrowsClause")
    @Override
    public void init(@NonNull final SshClientConfig config,
                     @NonNull final PacketIO io,
                     @NonNull final byte[] V_S,
                     @NonNull final byte[] V_C,
                     @NonNull final byte[] I_S,
                     @NonNull final byte[] I_C)
            throws IOException, GeneralSecurityException {
        md = MessageDigest.getInstance(digestAlgorithm);

        this.config = config;
        this.io = io;

        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
    }

    /**
     * Get the algorithm name as received in the final KEX packet.
     *
     * @return "ssh-dss", "ssh-rsa", "ecdsa*", "ssh-ed25519", "ssh-ed448"
     */
    @NonNull
    @Override
    public String getHostKeyAlgorithm() {
        return hostKeyAlgorithm;
    }

    @Override
    public byte getNextPacketExpected() {
        return state;
    }

    @Override
    public boolean isExpecting(final byte command) {
        return state == command;
    }

    @NonNull
    @Override
    public byte[] getK() {
        return K;
    }

    @NonNull
    @Override
    public byte[] getH() {
        return H;
    }

    @NonNull
    @Override
    public MessageDigest getMessageDigest() {
        return md;
    }

    @NonNull
    @Override
    public byte[] getK_S() {
        return K_S;
    }

    void verify(@NonNull final byte[] hash,
                @NonNull final byte[] sig_of_H)
            throws GeneralSecurityException, IOException {

        final String sshSignatureAlgorithm = new Buffer(sig_of_H).getJString();
        final SshSignature sig = ImplementationFactory.getSignature(config, sshSignatureAlgorithm);
        sig.init(sshSignatureAlgorithm);

        // Extract the PublicKey from the server key blob
        final PublicKey publicKey;
        final Buffer buffer = new Buffer(K_S);
        hostKeyAlgorithm = buffer.getJString();
        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA: {
                final BigInteger publicExponent = buffer.getBigInteger();
                final BigInteger modulus = buffer.getBigInteger();

                publicKey = KeyPairRSA.generatePublic(publicExponent, modulus);
                break;
            }
            case HostKeyAlgorithm.SSH_DSS: {
                final BigInteger p = buffer.getBigInteger();
                final BigInteger q = buffer.getBigInteger();
                final BigInteger g = buffer.getBigInteger();
                final BigInteger y = buffer.getBigInteger();

                publicKey = KeyPairDSA.generatePublic(y, p, q, g);
                break;
            }
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256: {
                buffer.skipString(/* nistName */);
                final ECPoint w = ECKeyType.decodePoint(buffer.getString());
                publicKey = KeyPairECDSA.generatePublic(
                        ECKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm).curveName, w);
                break;
            }
            case HostKeyAlgorithm.SSH_ED25519:
            case HostKeyAlgorithm.SSH_ED448: {
                final byte[] key = buffer.getString();
                publicKey = KeyPairEdDSA.generatePublic(
                        EdKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm), key);
                break;
            }
            default: {
                throw new NoSuchAlgorithmException(hostKeyAlgorithm);
            }
        }

        md.update(hash, 0, hash.length);
        H = md.digest();

        sig.initVerify(publicKey);
        sig.update(H);

        if (!sig.verify(sig_of_H)) {
            throw new InvalidKeyException("KeyExchange#verify failed"
                                                  + ", hostKeyAlg=" + hostKeyAlgorithm
                                                  + ", sshSigAlg=" + sshSignatureAlgorithm);
        }
    }

    /**
     * The secret generated by {@link KeyAgreement#generateSecret}
     * may start with 0, even if it is a positive value.
     */
    @NonNull
    byte[] trimZeroes(@NonNull final byte[] b) {
        if (b.length > 1 && b[0] == 0 && (b[1] & 0x80) == 0) {
            final byte[] tmp = new byte[b.length - 1];
            System.arraycopy(b, 1, tmp, 0, tmp.length);
            return trimZeroes(tmp);
        } else {
            return b;
        }
    }
}
