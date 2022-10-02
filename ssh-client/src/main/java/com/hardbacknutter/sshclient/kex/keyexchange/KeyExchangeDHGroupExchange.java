package com.hardbacknutter.sshclient.kex.keyexchange;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.kex.KexProtocolException;
import com.hardbacknutter.sshclient.kex.keyagreements.DH;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

/**
 * Base class for {@code diffie-hellman-group-exchange-sha*}
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4419">
 * RFC 4419, Diffie-Hellman Group Exchange for the Secure Shell (SSH)</a>
 * @see <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.toc">
 * Key Exchange (KEX) Method Updates and Recommendations</a>
 */
public class KeyExchangeDHGroupExchange
        extends KeyExchangeBase {

    /**
     * First, the client sends:
     * <p>
     * byte     SSH_MSG_KEY_DH_GEX_REQUEST
     * uint32   min, minimal size in bits of an acceptable group
     * uint32   n, preferred size in bits of the group the server will send
     * uint32   max, maximal size in bits of an acceptable group
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4419#section-5">
     * RFC 4419 Diffie-Hellman Group Exchange for SSH Transport Layer Protocol,
     * section 5. Summary of Message Numbers</a>
     */
    private static final byte SSH_MSG_KEX_DH_GEX_REQUEST = 34;
    /**
     * The server responds with
     * <p>
     * byte    SSH_MSG_KEX_DH_GEX_GROUP
     * mpint   p, safe prime
     * mpint   g, generator for subgroup in GF(p)
     */
    private static final byte SSH_MSG_KEX_DH_GEX_GROUP = 31;
    /**
     * The client responds with:
     * <p>
     * byte    SSH_MSG_KEX_DH_GEX_INIT
     * mpint   e
     */
    private static final byte SSH_MSG_KEX_DH_GEX_INIT = 32;
    /**
     * The server responds with:
     * <p>
     * byte     SSH_MSG_KEX_DH_GEX_REPLY
     * string   server public host key and certificates (K_S)
     * mpint    f
     * string   signature of H
     */
    private static final byte SSH_MSG_KEX_DH_GEX_REPLY = 33;


    private static final int minKeySize = 1024;
    private int preferredKeySize = 1024;
    private int maxKeySize = 2048;

    private DH agreement;

    /** prime modulus. */
    private BigInteger p;
    /** base generator. */
    private BigInteger g;
    /**
     * Client generates a random number x, where 1 < x < (p-1)/2.  It
     * computes e = g^x mod p, and sends "e" to Server.
     */
    private BigInteger e;

    /**
     * Constructor.
     *
     * @param digestAlgorithm standard JDK digest algorithm name
     */
    public KeyExchangeDHGroupExchange(@NonNull final String digestAlgorithm) {
        super(digestAlgorithm);
    }

    @Override
    public void initKeyAgreement(@NonNull final SshClientConfig config)
            throws GeneralSecurityException {

        // Since JDK8, SunJCE has lifted the key size restrictions
        // from 1024 to 2048 for DH.
        // JDK-8072452 increases DH max to 8192
        maxKeySize = check8192(config);
        if (maxKeySize >= 2048) {
            preferredKeySize = 2048;
        }

        agreement = ImplementationFactory.getDHKeyAgreement(config);
        agreement.init();
    }

    @Override
    public void init(@NonNull final SshClientConfig config,
                     @NonNull final PacketIO io,
                     @NonNull final byte[] V_S,
                     @NonNull final byte[] V_C,
                     @NonNull final byte[] I_S,
                     @NonNull final byte[] I_C)
            throws GeneralSecurityException, IOException {
        super.init(config, io, V_S, V_C, I_S, I_C);
        if (agreement == null) {
            initKeyAgreement(config);
        }

        // byte     SSH_MSG_KEY_DH_GEX_REQUEST
        // uint32   min, minimal size in bits of an acceptable group
        // uint32   n, preferred size in bits of the group the server will send
        // uint32   max, maximal size in bits of an acceptable group
        final Packet packet = new Packet(SSH_MSG_KEX_DH_GEX_REQUEST)
                .putInt(minKeySize)
                .putInt(preferredKeySize)
                .putInt(maxKeySize);
        io.write(packet);

        if (getLogger().isEnabled(Logger.DEBUG)) {
            getLogger().log(Logger.DEBUG, () -> "SSH_MSG_KEX_DH_GEX_REQUEST(34)("
                    + minKeySize + "<" + preferredKeySize + "<" + maxKeySize + ") sent,"
                    + " expecting SSH_MSG_KEX_DH_GEX_GROUP(31)");
        }
        state = SSH_MSG_KEX_DH_GEX_GROUP;
    }

    @Override
    public void next(@NonNull final Packet receivedPacket)
            throws GeneralSecurityException, IOException {

        receivedPacket.startReadingPayload();
        final byte command = receivedPacket.getByte();
        if (command != state) {
            throw new KexProtocolException(state, command);
        }

        switch (command) {
            case SSH_MSG_KEX_DH_GEX_GROUP: {
                // byte     SSH_MSG_KEX_DH_GEX_GROUP(31)
                // mpint    p, safe prime
                // mpint    g, generator for subgroup in GF (p)
                p = receivedPacket.getBigInteger();
                g = receivedPacket.getBigInteger();

                agreement.setP(p);
                agreement.setG(g);
                e = agreement.getE();

                // The client responds with:
                // byte     SSH_MSG_KEX_DH_GEX_INIT(32)
                // mpint    e <- g^x mod p
                //          x is a random number (1 < x < (p-1)/2)
                final Packet packet = new Packet(SSH_MSG_KEX_DH_GEX_INIT)
                        .putBigInteger(e);
                io.write(packet);

                if (getLogger().isEnabled(Logger.DEBUG)) {
                    getLogger().log(Logger.DEBUG, () -> "SSH_MSG_KEX_DH_GEX_INIT(32) sent,"
                            + " expecting SSH_MSG_KEX_DH_GEX_REPLY(33)");
                }
                state = SSH_MSG_KEX_DH_GEX_REPLY;
                break;
            }
            case SSH_MSG_KEX_DH_GEX_REPLY: {
                state = KeyExchange.STATE_END;

                // byte     SSH_MSG_KEX_DH_GEX_REPLY
                // string   server public host key and certificates (K_S)
                // mpint    f
                // string   signature of H
                K_S = receivedPacket.getString();
                final BigInteger f = receivedPacket.getBigInteger();
                final byte[] sig_of_H = receivedPacket.getString();

                agreement.validate(e, f);
                K = agreement.getSharedSecret(f);
                K = trimZeroes(K);

                // https://datatracker.ietf.org/doc/html/rfc4419#section-3
                //The hash H is computed as the HASH hash of the concatenation of the
                //following:
                // string    V_C, the client's version string (CR and NL excluded)
                // string    V_S, the server's version string (CR and NL excluded)
                // string    I_C, the payload of the client's SSH_MSG_KEXINIT
                // string    I_S, the payload of the server's SSH_MSG_KEXINIT
                // string    K_S, the host key
                // uint32    min, minimal size in bits of an acceptable group
                // uint32    n, preferred size in bits of the group the server should send
                // uint32    max, maximal size in bits of an acceptable group
                // mpint     p, safe prime
                // mpint     g, generator for subgroup
                // mpint     e, exchange value sent by the client
                // mpint     f, exchange value sent by the server
                // mpint     K, the shared secret
                final byte[] exchangeHash = new Buffer()
                        .putString(V_C)
                        .putString(V_S)
                        .putString(I_C)
                        .putString(I_S)
                        .putString(K_S)
                        .putInt(minKeySize)
                        .putInt(preferredKeySize)
                        .putInt(maxKeySize)
                        .putBigInteger(p)
                        .putBigInteger(g)
                        .putBigInteger(e)
                        .putBigInteger(f)
                        .putMPInt(K)
                        .getPayload();

                verify(exchangeHash, sig_of_H);
                break;
            }

            default:
                throw new KexProtocolException(state, command);
        }
    }

    private int check8192(@NonNull final SshClientConfig config)
            throws GeneralSecurityException {

        final DH dh = ImplementationFactory.getDHKeyAgreement(config);
        // try for 8192
        dh.init();
        dh.setP(new BigInteger(1, KeyExchangeDHGroup18.p));
        dh.setG(KeyExchangeDHGroup18.g);
        try {
            dh.getE();
            return 8192;
        } catch (final Exception ignore) {
            // ignore
        }

        // try for 2048
        dh.init();
        dh.setP(new BigInteger(1, KeyExchangeDHGroup14.p));
        dh.setG(KeyExchangeDHGroup14.g);

        try {
            dh.getE();
            return 2048;
        } catch (final Exception ignore) {
            // ignore
        }
        // ouch...
        return minKeySize;
    }
}
