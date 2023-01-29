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
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-8">
 * RFC 4253 SSH Transport Layer Protocol, section 8. Diffie-Hellman Key Exchange</a>
 */
abstract class KeyExchangeDHGroup_n
        extends KeyExchangeBase {

    /**
     * <p>
     * The client sends:
     * <p>
     * byte      SSH_MSG_KEXDH_INIT
     * mpint     e
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253">RFC 4253</a>
     */
    private static final byte SSH_MSG_KEXDH_INIT = 30;

    /**
     * The server responds with:
     * <p>
     * byte      SSH_MSG_KEXDH_REPLY
     * string    server public host key and certificates (K_S)
     * mpint     f
     * string    signature of H
     */
    private static final byte SSH_MSG_KEXDH_REPLY = 31;

    private DH agreement;
    private BigInteger e;

    /**
     * Constructor.
     *
     * @param digestAlgorithm standard JDK digest algorithm name
     */
    KeyExchangeDHGroup_n(@NonNull final String digestAlgorithm) {
        super(digestAlgorithm);
    }

    @NonNull
    abstract BigInteger getP();

    @NonNull
    abstract BigInteger getG();

    @Override
    public void initKeyAgreement(@NonNull final SshClientConfig config)
            throws GeneralSecurityException {

        agreement = ImplementationFactory.getDHKeyAgreement(config);
        agreement.init();

        agreement.setP(getP());
        agreement.setG(getG());
        e = agreement.getE();
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

        final Packet packet = new Packet(SSH_MSG_KEXDH_INIT)
                .putMPInt(e);

        io.write(packet);

        if (getLogger().isEnabled(Logger.DEBUG)) {
            getLogger().log(Logger.DEBUG, () -> "SSH_MSG_KEXDH_INIT(30) sent,"
                    + " expecting SSH_MSG_KEXDH_REPLY(31)");
        }
        state = SSH_MSG_KEXDH_REPLY;
    }

    @Override
    public void next(@NonNull final Packet receivedPacket)
            throws GeneralSecurityException, IOException {

        receivedPacket.startReadingPayload();
        final byte command = receivedPacket.getByte();
        if (command != state) {
            throw new KexProtocolException(state, command);
        }

        if (command == SSH_MSG_KEXDH_REPLY) {
            state = KeyExchange.STATE_END;

            // byte      SSH_MSG_KEXDH_REPLY
            // string    server public host key and certificates (K_S)
            // mpint     f
            // string    the signature on the exchange hash H
            K_S = receivedPacket.getString();
            final BigInteger f = receivedPacket.getBigInteger();
            final byte[] sig_of_H = receivedPacket.getString();

            agreement.validate(e, f);

            K = agreement.getSharedSecret(f);
            K = trimZeroes(K);

            // https://datatracker.ietf.org/doc/html/rfc4253#section-8
            //The hash H is computed as the HASH hash of the concatenation of the
            //following:
            // string    V_C, the client's version string (CR and NL excluded)
            // string    V_S, the server's version string (CR and NL excluded)
            // string    I_C, the payload of the client's SSH_MSG_KEXINIT
            // string    I_S, the payload of the server's SSH_MSG_KEXINIT
            // string    K_S, the host key
            // mpint     e, exchange value sent by the client
            // mpint     f, exchange value sent by the server
            // mpint     K, the shared secret
            final byte[] exchangeHash = new Buffer()
                    .putString(V_C)
                    .putString(V_S)
                    .putString(I_C)
                    .putString(I_S)
                    .putString(K_S)
                    .putMPInt(e)
                    .putMPInt(f)
                    .putMPInt(K)
                    .getPayload();

            verify(exchangeHash, sig_of_H);

        } else {
            throw new KexProtocolException(state, command);
        }
    }
}
