package com.hardbacknutter.sshclient.kex.keyexchange;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.spec.ECPoint;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.kex.KexProtocolException;
import com.hardbacknutter.sshclient.kex.keyagreements.ECDH;
import com.hardbacknutter.sshclient.keypair.ECKeyType;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5656#section-7">
 *         RFC 5656, Elliptic Curve Algorithm Integration</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5656#section-10.1">
 *         RFC 3526 MODP Diffie-Hellman groups for Internet Key Exchange (IKE),
 *         section 10.1 Required Curves</a>
 */
public class KeyExchangeECDH
        extends KeyExchangeBase {

    /**
     * The client sends:
     * <p>
     * byte     SSH_MSG_KEX_ECDH_INIT
     * string   Q_C, client's ephemeral public key octet string
     */
    private static final byte SSH_MSG_KEX_ECDH_INIT = 30;

    /**
     * The server responds with:
     * <p>
     * byte     SSH_MSG_KEX_ECDH_REPLY
     * string   K_S, server's public host key
     * string   Q_S, server's ephemeral public key octet string
     * string   the signature on the exchange hash
     */
    private static final byte SSH_MSG_KEX_ECDH_REPLY = 31;

    @NonNull
    private final ECKeyType ecType;
    private ECDH agreement;

    /** Q_C, client's ephemeral public key octet string. */
    private byte[] Q_C;

    /**
     * Constructor.
     *
     * @param digestAlgorithm standard JDK digest algorithm name
     * @param ecType          {@link ECKeyType}
     */
    public KeyExchangeECDH(@NonNull final String digestAlgorithm,
                           @NonNull final ECKeyType ecType) {
        super(digestAlgorithm);
        this.ecType = ecType;
    }

    @Override
    public void initKeyAgreement(@NonNull final SshClientConfig config)
            throws GeneralSecurityException {

        agreement = ImplementationFactory.getECDHKeyAgreement(config);
        agreement.init(ecType);
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

        Q_C = agreement.getQ();

        // byte     SSH_MSG_KEX_ECDH_INIT
        // string   Q_C, client's ephemeral public key octet string
        final Packet packet = new Packet(SSH_MSG_KEX_ECDH_INIT)
                .putString(Q_C);
        io.write(packet);

        getLogger().log(Logger.DEBUG, () ->
                "SSH_MSG_KEX_ECDH_INIT(30) sent, expecting SSH_MSG_KEX_ECDH_REPLY(31)");

        state = SSH_MSG_KEX_ECDH_REPLY;
    }

    @Override
    public void next(@NonNull final Packet receivedPacket)
            throws GeneralSecurityException, IOException {

        receivedPacket.startReadingPayload();
        final byte command = receivedPacket.getByte();
        if (command != state) {
            throw new KexProtocolException(state, command);
        }

        if (command == SSH_MSG_KEX_ECDH_REPLY) {
            state = STATE_END;

            // byte     SSH_MSG_KEX_ECDH_REPLY
            // string   K_S, server's public host key
            // string   Q_S, server's ephemeral public key octet string
            // string   the signature on the exchange hash H
            K_S = receivedPacket.getString();
            final byte[] q_s = receivedPacket.getString();
            final byte[] sig_of_H = receivedPacket.getString();

            final ECPoint w = ECKeyType.decodePoint(q_s);

            // RFC 5656,
            // 4. ECDH Key Exchange
            //   All elliptic curve public keys MUST be validated after they are
            //   received.  An example of a validation algorithm can be found in
            //   Section 3.2.2 of [SEC1].  If a key fails validation,
            //   the key exchange MUST fail.
            agreement.validate(w);

            K = encodeAsMPInt(trimZeroes(agreement.getSharedSecret(w)));

            //The hash H is computed as the HASH hash of the concatenation of the
            //following:
            // string   V_C, client's identification string (CR and LF excluded)
            // string   V_S, server's identification string (CR and LF excluded)
            // string   I_C, payload of the client's SSH_MSG_KEXINIT
            // string   I_S, payload of the server's SSH_MSG_KEXINIT
            // string   K_S, server's public host key
            // string   Q_C, client's ephemeral public key octet string
            // string   Q_S, server's ephemeral public key octet string
            // mpint    K,   shared secret
            final byte[] exchangeHash = new Buffer()
                    .putString(V_C)
                    .putString(V_S)
                    .putString(I_C)
                    .putString(I_S)
                    .putString(K_S)
                    .putString(Q_C)
                    .putString(q_s)
                    // pre-encoded as a raw byte[]
                    .putBytes(K)
                    .getPayload();

            final MessageDigest md = getMessageDigest();
            md.update(exchangeHash, 0, exchangeHash.length);
            H = md.digest();

            verifyHashSignature(sig_of_H);

        } else {
            throw new KexProtocolException(state, command);
        }
    }
}
