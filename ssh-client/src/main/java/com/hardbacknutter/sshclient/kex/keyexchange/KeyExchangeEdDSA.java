package com.hardbacknutter.sshclient.kex.keyexchange;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.kex.KexProtocolException;
import com.hardbacknutter.sshclient.kex.keyagreements.XDH;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8731#section-3">
 *         RFC 8731 Key Exchange Method Using Curve25519 and Curve448,
 *         section 3: Key Exchange Methods</a>
 */
public class KeyExchangeEdDSA
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
    private final String xdhCurveName;
    @NonNull
    private final ASN1ObjectIdentifier oid;

    private final int keySize;

    private XDH agreement;

    /** Q_C, client's ephemeral public key octet string. */
    private byte[] Q_C;

    /**
     * @param digestAlgorithm standard JDK digest algorithm name
     * @param xdhCurveName    {@link XDHParameterSpec#X25519} or
     *                        {@link XDHParameterSpec#X448}
     * @param keySize         {@link X25519PublicKeyParameters#KEY_SIZE} or
     *                        {@link X448PublicKeyParameters#KEY_SIZE}
     * @param oid             {@link EdECObjectIdentifiers#id_X25519} or
     *                        {@link EdECObjectIdentifiers#id_X448}
     */
    public KeyExchangeEdDSA(@NonNull final String digestAlgorithm,
                            @NonNull final String xdhCurveName,
                            final int keySize,
                            @NonNull final ASN1ObjectIdentifier oid) {
        super(digestAlgorithm);
        this.xdhCurveName = xdhCurveName;
        this.oid = oid;
        this.keySize = keySize;
    }

    @Override
    public void initKeyAgreement(@NonNull final SshClientConfig config)
            throws GeneralSecurityException {

        agreement = ImplementationFactory.getXDHKeyAgreement(config);
        agreement.init(xdhCurveName, oid, keySize);
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
            state = KeyExchange.STATE_END;

            // byte     SSH_MSG_KEX_ECDH_REPLY
            // string   K_S, server's public host key
            // string   Q_S, server's ephemeral public key octet string
            // string   the signature on the exchange hash H
            K_S = receivedPacket.getString();
            final byte[] q_s = receivedPacket.getString();
            final byte[] sig_of_H = receivedPacket.getString();

            agreement.validate(q_s);

            K = encodeAsMPInt(trimZeroes(agreement.getSharedSecret(q_s)));

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
