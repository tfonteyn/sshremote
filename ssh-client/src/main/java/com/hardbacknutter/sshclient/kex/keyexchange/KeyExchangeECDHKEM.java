package com.hardbacknutter.sshclient.kex.keyexchange;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.kex.KexProtocolException;
import com.hardbacknutter.sshclient.kex.kem.KEM;
import com.hardbacknutter.sshclient.kex.keyagreements.XDH;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-josefsson-ntruprime-ssh-02">
 *         draft-josefsson-ntruprime-ssh-02</a>
 * @see KeyExchangeECDH
 */
public class KeyExchangeECDHKEM
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
    @NonNull
    private final KEM kem;
    private XDH agreement;

    /** Q_C, client's ephemeral public key octet string. */
    private byte[] Q_C;

    /**
     * Constructor.
     * <p>
     * Dev. note: all parameters are in fact fixed for now,
     * but we're still passing them in for consistency with other classes.
     *
     * @param digestAlgorithm standard JDK digest algorithm name
     * @param xdhCurveName    {@link XDHParameterSpec#X25519}
     * @param keySize         {@link X25519PublicKeyParameters#KEY_SIZE}
     * @param oid             {@link EdECObjectIdentifiers#id_X25519}
     * @param kem             new instance
     */
    public KeyExchangeECDHKEM(@NonNull final String digestAlgorithm,
                              @NonNull final String xdhCurveName,
                              final int keySize,
                              @NonNull final ASN1ObjectIdentifier oid,
                              @NonNull final KEM kem) {
        super(digestAlgorithm);
        this.xdhCurveName = xdhCurveName;
        this.keySize = keySize;
        this.oid = oid;
        this.kem = kem;
    }

    @Override
    public void initKeyAgreement(@NonNull final SshClientConfig config)
            throws GeneralSecurityException {

        agreement = ImplementationFactory.getXDHKeyAgreement(config);
        agreement.init(xdhCurveName, oid, keySize);

        kem.init();
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

        // Q_C is the concatenation of KEM and XDH Q_C
        final int kemPublicKeyLength = kem.getPublicKeyLength();
        Q_C = new byte[kemPublicKeyLength + keySize];
        System.arraycopy(kem.getPublicKey(), 0, Q_C, 0, kemPublicKeyLength);
        System.arraycopy(agreement.getQ(), 0, Q_C, kemPublicKeyLength, keySize);

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

            final int encapsulationLength = kem.getEncapsulationLength();

            // byte     SSH_MSG_KEX_ECDH_REPLY
            // string   K_S, server's public host key
            // string   Q_S, server's ephemeral public key octet string
            // string   the signature on the exchange hash H
            K_S = receivedPacket.getString();
            final byte[] q_s = receivedPacket.getString();
            if (q_s.length != encapsulationLength + keySize) {
                throw new InvalidKeyException("Q_S length mismatch");
            }

            final byte[] sig_of_H = receivedPacket.getString();

            // split the Q_S blob into its components
            final byte[] kemPublicKey = new byte[encapsulationLength];
            final byte[] xdhPublicKey = new byte[keySize];
            System.arraycopy(q_s, 0, kemPublicKey, 0, encapsulationLength);
            System.arraycopy(q_s, encapsulationLength, xdhPublicKey, 0, keySize);

            // RFC 5656,
            // 4. ECDH Key Exchange
            //   All elliptic curve public keys MUST be validated after they are
            //   received.  An example of a validation algorithm can be found in
            //   Section 3.2.2 of [SEC1].  If a key fails validation,
            //   the key exchange MUST fail.
            agreement.validate(xdhPublicKey);

            final MessageDigest md = getMessageDigest();
            // Create the shared secret based on KEM and XDC
            byte[] tmp = kem.extractSecret(kemPublicKey);
            md.update(tmp, 0, tmp.length);
            tmp = trimZeroes(agreement.getSharedSecret(xdhPublicKey));
            md.update(tmp, 0, tmp.length);
            tmp = md.digest();

            // https://datatracker.ietf.org/doc/html/draft-josefsson-ntruprime-ssh-02
            // Instead of encoding the shared secret K as 'mpint',
            // it MUST be encoded as 'string'.
            K = encodeAsString(tmp);

            //The hash H is computed as the HASH hash of the concatenation of the
            //following:
            // string   V_C, client's identification string (CR and LF excluded)
            // string   V_S, server's identification string (CR and LF excluded)
            // string   I_C, payload of the client's SSH_MSG_KEXINIT
            // string   I_S, payload of the server's SSH_MSG_KEXINIT
            // string   K_S, server's public host key
            // string   Q_C, client's ephemeral public key octet string
            // string   Q_S, server's ephemeral public key octet string
            // string   K,   shared secret
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

            md.update(exchangeHash, 0, exchangeHash.length);
            H = md.digest();

            verifyHashSignature(sig_of_H);

        } else {
            throw new KexProtocolException(state, command);
        }
    }
}
