package com.hardbacknutter.sshclient.kex.keyexchange;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.spec.ECPoint;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.kex.KexProtocolException;
import com.hardbacknutter.sshclient.kex.kem.KEM;
import com.hardbacknutter.sshclient.kex.kem.MLKEM;
import com.hardbacknutter.sshclient.kex.keyagreements.ECDH;
import com.hardbacknutter.sshclient.keypair.ECKeyType;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.jspecify.annotations.NonNull;

/**
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-sshm-mlkem-hybrid-kex-02.html">
 *         draft-ietf-sshm-mlkem-hybrid-kex-02</a>
 */
public class KeyExchangeDHECNKEM
        extends KeyExchangeBase {

    /**
     * The client sends:
     * <p>
     * byte     SSH_MSG_KEX_HYBRID_INIT
     * string   C_INIT concatenation of C_PK2 and C_PK1
     */
    private static final byte SSH_MSG_KEX_HYBRID_INIT = 30;

    /**
     * The server responds with:
     * <p>
     * byte     SSH_MSG_KEX_HYBRID_REPLY
     * string   K_S, server's public host key
     * string   S_REPLY concatenation of S_CT2 and S_PK1
     * string   the signature on the exchange hash
     */
    private static final byte SSH_MSG_KEX_HYBRID_REPLY = 31;

    @NonNull
    private final ECKeyType ecKeyType;
    @NonNull
    private final KEM kem;
    private ECDH agreement;

    private byte[] C_INIT;

    /**
     * Constructor.
     *
     * @param digestAlgorithm standard JDK digest algorithm name
     * @param ecKeyType       {@link ECKeyType}
     * @param kem             {@link MLKEM}
     */
    public KeyExchangeDHECNKEM(@NonNull final String digestAlgorithm,
                               @NonNull final ECKeyType ecKeyType,
                               @NonNull final KEM kem) {
        super(digestAlgorithm);
        this.ecKeyType = ecKeyType;
        this.kem = kem;
    }

    @Override
    public void initKeyAgreement(@NonNull final SshClientConfig config)
            throws GeneralSecurityException {
        agreement = ImplementationFactory.getECDHKeyAgreement(config);
        agreement.init(ecKeyType);
    }

    @Override
    public void init(final @NonNull SshClientConfig config,
                     final @NonNull PacketIO io,
                     final byte @NonNull [] V_S,
                     final byte @NonNull [] V_C,
                     final byte @NonNull [] I_S,
                     final byte @NonNull [] I_C)
            throws IOException, GeneralSecurityException {
        super.init(config, io, V_S, V_C, I_S, I_C);
        if (agreement == null) {
            initKeyAgreement(config);
        }

        final int kemPublicKeyLength = kem.getPublicKeyLength();
        C_INIT = new byte[kemPublicKeyLength + ecKeyType.keySize];
        System.arraycopy(kem.getPublicKey(), 0, C_INIT, 0, kemPublicKeyLength);
        System.arraycopy(agreement.getQ(), 0, C_INIT, kemPublicKeyLength, ecKeyType.keySize);

        // byte     SSH_MSG_KEX_HYBRID_INIT
        // string   C_INIT concatenation of C_PK2 and C_PK1
        final Packet packet = new Packet(SSH_MSG_KEX_HYBRID_INIT)
                .putString(C_INIT);
        io.write(packet);

        getLogger().log(Logger.DEBUG, () ->
                "SSH_MSG_KEX_HYBRID_INIT(30) sent, expecting SSH_MSG_KEX_HYBRID_REPLY(31)");

        state = SSH_MSG_KEX_HYBRID_REPLY;
    }

    @Override
    public void next(@NonNull final Packet receivedPacket)
            throws GeneralSecurityException, IOException {

        receivedPacket.startReadingPayload();
        final byte command = receivedPacket.getByte();
        if (command != state) {
            throw new KexProtocolException(state, command);
        }

        if (command == SSH_MSG_KEX_HYBRID_REPLY) {
            state = STATE_END;

            final int encapsulationLength = kem.getEncapsulationLength();

            // byte     SSH_MSG_KEX_HYBRID_REPLY
            // string   K_S, server's public host key
            // string   S_REPLY concatenation of S_CT2 and S_PK1
            // string   the signature on the exchange hash
            K_S = receivedPacket.getString();
            final byte[] S_REPLY = receivedPacket.getString();
            if (S_REPLY.length != encapsulationLength + ecKeyType.keySize) {
                throw new InvalidKeyException("S_REPLY length mismatch");
            }

            final byte[] sig_of_H = receivedPacket.getString();

            // split the S_REPLY blob into its components
            final byte[] kemPublicKey = new byte[encapsulationLength];
            final byte[] ecdhPublicKey = new byte[ecKeyType.keySize];
            System.arraycopy(S_REPLY, 0, kemPublicKey, 0, encapsulationLength);
            System.arraycopy(S_REPLY, encapsulationLength, ecdhPublicKey, 0, ecKeyType.keySize);

            final ECPoint ecPoint = ECKeyType.decodePoint(ecdhPublicKey);

            // RFC 5656,
            // 4. ECDH Key Exchange
            //   All elliptic curve public keys MUST be validated after they are
            //   received.  An example of a validation algorithm can be found in
            //   Section 3.2.2 of [SEC1].  If a key fails validation,
            //   the key exchange MUST fail.
            agreement.validate(ecPoint);

            final MessageDigest md = getMessageDigest();
            // Create the shared secret based on KEM and XDC
            byte[] tmp = kem.extractSecret(kemPublicKey);
            md.update(tmp, 0, tmp.length);
            // do not trimZeroes, as they are a part of the secret
            tmp = agreement.getSharedSecret(ecPoint);
            md.update(tmp, 0, tmp.length);
            tmp = md.digest();

            // https://datatracker.ietf.org/doc/html/draft-josefsson-ntruprime-ssh-02
            // Instead of encoding the shared secret K as 'mpint',
            // it MUST be encoded as 'string'.
            K = encodeAsString(tmp);

            // The PQ/T Hybrid key exchange hash H is the result of computing the
            // HASH, where HASH is the hash algorithm specified in the named PQ/T
            // Hybrid key exchange method name, over the concatenation of the
            // following:
            // string   V_C,     client's identification string (CR and LF excluded)
            // string   V_S,     server's identification string (CR and LF excluded)
            // string   I_C,     payload of the client's SSH_MSG_KEXINIT
            // string   I_S,     payload of the server's SSH_MSG_KEXINIT
            // string   K_S,     server's public host key
            // string   C_INIT,  client message octet string
            // string   S_REPLY, server message octet string
            // string   K,       shared secret
            final byte[] exchangeHash = new Buffer()
                    .putString(V_C)
                    .putString(V_S)
                    .putString(I_C)
                    .putString(I_S)
                    .putString(K_S)
                    .putString(C_INIT)
                    .putString(S_REPLY)
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
