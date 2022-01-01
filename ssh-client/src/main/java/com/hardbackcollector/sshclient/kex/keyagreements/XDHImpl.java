package com.hardbackcollector.sshclient.kex.keyagreements;


import androidx.annotation.NonNull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8731#section-3">
 * RFC 8731 SSH Key Exchange Method Using Curve25519 and Curve448,
 * section 3. Key Exchange Methods</a>
 */
public class XDHImpl
        implements XDH {

    private AlgorithmIdentifier algId;
    private int keySize;
    private KeyAgreement keyAgreement;
    private byte[] q;

    @Override
    public void init(@NonNull final String xdhCurveName,
                     @NonNull final ASN1ObjectIdentifier oid,
                     final int keySize)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

        this.algId = new AlgorithmIdentifier(oid);
        this.keySize = keySize;

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(xdhCurveName, "BC");
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final XDHPublicKey publicKey = (XDHPublicKey) keyPair.getPublic();
        final byte[] u = publicKey.getU().toByteArray();
        q = rotate(u);

        keyAgreement = KeyAgreement.getInstance(xdhCurveName, "BC");
        keyAgreement.init(keyPair.getPrivate());
    }

    @NonNull
    @Override
    public byte[] getQ() {
        return q;
    }

    @NonNull
    @Override
    public byte[] getSharedSecret(@NonNull final byte[] q_s)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
                   InvalidKeyException, IllegalStateException, NoSuchProviderException {

        // create an ASN1 object, so we can read the keySpec from it.
        final SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algId, q_s);
        final KeySpec keySpec;
        try {
            keySpec = new X509EncodedKeySpec(publicKeyInfo.getEncoded());

        } catch (final IOException e) {
            throw new InvalidKeySpecException(e);
        }

        final KeyFactory keyFactory = KeyFactory.getInstance("XDH", "BC");
        final PublicKey theirPublicKey = keyFactory.generatePublic(keySpec);

        keyAgreement.doPhase(theirPublicKey, true);
        return keyAgreement.generateSecret();
    }

    // https://datatracker.ietf.org/doc/html/rfc8731#section-3
    // 3. Key Exchange Methods
    //   Clients and servers MUST
    //   also abort if the length of the received public keys are not the
    //   expected lengths.  An abort for these purposes is defined as a
    //   disconnect (SSH_MSG_DISCONNECT) of the session and SHOULD use the
    //   SSH_DISCONNECT_KEY_EXCHANGE_FAILED reason for the message
    //   [IANA-REASON].  No further validation is required beyond what is
    //   described in [RFC7748].
    @Override
    public void validate(@NonNull final byte[] q_s)
            throws InvalidKeyException {
        if (q_s.length != keySize) {
            throw new InvalidKeyException("validation failed");
        }
    }

    /**
     * 5. The X25519 and X448 Functions
     * The u-coordinates are elements of the underlying field GF(2^255 - 19)
     * or GF(2^448 - 2^224 - 1) and are encoded as an array of bytes, u, in
     * little-endian order such that u[0] + 256*u[1] + 256^2*u[2] + ... +
     * 256^(n-1)*u[n-1] is congruent to the value modulo p and u[n-1] is
     * minimal.  When receiving such an array, implementations of X25519
     * (but not X448) MUST mask the most significant bit in the final byte.
     * This is done to preserve compatibility with point formats that
     * reserve the sign bit for use in other protocols and to increase
     * resistance to implementation fingerprinting.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7748#section-5">
     * RFC 7748 Elliptic Curves for Security, section 5. The X25519 and X448 Functions</a>
     */
    @NonNull
    private byte[] rotate(@NonNull final byte[] u) {
        final int len = u.length;
        final byte[] out = new byte[len];

        for (int i = 0; i < len; i++) {
            out[i] = u[len - i - 1];
        }

        return Arrays.copyOf(out, keySize);
    }
}
