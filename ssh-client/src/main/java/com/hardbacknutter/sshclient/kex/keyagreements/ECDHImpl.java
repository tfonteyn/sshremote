package com.hardbacknutter.sshclient.kex.keyagreements;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.keypair.ECKeyType;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.KeyAgreement;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5656#section-7">
 * RFC 5656 Elliptic Curve Algorithm Integration in the SSH Transport Layer,
 * section 7.Key Exchange Messages</a>
 */
public class ECDHImpl
        implements ECDH {

    private static final BigInteger THREE = BigInteger.valueOf(3);

    private KeyAgreement keyAgreement;
    private ECPublicKey publicKey;
    private byte[] q;

    @Override
    public void init(@NonNull final ECKeyType ecType)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
                   InvalidKeyException {

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        final AlgorithmParameterSpec params = new ECGenParameterSpec(ecType.curveName);
        keyPairGenerator.initialize(params);

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = (ECPublicKey) keyPair.getPublic();
        q = ecType.encodePoint(publicKey.getW());

        keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(keyPair.getPrivate());
    }

    @NonNull
    @Override
    public byte[] getQ() {
        return q;
    }

    @NonNull
    @Override
    public byte[] getSharedSecret(@NonNull final ECPoint w)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
                   InvalidKeyException, IllegalStateException {

        final KeySpec keySpec = new ECPublicKeySpec(w, publicKey.getParams());

        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        final PublicKey theirPublicKey = keyFactory.generatePublic(keySpec);

        keyAgreement.doPhase(theirPublicKey, true);
        return keyAgreement.generateSecret();
    }

    // SEC 1: Elliptic Curve Cryptography, Version 2.0
    // http://www.secg.org/sec1-v2.pdf
    // 3.2.2.1 Elliptic Curve Public Key Validation Primitive
    @Override
    public void validate(@NonNull final ECPoint w)
            throws InvalidKeyException {

        // Step.1
        //   Check that Q != infinity
        if (w.equals(ECPoint.POINT_INFINITY)) {
            throw new InvalidKeyException("validation(1) failed");
        }

        // Step.2
        // If T represents elliptic curve domain parameters over Fp,
        // check that xQ and yQ are integers in the interval [0, p-1],
        // and that:
        //   y^2 = x^3 + x*a + b (mod p)

        final ECParameterSpec params = publicKey.getParams();
        final EllipticCurve curve = params.getCurve();
        final BigInteger p = ((ECFieldFp) curve.getField()).getP();

        final BigInteger xQ = w.getAffineX();
        final BigInteger yQ = w.getAffineY();

        // Check that xQ and yQ are integers in the interval [0, p-1]
        if (xQ.compareTo(BigInteger.ZERO) < 0 || xQ.compareTo(p) >= 0
                ||
                yQ.compareTo(BigInteger.ZERO) < 0 || yQ.compareTo(p) >= 0
        ) {
            throw new InvalidKeyException("validation(2.1) failed");
        }

        // and that y^2 = x^3 + x*a + b (mod p)
        final BigInteger tmp = xQ.multiply(curve.getA())
                                 .add(curve.getB())
                                 .add(xQ.modPow(THREE, p))
                                 .mod(p);
        final BigInteger y_2 = yQ.modPow(BigInteger.valueOf(2), p);
        if (!y_2.equals(tmp)) {
            throw new InvalidKeyException("validation(2.2) failed");
        }

        // Step.3
        //   Check that nQ = O.
        // Unfortunately, JCE does not provide the point multiplication method.

//         if (!w.multiply(params.getOrder()).equals(ECPoint.POINT_INFINITY)) {
//            throw new InvalidKeyException("validation(3) failed");
//         }

    }
}
