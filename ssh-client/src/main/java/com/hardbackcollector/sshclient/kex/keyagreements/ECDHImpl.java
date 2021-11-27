/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2015-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.kex.keyagreements;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.keypair.ECKeyType;

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
