package com.hardbackcollector.sshclient.kex.keyagreements;

import androidx.annotation.NonNull;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class DHImpl
        implements DH {

    /** prime modulus. */
    private BigInteger p;
    /** base generator. */
    private BigInteger g;

    private KeyAgreement keyAgreement;
    private KeyPairGenerator keyPairGenerator;

    @Override
    public void init()
            throws NoSuchAlgorithmException {

        keyAgreement = KeyAgreement.getInstance("DH");
        keyPairGenerator = KeyPairGenerator.getInstance("DH");
    }

    @Override
    public void setP(@NonNull final BigInteger p) {
        this.p = p;
    }

    @Override
    public void setG(@NonNull final BigInteger g) {
        this.g = g;
    }

    @Override
    @NonNull
    public BigInteger getE()
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        final AlgorithmParameterSpec params = new DHParameterSpec(p, g);
        keyPairGenerator.initialize(params);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        keyAgreement.init(keyPair.getPrivate());

        return ((DHPublicKey) keyPair.getPublic()).getY();
    }

    @Override
    @NonNull
    public byte[] getSharedSecret(@NonNull final BigInteger f)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
                   InvalidKeyException, IllegalStateException {

        final KeySpec keySpec = new DHPublicKeySpec(f, p, g);

        final KeyFactory keyFactory = KeyFactory.getInstance("DH");
        final PublicKey theirPublicKey = keyFactory.generatePublic(keySpec);

        keyAgreement.doPhase(theirPublicKey, true);
        return keyAgreement.generateSecret();
    }


    /**
     * Check that e and f are integers in the interval [1, p-1]
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-8">
     * RFC 4253 SSH Transport Layer Protocol, section 8.</a>
     */
    @Override
    public void validate(@NonNull final BigInteger e,
                         @NonNull final BigInteger f)
            throws InvalidKeyException {
        if (e.compareTo(BigInteger.ONE) < 0 || e.compareTo(p) >= 0
                ||
                f.compareTo(BigInteger.ONE) < 0 || f.compareTo(p) >= 0
        ) {
            throw new InvalidKeyException("validation failed");
        }
    }
}
