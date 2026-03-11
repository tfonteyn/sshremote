package com.hardbacknutter.sshclient.kex.kem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.jspecify.annotations.NonNull;

public class MLKEM
        implements KEM {

    private static final int KYBER_POLY_BYTES = 384;

    @NonNull
    private final MLKEMParameters parameters;
    private MLKEMExtractor extractor;
    private MLKEMPublicKeyParameters publicKey;
    private final int pubKeyLen;

    public MLKEM(@NonNull final MLKEMParameters parameters) {
        this.parameters = parameters;

        // Always 32, but makes it clear why...
        final int rhoSize = parameters.getSessionKeySize() / 8;

        final String name = parameters.getName();
        if (name.endsWith("512")) {
            pubKeyLen = 2 * KYBER_POLY_BYTES + rhoSize;
        } else if (name.endsWith("768")) {
            pubKeyLen = 3 * KYBER_POLY_BYTES + rhoSize;
        } else if (name.endsWith("1024")) {
            pubKeyLen = 4 * KYBER_POLY_BYTES + rhoSize;
        } else {
            throw new IllegalArgumentException(name);
        }
    }

    @Override
    public void init() {
        final AsymmetricCipherKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        final MLKEMKeyGenerationParameters param = new MLKEMKeyGenerationParameters(
                new SecureRandom(), parameters);
        kpg.init(param);

        final AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        extractor = new MLKEMExtractor((MLKEMPrivateKeyParameters) kp.getPrivate());
        publicKey = (MLKEMPublicKeyParameters) kp.getPublic();
    }

    @Override
    public int getPublicKeyLength() {
        return pubKeyLen;
    }

    @Override
    public byte @NonNull [] getPublicKey() {
        return publicKey.getEncoded();
    }

    @Override
    public int getEncapsulationLength() {
        return extractor.getEncapsulationLength();
    }

    @Override
    public byte @NonNull [] extractSecret(final byte[] encapsulation) {
        return extractor.extractSecret(encapsulation);
    }
}
