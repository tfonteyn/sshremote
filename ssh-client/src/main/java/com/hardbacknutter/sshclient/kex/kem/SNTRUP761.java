package com.hardbacknutter.sshclient.kex.kem;

import androidx.annotation.NonNull;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;

public class SNTRUP761
        implements KEM {

    private EncapsulatedSecretExtractor extractor;
    private SNTRUPrimePublicKeyParameters publicKey;
    private SNTRUPrimeParameters kemPrimeParameters;

    // Bouncy Castle before 1.78 defines sharedKeyBytes differently than OpenSSH (16 instead of 32)
    // https://github.com/bcgit/bc-java/issues/1554
    // https://github.com/bcgit/bc-java/commit/db3ae60
    private static SNTRUPrimeParameters createSNTRUP761() {
        if (SNTRUPrimeParameters.sntrup761.getSessionKeySize() == 32 * 8) {
            return SNTRUPrimeParameters.sntrup761;
        }
        try {
            final Constructor<SNTRUPrimeParameters> c =
                    SNTRUPrimeParameters.class.getDeclaredConstructor(
                            String.class,
                            int.class, int.class, int.class,
                            int.class, int.class,
                            int.class, int.class, int.class);
            c.setAccessible(true);
            return c.newInstance("sntrup761", 761, 4591, 286, 1158, 1007, 1158, 1763, 32);
        } catch (final NoSuchMethodException | InstantiationException
                       | IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException(
                    "Bouncy Castle 1.77 or older failed to create SNTRUPrimeParameters");
        }
    }

    @Override
    public void init() {
        kemPrimeParameters = createSNTRUP761();
        final AsymmetricCipherKeyPairGenerator kpg = new SNTRUPrimeKeyPairGenerator();
        kpg.init(new SNTRUPrimeKeyGenerationParameters(new SecureRandom(), kemPrimeParameters));

        final AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        extractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters) kp.getPrivate());
        publicKey = (SNTRUPrimePublicKeyParameters) kp.getPublic();
    }

    @Override
    public int getPublicKeyLength() {
        return kemPrimeParameters.getPublicKeyBytes();
    }

    @Override
    public byte[] getPublicKey() {
        return publicKey.getEncoded();
    }

    @Override
    public int getEncapsulationLength() {
        return extractor.getEncapsulationLength();
    }

    @Override
    @NonNull
    public byte[] extractSecret(final byte[] encapsulation) {
        return extractor.extractSecret(encapsulation);
    }
}
