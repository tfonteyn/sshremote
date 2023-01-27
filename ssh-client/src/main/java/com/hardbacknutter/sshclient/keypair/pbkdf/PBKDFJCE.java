package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898">
 * RFC 2898 PKCS #5: Password-Based Cryptography Specification</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms">
 * Standard algorithm names</a>
 */
@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDFJCE
        implements PBKDF {

    @NonNull
    private String algorithm;
    @NonNull
    private byte[] salt;
    private int iterationCount;

    @SuppressWarnings("FieldNotUsedInToString")
    @NonNull
    private SecretKeyFactory skf;

    /**
     * Init.
     *
     * @param algorithm      standard JDK name (e.g. "PBKDF2WithHmacSHA1")
     * @param salt           the salt.
     * @param iterationCount the iteration count.
     */
    public PBKDFJCE init(@NonNull final String algorithm,
                         @NonNull final byte[] salt,
                         final int iterationCount)
            throws NoSuchAlgorithmException {
        this.algorithm = algorithm;
        this.salt = salt;
        this.iterationCount = iterationCount;

        skf = SecretKeyFactory.getInstance(algorithm);

        return this;
    }

    @Override
    @NonNull
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int keyLength)
            throws InvalidKeySpecException {

        final char[] pass = new char[passphrase.length];
        for (int i = 0; i < passphrase.length; i++) {
            pass[i] = (char) (passphrase[i] & 0xff);
        }

        final KeySpec keySpec = new PBEKeySpec(pass, salt, iterationCount, keyLength * 8);
        return skf.generateSecret(keySpec).getEncoded();
    }

    @Override
    public String toString() {
        return "PBKDFJCE{"
                + "algorithm='" + algorithm + '\''
                + ", salt=" + Arrays.toString(salt)
                + ", iterations=" + iterationCount
                + '}';
    }
}
