package com.hardbacknutter.sshclient.keypair.pbkdf;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * JCE based standard PBKDF2 using a salt and iteration-count.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898">
 *         RFC 2898 PKCS #5: Password-Based Cryptography Specification</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms">
 *         Standard algorithm names</a>
 */
public class PBKDF2
        implements PBKDF {

    @Nullable
    private String transformation;
    private int keySize;
    private byte @Nullable [] cipherIV;

    private byte[] salt;
    private int iterationCount;

    private SecretKeyFactory skf;


    public PBKDF2 init(@NonNull final String algorithm,
                       final byte @NonNull [] salt,
                       final int iterationCount)
            throws NoSuchAlgorithmException {
        this.salt = salt;
        this.iterationCount = iterationCount;

        skf = SecretKeyFactory.getInstance(algorithm);
        return this;
    }

    @Override
    public void setCipher(final @NonNull String transformation,
                          final int keySize,
                          final byte @NonNull [] cipherIV) {
        this.transformation = transformation;
        this.keySize = keySize;
        this.cipherIV = cipherIV;
    }

    public byte @NonNull [] generateSecretKey(final byte @NonNull [] passphrase,
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
    public byte @NonNull [] decrypt(final byte @NonNull [] passphrase,
                                    final byte @NonNull [] blob)
            throws GeneralSecurityException, IOException {

        if (transformation == null || cipherIV == null) {
            throw new KeyException("transformation/iv not set");
        }

        byte[] pbeKey = null;
        try {
            pbeKey = generateSecretKey(passphrase, keySize);

            final Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(pbeKey, transformation.split("/")[0]),
                        new IvParameterSpec(cipherIV));

            return cipher.doFinal(blob);

        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
        }
    }
}
