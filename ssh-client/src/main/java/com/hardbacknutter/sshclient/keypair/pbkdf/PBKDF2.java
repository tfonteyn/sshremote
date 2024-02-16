package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

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

    private SshCipher cipher;
    private byte[] cipherIV;

    private byte[] salt;
    private int iterationCount;

    private SecretKeyFactory skf;


    public PBKDF2 init(@NonNull final String algorithm,
                       @NonNull final byte[] salt,
                       final int iterationCount)
            throws NoSuchAlgorithmException {
        this.salt = salt;
        this.iterationCount = iterationCount;

        skf = SecretKeyFactory.getInstance(algorithm);
        return this;
    }

    @Override
    public void setCipher(@NonNull final SshCipher cipher,
                          @NonNull final byte[] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
    }

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

    @NonNull
    @Override
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
            throws GeneralSecurityException, IOException {
        byte[] pbeKey = null;
        final byte[] plainKey = new byte[blob.length];
        try {
            pbeKey = generateSecretKey(passphrase, cipher.getKeySize());

            cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
            cipher.doFinal(blob, 0, blob.length, plainKey, 0);

        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
        }
        return plainKey;
    }
}
