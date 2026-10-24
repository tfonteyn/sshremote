package com.hardbacknutter.sshclient.keypair.pbkdf;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TODO: is this not available using JCE?
 * https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms
 * <p>
 * <a href="https://datatracker.ietf.org/doc/html/rfc8018#section-5.1">PBKDF1</a>
 */
@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDF1 implements PBKDF {

    private byte[] salt;

    @NonNull
    private MessageDigest md;

    @Nullable
    private String transformation;
    private int keySize;
    private byte @Nullable [] cipherIV;

    public PBKDF1 init(@NonNull final String algorithm,
                       final byte @NonNull [] salt)
            throws NoSuchAlgorithmException {
        this.salt = salt;
        md = MessageDigest.getInstance(algorithm);
        return this;
    }

    @Override
    public void setCipher(final @NonNull String transformation,
                          final int keySize,
                          final byte @Nullable [] cipherIV) {
        this.transformation = transformation;
        this.keySize = keySize;
        this.cipherIV = cipherIV;
    }

    public byte @NonNull [] generateSecretKey(final byte @NonNull [] passphrase,
                                    final int keyLength) {
        /*
         * https://datatracker.ietf.org/doc/html/rfc8018#section-5.1
         * PBKDF1
         * hash is MD5
         * h(0) <- hash(passphrase, iv);
         * h(n) <- hash(h(n-1), passphrase, iv);
         * key <- (h(0),...,h(n))[0,..,key.length];
         */
        final int hashSize = md.getDigestLength();
        final byte[] hn = new byte[keyLength / hashSize * hashSize +
                (keyLength % hashSize == 0 ? 0 : hashSize)];
        byte[] tmp = null;
        int index = 0;
        while (index + hashSize <= hn.length) {
            if (tmp != null) {
                md.update(tmp, 0, tmp.length);
            }
            md.update(passphrase, 0, passphrase.length);
            md.update(salt, 0, Math.min(salt.length, 8));

            tmp = md.digest();
            System.arraycopy(tmp, 0, hn, index, tmp.length);
            index += tmp.length;
        }

        final byte[] key = new byte[keyLength];
        System.arraycopy(hn, 0, key, 0, key.length);
        return key;
    }

    public byte @NonNull [] decrypt(final byte @NonNull [] passphrase,
                          final byte @NonNull [] blob)
            throws GeneralSecurityException {

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
            Arrays.fill(passphrase, (byte) 0);
        }
    }
}
