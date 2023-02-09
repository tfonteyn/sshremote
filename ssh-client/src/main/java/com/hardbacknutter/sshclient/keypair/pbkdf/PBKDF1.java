package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * TODO: is this not available using JCE?
 * https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms
 *
 * <a href="https://datatracker.ietf.org/doc/html/rfc8018#section-5.1">PBKDF1</a>
 */
@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDF1 implements PBKDF {

    private byte[] salt;

    @NonNull
    private MessageDigest md;

    @Nullable
    private SshCipher cipher;
    @Nullable
    private byte[] cipherIV;

    public PBKDF1 init(@NonNull final String algorithm,
                       @NonNull final byte[] salt)
            throws NoSuchAlgorithmException {
        this.salt = salt;
        md = MessageDigest.getInstance(algorithm);
        return this;
    }

    @Override
    public void setCipher(@Nullable final SshCipher cipher,
                          @Nullable final byte[] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
    }

    @NonNull
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int keyLength) throws NoSuchAlgorithmException {
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
                (keyLength % hashSize
                        == 0 ? 0 : hashSize)];
        byte[] tmp = null;
        for (int index = 0; index + hashSize <= hn.length; ) {
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

    @NonNull
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
            throws GeneralSecurityException {
        if (cipher == null || cipherIV == null) {
            throw new KeyException("Cipher/iv not set");
        }

        byte[] pbeKey = null;
        try {
            pbeKey = generateSecretKey(passphrase, cipher.getKeySize());

            final byte[] plainKey = new byte[blob.length];
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
            cipher.doFinal(blob, 0, blob.length, plainKey, 0);
            return plainKey;
        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
            Arrays.fill(passphrase, (byte) 0);
        }
    }
}
