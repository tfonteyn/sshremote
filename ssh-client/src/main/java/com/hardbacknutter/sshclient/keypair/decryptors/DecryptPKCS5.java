package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;

public class DecryptPKCS5 implements PKDecryptor {

    @Nullable
    private SshCipher cipher;
    @Nullable
    private byte[] cipherIV;

    @Override
    public void setCipher(@Nullable final SshCipher cipher,
                          @Nullable final byte[] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
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
            /*
             * https://datatracker.ietf.org/doc/html/rfc8018#section-5.1
             * PBKDF1
             * hash is MD5
             * h(0) <- hash(passphrase, iv);
             * h(n) <- hash(h(n-1), passphrase, iv);
             * key <- (h(0),...,h(n))[0,..,key.length];
             */
            final MessageDigest md5 = MessageDigest.getInstance("MD5");
            final int hashSize = md5.getDigestLength();
            final byte[] hn = new byte[cipher.getKeySize() / hashSize * hashSize +
                    (cipher.getKeySize() % hashSize
                            == 0 ? 0 : hashSize)];
            byte[] tmp = null;
            for (int index = 0; index + hashSize <= hn.length; ) {
                if (tmp != null) {
                    md5.update(tmp, 0, tmp.length);
                }
                md5.update(passphrase, 0, passphrase.length);
                md5.update(cipherIV, 0, Math.min(cipherIV.length, 8));

                tmp = md5.digest();
                System.arraycopy(tmp, 0, hn, index, tmp.length);
                index += tmp.length;
            }

            pbeKey = new byte[cipher.getKeySize()];
            System.arraycopy(hn, 0, pbeKey, 0, pbeKey.length);

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
