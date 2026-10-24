package com.hardbacknutter.sshclient.keypair.pbkdf;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * PuTTY PPK-2 specific.
 * <p>
 * <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk-v2">ppk-v2</a>
 * <p>
 * <a href="https://github.com/github/putty/blob/7003b43963aef6cdf2841c2a882a684025f1d806/sshpubk.c#L662">github</a>
 * <pre>{@code
 *  static void ssh2_ppk_derivekey(ptrlen passphrase, uint8_t *key)
 *  {
 *      ssh_hash *h;
 *      h = ssh_hash_new(&ssh_sha1);
 *      put_uint32(h, 0);
 *      put_datapl(h, passphrase);
 *      ssh_hash_digest(h, key + 0);
 *      ssh_hash_reset(h);
 *      put_uint32(h, 1);
 *      put_datapl(h, passphrase);
 *      ssh_hash_final(h, key + 20);
 *  }
 * }</pre>
 */
@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDFPutty2 implements PBKDF {

    @NonNull
    private MessageDigest md;

    @Nullable
    private String transformation;
    private int keySize;
    private byte @Nullable [] cipherIV;

    @NonNull
    public PBKDFPutty2 init()
            throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance("SHA-1");
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

    /**
     * @param keyLength MUST be set to 32 for compatibility
     */
    public byte @NonNull [] generateSecretKey(final byte @NonNull [] passphrase,
                                    final int keyLength) {
        if (keyLength != 32) {
            throw new IllegalArgumentException("keyLength must be 32");
        }
        Objects.requireNonNull(md, "init must be called before use");

        md.reset();
        md.update(new byte[]{0, 0, 0, 0});
        md.update(passphrase);
        final byte[] key1 = md.digest();

        md.reset();
        md.update(new byte[]{0, 0, 0, 1});
        md.update(passphrase);
        final byte[] key2 = md.digest();

        final byte[] pbeKey = new byte[32];
        System.arraycopy(key1, 0, pbeKey, 0, 20);
        System.arraycopy(key2, 0, pbeKey, 20, 12);
        return pbeKey;
    }

    public byte @NonNull [] decrypt(final byte @NonNull [] passphrase,
                          final byte @NonNull [] blob)
            throws GeneralSecurityException {

        if (transformation == null || cipherIV == null) {
            throw new KeyException("transformation/iv not set");
        }

        byte[] pbeKey = null;
        try {
            pbeKey = generateSecretKey(passphrase, 32);

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
