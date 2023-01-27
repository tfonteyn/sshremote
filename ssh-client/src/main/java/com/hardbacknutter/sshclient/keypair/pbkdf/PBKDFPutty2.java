package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * SHA-1 is hardcoded in PuTTY PPK-2 files.
 *
 * <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk-v2">ppk-v2</a>
 *
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
public class PBKDFPutty2
        implements PBKDF {

    @NonNull
    private MessageDigest md;

    public PBKDFPutty2 init()
            throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance("SHA-1");
        return this;
    }

    /**
     * @param keyLength MUST be set to 32 for compatibility
     */
    @NonNull
    @Override
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
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
}
