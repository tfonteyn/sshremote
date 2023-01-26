package com.hardbacknutter.sshclient.pbkdf;

import androidx.annotation.NonNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-1 is hardcoded in PuTTY PPK-2 files.
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
public class PBKDFPutty2
        implements PBKDF {

    @NonNull
    private final MessageDigest md;

    public PBKDFPutty2()
            throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance("SHA-1");
    }

    /**
     * @param always32 hardcoded to 32; always pass in 32 for future compatibility
     */
    @NonNull
    @Override
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int always32) {
        md.reset();
        md.update(new byte[]{0, 0, 0, 0});
        md.update(passphrase);
        final byte[] key1 = md.digest();

        md.update(new byte[]{0, 0, 0, 1});
        md.update(passphrase);
        final byte[] key2 = md.digest();

        final byte[] pbeKey = new byte[32];
        System.arraycopy(key1, 0, pbeKey, 0, 20);
        System.arraycopy(key2, 0, pbeKey, 20, 12);
        return pbeKey;
    }
}
