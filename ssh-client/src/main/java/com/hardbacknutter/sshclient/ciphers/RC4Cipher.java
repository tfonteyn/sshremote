package com.hardbacknutter.sshclient.ciphers;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

public class RC4Cipher
        extends SshCipherImpl {

    private final int skip;

    public RC4Cipher(@NonNull final String algorithm,
                     @NonNull final String mode,
                     @NonNull final String padding,
                     final int blockSize,
                     final int keyLength,
                     final int ivSize,
                     final int skip)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(algorithm, mode, padding, keyLength, blockSize, ivSize);
        this.skip = skip;
    }

    @Override
    public void init(final int opmode,
                     @NonNull final byte[] key,
                     @NonNull final byte[] iv)
            throws GeneralSecurityException {
        super.init(opmode, key, iv);

        if (skip > 0) {
            final byte[] tmp = new byte[1];
            for (int i = 0; i < skip; i++) {
                cipher.update(tmp, 0, 1, tmp, 0);
            }
        }
    }
}
