package com.hardbacknutter.sshclient.utils;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Random;

import java.security.SecureRandom;

public class RandomImpl
        implements Random {

    @NonNull
    private final SecureRandom random;
    @NonNull
    private byte[] tmp = new byte[16];

    public RandomImpl() {
        random = new SecureRandom();
    }

    @Override
    public void fill(@NonNull final byte[] buf,
                     final int start,
                     final int len) {
        synchronized (random) {
            if (len > tmp.length) {
                tmp = new byte[len];
            }
            random.nextBytes(tmp);
            System.arraycopy(tmp, 0, buf, start, len);
        }
    }
}
