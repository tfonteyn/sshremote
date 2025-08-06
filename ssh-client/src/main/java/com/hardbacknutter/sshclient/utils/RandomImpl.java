package com.hardbacknutter.sshclient.utils;

import org.jspecify.annotations.NonNull;

import java.security.SecureRandom;

import com.hardbacknutter.sshclient.Random;

public class RandomImpl
        implements Random {

    @NonNull
    private final SecureRandom random;
    private byte @NonNull [] tmp = new byte[16];

    public RandomImpl() {
        random = new SecureRandom();
    }

    @Override
    public byte @NonNull [] nextBytes(final int length) {
        final byte[] buf = new byte[length];
        synchronized (random) {
            if (buf.length > tmp.length) {
                tmp = new byte[buf.length];
            }
            random.nextBytes(tmp);
            System.arraycopy(tmp, 0, buf, 0, buf.length);
        }
        return buf;
    }

}
