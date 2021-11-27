package com.hardbackcollector.sshclient.kex;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.kex.keyexchange.KeyExchange;

import java.security.MessageDigest;

/**
 * Value class with the results of a {@link KeyExchange}
 */
public class KexKeys {

    @NonNull
    private final byte[] K;
    @NonNull
    private final byte[] H;
    @NonNull
    private final MessageDigest md;

    public KexKeys(@NonNull final byte[] k,
                   @NonNull final byte[] h,
                   @NonNull final MessageDigest md) {
        K = k;
        H = h;
        this.md = md;
    }

    @NonNull
    public byte[] getK() {
        return K;
    }

    @NonNull
    public byte[] getH() {
        return H;
    }

    @NonNull
    public MessageDigest getMessageDigest() {
        return md;
    }
}
