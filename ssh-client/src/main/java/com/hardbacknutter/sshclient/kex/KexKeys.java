package com.hardbacknutter.sshclient.kex;

import androidx.annotation.NonNull;

import java.security.MessageDigest;

import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchange;

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

    /**
     * Constructor.
     *
     * @param md the hash generator as used during KEX.
     * @param K  the shared secret; pre-encoded as a raw byte[]
     * @param H  the hash; pre-encoded as a raw byte[]
     */
    KexKeys(@NonNull final MessageDigest md,
            @NonNull final byte[] K,
            @NonNull final byte[] H) {
        this.md = md;
        this.K = K;
        this.H = H;
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
