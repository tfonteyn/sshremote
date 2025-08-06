package com.hardbacknutter.sshclient.kex;

import org.jspecify.annotations.NonNull;

import java.security.MessageDigest;

import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchange;

/**
 * Value class with the results of a {@link KeyExchange}
 */
public class KexKeys {

    private final byte @NonNull [] K;
    private final byte @NonNull [] H;
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
            final byte @NonNull [] K,
            final byte @NonNull [] H) {
        this.md = md;
        this.K = K;
        this.H = H;
    }

    public byte @NonNull [] getK() {
        return K;
    }

    public byte @NonNull [] getH() {
        return H;
    }

    @NonNull
    public MessageDigest getMessageDigest() {
        return md;
    }
}
