package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import java.io.IOException;

/**
 * This not "NoSuchAlgorithmException" which means JCE/BC does not know the algorithm.
 * <p>
 * This is a situation where the algorithm is known but this library does not support it.
 */
public class UnsupportedAlgorithmException extends IOException {

    private static final long serialVersionUID = -3700516781888323459L;

    public UnsupportedAlgorithmException(@NonNull final String name) {
        super(name);
    }
}
