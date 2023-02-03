package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import java.io.IOException;

public class UnsupportedAlgorithmException extends IOException {


    private static final long serialVersionUID = -3700516781888323459L;

    public UnsupportedAlgorithmException(@NonNull final String name) {
        super(name);
    }
}
