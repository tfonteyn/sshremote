package com.hardbacknutter.sshclient.kex;

import androidx.annotation.NonNull;

import java.io.IOException;

public class KexException
        extends IOException {

    private static final long serialVersionUID = 4416489243578995154L;

    public KexException(@NonNull final String message) {
        super(message);
    }

    public KexException(@NonNull final Throwable cause) {
        super(cause);
    }
}
