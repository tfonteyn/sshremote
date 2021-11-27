package com.hardbackcollector.sshclient.kex;

import androidx.annotation.NonNull;

public class KexTimeoutException
        extends KexException {

    private static final String TIMEOUT = "timeout in waiting for re-keying process.";
    private static final long serialVersionUID = 4160075650066603177L;

    public KexTimeoutException() {
        super(TIMEOUT);
    }

    public KexTimeoutException(@NonNull final String message) {
        super(message);
    }
}
