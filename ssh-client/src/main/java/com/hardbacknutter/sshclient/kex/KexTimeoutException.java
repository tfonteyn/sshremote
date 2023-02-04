package com.hardbacknutter.sshclient.kex;

public class KexTimeoutException
        extends KexException {

    private static final String TIMEOUT = "timeout in waiting for re-keying process.";
    private static final long serialVersionUID = 4160075650066603177L;

    public KexTimeoutException() {
        super(TIMEOUT);
    }
}
