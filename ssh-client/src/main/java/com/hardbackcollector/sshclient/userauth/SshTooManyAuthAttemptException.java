package com.hardbackcollector.sshclient.userauth;

import androidx.annotation.NonNull;

public class SshTooManyAuthAttemptException
        extends SshAuthException {

    private static final long serialVersionUID = 1882437696445535542L;
    @NonNull
    private final String method;
    private final int auth_tries;

    SshTooManyAuthAttemptException(@NonNull final String method,
                                   final int auth_tries) {
        super("");
        this.method = method;
        this.auth_tries = auth_tries;
    }

    public int getAuthTries() {
        return auth_tries;
    }

    @NonNull
    public String getMethod() {
        return method;
    }

    @Override
    public String getMessage() {
        return "To many authentication tries: " + method + ": " + auth_tries;
    }
}
