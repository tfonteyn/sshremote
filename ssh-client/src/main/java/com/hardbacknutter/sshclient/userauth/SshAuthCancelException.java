package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;

public class SshAuthCancelException
        extends SshAuthException {

    private static final long serialVersionUID = -1615925931671542958L;
    @NonNull
    private final String method;

    public SshAuthCancelException(@NonNull final String method) {
        super(method);
        this.method = method;
    }

    @NonNull
    public String getMethod() {
        return method;
    }
}
