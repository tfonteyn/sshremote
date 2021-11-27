package com.hardbackcollector.sshclient.userauth;

import androidx.annotation.NonNull;

public class SshAuthNoSuchMethodException
        extends SshAuthException {

    private static final long serialVersionUID = 4375517343708578019L;
    @NonNull
    private final String method;

    public SshAuthNoSuchMethodException(@NonNull final String method) {
        super(method);
        this.method = method;
    }

    public SshAuthNoSuchMethodException(@NonNull final String method,
                                        @NonNull final Throwable cause) {
        super(cause);
        this.method = method;
    }

    @NonNull
    public String getMethod() {
        return method;
    }
}
