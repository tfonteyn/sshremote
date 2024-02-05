package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;

import java.util.Arrays;
import java.util.List;

public class SshPartialAuthException
        extends SshAuthException {

    private static final long serialVersionUID = 4651271794882031392L;
    @NonNull
    private final List<String> methods;

    SshPartialAuthException(@NonNull final String method,
                            @NonNull final String methods) {
        super(method);
        this.methods = Arrays.asList(methods.split(","));
    }

    @NonNull
    public List<String> getMethods() {
        return methods;
    }
}
