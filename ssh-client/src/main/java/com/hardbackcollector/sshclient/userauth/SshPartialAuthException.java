package com.hardbackcollector.sshclient.userauth;

import androidx.annotation.NonNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class SshPartialAuthException
        extends SshAuthException {

    private static final long serialVersionUID = 7869541420233336760L;
    @NonNull
    private final String methods;

    SshPartialAuthException(@NonNull final String method,
                            @NonNull final byte[] methods) {
        super(method);
        this.methods = new String(methods, 0, methods.length, StandardCharsets.UTF_8);
    }

    @NonNull
    public List<String> getMethods() {
        return Arrays.asList(methods.split(","));
    }
}
